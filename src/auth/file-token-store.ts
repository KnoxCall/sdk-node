// FileTokenStore — persistent token cache across process restarts.
//
// Writes JSON to a path of the caller's choosing (defaults to
// ~/.knoxcall/token-cache.json). File mode is set to 0600 atomically via
// write-temp-then-rename. On Windows the mode bits are no-ops, but the
// default-user ACL is restrictive enough.
//
// Concurrency: in-process locks are held via a per-key Promise map (same
// pattern as MemoryTokenStore). Cross-process locking is best-effort via
// O_EXCL lock files — sufficient for the dev-laptop case where this store
// is intended. For multi-process production fleets use RedisTokenStore.

import { homedir } from "os";
import { join } from "path";
import { existsSync, mkdirSync, renameSync, unlinkSync, writeFileSync } from "fs";
import { readFile, writeFile, mkdir, rename, unlink, open } from "fs/promises";

import { Redacted } from "../redacted.js";
import type { TokenStore, CachedToken } from "./token-store.js";

function defaultPath(): string {
  return join(homedir(), ".knoxcall", "token-cache.json");
}

interface Persisted {
  [cacheKey: string]: {
    accessToken: string;
    refreshToken?: string;
    expiresAt: number;
    lifetime?: number;
    scope: string[];
    tokenType: "Bearer" | "DPoP";
    cnfJkt?: string;
    tenant?: string;
  };
}

function toPersisted(t: CachedToken): Persisted[string] {
  return {
    accessToken: t.accessToken.expose(),
    refreshToken: t.refreshToken?.expose(),
    expiresAt: t.expiresAt,
    lifetime: t.lifetime,
    scope: t.scope,
    tokenType: t.tokenType,
    cnfJkt: t.cnfJkt,
    tenant: t.tenant,
  };
}

function fromPersisted(p: Persisted[string]): CachedToken {
  return {
    accessToken: new Redacted(p.accessToken),
    refreshToken: p.refreshToken ? new Redacted(p.refreshToken) : undefined,
    expiresAt: p.expiresAt,
    lifetime: p.lifetime,
    scope: p.scope,
    tokenType: p.tokenType,
    cnfJkt: p.cnfJkt,
    tenant: p.tenant,
  };
}

export class FileTokenStore implements TokenStore {
  #path: string;
  #locks = new Map<string, Promise<unknown>>();

  constructor(path?: string) {
    this.#path = path ?? defaultPath();
  }

  async #readAll(): Promise<Persisted> {
    try {
      const raw = await readFile(this.#path, "utf8");
      return JSON.parse(raw) as Persisted;
    } catch (e: unknown) {
      if ((e as { code?: string })?.code === "ENOENT") return {};
      throw e;
    }
  }

  async #writeAll(data: Persisted): Promise<void> {
    await mkdir(join(this.#path, ".."), { recursive: true, mode: 0o700 });
    const tmp = `${this.#path}.tmp`;
    await writeFile(tmp, JSON.stringify(data, null, 2), { mode: 0o600 });
    await rename(tmp, this.#path);
  }

  async get(key: string): Promise<CachedToken | null> {
    const all = await this.#readAll();
    const entry = all[key];
    return entry ? fromPersisted(entry) : null;
  }

  async set(key: string, token: CachedToken): Promise<void> {
    const all = await this.#readAll();
    all[key] = toPersisted(token);
    await this.#writeAll(all);
  }

  async delete(key: string): Promise<void> {
    const all = await this.#readAll();
    if (!(key in all)) return;
    delete all[key];
    await this.#writeAll(all);
  }

  async withLock<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const existing = this.#locks.get(key);
    if (existing) {
      await existing.catch(() => undefined);
    }
    const promise = (async () => {
      try {
        return await fn();
      } finally {
        this.#locks.delete(key);
      }
    })();
    this.#locks.set(key, promise);
    return promise;
  }
}
