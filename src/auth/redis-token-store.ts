// RedisTokenStore — shared token cache for multi-instance fleets.
//
// The SDK does NOT bundle a Redis client. You bring your own (ioredis,
// node-redis, etc.) — anything matching the small `RedisClient` interface
// below works. This keeps the SDK's dependency footprint minimal while
// supporting both ioredis and redis@4+ semantics with no changes.
//
// Single-flight refresh is enforced via SET NX EX — only one instance in
// the fleet refreshes at a time; losers poll the cache briefly until the
// winner finishes.

import { Redacted } from "../redacted.js";
import type { TokenStore, CachedToken } from "./token-store.js";

/**
 * Minimal Redis client contract. Both `ioredis` and the modern `redis`
 * (>=4.0) packages satisfy this with their default APIs.
 */
export interface RedisClient {
  get(key: string): Promise<string | null>;
  // Variadic to support both `SET k v EX ttl` and `SET k v NX EX ttl` shapes
  // across ioredis + redis@4 + node-redis.
  set(key: string, value: string, ...args: (string | number)[]): Promise<unknown>;
  setEx?(key: string, ttlSeconds: number, value: string): Promise<unknown>;
  del(key: string | string[]): Promise<unknown>;
  exists?(key: string): Promise<number>;
}

export interface RedisTokenStoreOptions {
  client: RedisClient;
  /** Prefix for all cache keys (default "knoxcall:"). */
  prefix?: string;
  /** Lock wait timeout in milliseconds (default 10s). */
  lockWaitMs?: number;
  /** Lock TTL in seconds — protects against orphan locks on crashed instances (default 30s). */
  lockTtlSeconds?: number;
  /** Cache entry TTL hint in seconds; the SDK passes the token's exp window. */
  defaultCacheTtlSeconds?: number;
}

interface Persisted {
  accessToken: string;
  refreshToken?: string;
  expiresAt: number;
  lifetime?: number;
  scope: string[];
  tokenType: "Bearer" | "DPoP";
  cnfJkt?: string;
  tenant?: string;
}

function toPersisted(t: CachedToken): Persisted {
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

function fromPersisted(p: Persisted): CachedToken {
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

export class RedisTokenStore implements TokenStore {
  #client: RedisClient;
  #prefix: string;
  #lockWaitMs: number;
  #lockTtl: number;
  #defaultTtl: number;

  constructor(opts: RedisTokenStoreOptions) {
    this.#client = opts.client;
    this.#prefix = (opts.prefix ?? "knoxcall:").replace(/:?$/, ":");
    this.#lockWaitMs = opts.lockWaitMs ?? 10_000;
    this.#lockTtl = opts.lockTtlSeconds ?? 30;
    this.#defaultTtl = opts.defaultCacheTtlSeconds ?? 3600;
  }

  #cacheKey(key: string): string {
    return `${this.#prefix}token:${key}`;
  }

  #lockKey(key: string): string {
    return `${this.#prefix}lock:${key}`;
  }

  async get(key: string): Promise<CachedToken | null> {
    const raw = await this.#client.get(this.#cacheKey(key));
    if (!raw) return null;
    try {
      return fromPersisted(JSON.parse(raw) as Persisted);
    } catch {
      // Corrupt cache entry — treat as miss.
      return null;
    }
  }

  async set(key: string, token: CachedToken): Promise<void> {
    const value = JSON.stringify(toPersisted(token));
    // TTL = time-to-expiry + 60s grace, capped at defaultTtl.
    const ttlSeconds = Math.max(
      60,
      Math.min(this.#defaultTtl, Math.ceil((token.expiresAt - Date.now()) / 1000) + 60),
    );
    if (typeof this.#client.setEx === "function") {
      await this.#client.setEx(this.#cacheKey(key), ttlSeconds, value);
    } else {
      // ioredis-style 4-arg SET with EX mode.
      await this.#client.set(this.#cacheKey(key), value, "EX", ttlSeconds);
    }
  }

  async delete(key: string): Promise<void> {
    await this.#client.del(this.#cacheKey(key));
  }

  async withLock<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const lockKey = this.#lockKey(key);
    const token = randomLockToken();
    const start = Date.now();

    // Attempt to acquire; if someone else holds it, poll until they release
    // or the wait budget exhausts. Polling interval grows linearly to
    // avoid hammering Redis under contention.
    while (true) {
      const acquired = await tryAcquireLock(this.#client, lockKey, token, this.#lockTtl);
      if (acquired) break;

      if (Date.now() - start > this.#lockWaitMs) {
        // We timed out waiting. Proceed without the lock — the caller's
        // refresh logic re-checks the cache first, so worst-case is one
        // duplicate token-endpoint call.
        break;
      }
      const elapsedMs = Date.now() - start;
      const pollMs = Math.min(200, 25 + Math.floor(elapsedMs / 50));
      await new Promise((r) => setTimeout(r, pollMs));
    }

    try {
      return await fn();
    } finally {
      // Best-effort release — guarded so we only delete a lock we still own.
      try {
        const current = await this.#client.get(lockKey);
        if (current === token) {
          await this.#client.del(lockKey);
        }
      } catch {
        /* swallow */
      }
    }
  }
}

function randomLockToken(): string {
  return `${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

async function tryAcquireLock(
  client: RedisClient,
  key: string,
  token: string,
  ttlSeconds: number,
): Promise<boolean> {
  // SET key value NX EX seconds — single-flight primitive (RedLock-lite).
  // Both ioredis and redis@4 accept this signature; the typed wrapper
  // returns either "OK" on success or null on contention.
  const result = await client.set(key, token, "NX", "EX", ttlSeconds);
  // Different drivers return slightly different shapes — treat any
  // truthy non-null result as acquired.
  return result === "OK" || (result !== null && result !== undefined && result !== false);
}
