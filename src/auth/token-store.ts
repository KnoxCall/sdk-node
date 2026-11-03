// Token caching with single-flight refresh.
//
// In-memory MemoryTokenStore is the default. FileTokenStore + RedisTokenStore
// land in SDK v1.1 (PR-12 follow-up).

import { Redacted } from "../redacted.js";

export interface CachedToken {
  accessToken: Redacted<string>;
  refreshToken?: Redacted<string>;
  expiresAt: number; // epoch ms
  lifetime?: number; // original expires_in in ms, for refresh-ahead sizing
  scope: string[];
  tokenType: "Bearer" | "DPoP";
  cnfJkt?: string;
  tenant?: string; // slug from the token response (tenant auto-discovery)
}

export interface TokenStore {
  get(key: string): Promise<CachedToken | null>;
  set(key: string, token: CachedToken): Promise<void>;
  delete(key: string): Promise<void>;
  withLock<T>(key: string, fn: () => Promise<T>): Promise<T>;
}

/**
 * Process-local in-memory token store. Single-flight refresh via a per-key
 * Promise map — the first caller wins the lock, subsequent callers await
 * the same promise.
 */
export class MemoryTokenStore implements TokenStore {
  #tokens = new Map<string, CachedToken>();
  #locks = new Map<string, Promise<unknown>>();

  async get(key: string): Promise<CachedToken | null> {
    return this.#tokens.get(key) ?? null;
  }

  async set(key: string, token: CachedToken): Promise<void> {
    this.#tokens.set(key, token);
  }

  async delete(key: string): Promise<void> {
    this.#tokens.delete(key);
  }

  async withLock<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const existing = this.#locks.get(key);
    if (existing) {
      // Wait for in-flight refresh to finish, then return the freshly-cached value
      // by re-invoking fn (which should re-check the cache first).
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
