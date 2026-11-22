// RedisTokenStore tests with an in-memory stub Redis client.

import { describe, it, expect, beforeEach } from 'vitest';
import { RedisTokenStore, type RedisClient } from '../src/auth/redis-token-store.js';
import { redact } from '../src/redacted.js';

function makeStubRedis(): RedisClient & { _data: Map<string, { value: string; expiresAt: number }>; _ops: string[] } {
  const data = new Map<string, { value: string; expiresAt: number }>();
  const ops: string[] = [];

  const purge = () => {
    const now = Date.now();
    for (const [k, v] of data.entries()) {
      if (v.expiresAt && v.expiresAt < now) data.delete(k);
    }
  };

  return {
    _data: data,
    _ops: ops,

    async get(key: string) {
      purge();
      ops.push(`GET ${key}`);
      return data.get(key)?.value ?? null;
    },

    async set(key: string, value: string, ...args: (string | number)[]) {
      purge();
      ops.push(`SET ${key} ${args.join(' ')}`);
      let ttl = 0;
      let nx = false;
      for (let i = 0; i < args.length; i++) {
        const a = String(args[i]).toUpperCase();
        if (a === 'NX') nx = true;
        else if (a === 'EX') ttl = Number(args[i + 1]);
      }
      if (nx && data.has(key) && (data.get(key)!.expiresAt === 0 || data.get(key)!.expiresAt > Date.now())) {
        return null;
      }
      data.set(key, { value, expiresAt: ttl > 0 ? Date.now() + ttl * 1000 : 0 });
      return 'OK';
    },

    async del(key: string | string[]) {
      const keys = Array.isArray(key) ? key : [key];
      let n = 0;
      for (const k of keys) {
        if (data.delete(k)) n++;
      }
      ops.push(`DEL ${keys.join(',')}`);
      return n;
    },
  };
}

describe('RedisTokenStore', () => {
  let client: ReturnType<typeof makeStubRedis>;
  let store: RedisTokenStore;

  beforeEach(() => {
    client = makeStubRedis();
    store = new RedisTokenStore({ client, prefix: 'test:' });
  });

  it('returns null on cache miss', async () => {
    expect(await store.get('k')).toBeNull();
  });

  it('persists and reads back a token', async () => {
    await store.set('k', {
      accessToken: redact('kc_live_xyz'),
      expiresAt: Date.now() + 60_000,
      scope: ['routes:read'],
      tokenType: 'Bearer',
    });
    const got = await store.get('k');
    expect(got?.accessToken.expose()).toBe('kc_live_xyz');
    expect(got?.scope).toEqual(['routes:read']);
  });

  it('namespaces keys under the configured prefix', async () => {
    await store.set('k', {
      accessToken: redact('x'),
      expiresAt: Date.now() + 60_000,
      scope: [],
      tokenType: 'Bearer',
    });
    const keys = [...client._data.keys()];
    expect(keys.some((k) => k.startsWith('test:token:'))).toBe(true);
  });

  it('uses SET EX with sensible TTL', async () => {
    await store.set('k', {
      accessToken: redact('x'),
      expiresAt: Date.now() + 30 * 60 * 1000, // 30 min
      scope: [],
      tokenType: 'Bearer',
    });
    const setOp = client._ops.find((o) => o.startsWith('SET test:token'));
    expect(setOp).toMatch(/EX \d+/);
  });

  it('deletes the cache entry', async () => {
    await store.set('k', {
      accessToken: redact('x'),
      expiresAt: Date.now() + 60_000,
      scope: [],
      tokenType: 'Bearer',
    });
    await store.delete('k');
    expect(await store.get('k')).toBeNull();
  });

  it('single-flight withLock: second caller waits for first', async () => {
    const sequence: string[] = [];

    // Set a short lock wait so we know if the lock acquire path actually fires.
    const fastStore = new RedisTokenStore({ client, prefix: 'test:', lockWaitMs: 5000, lockTtlSeconds: 5 });

    const op = async (label: string, ms: number) =>
      fastStore.withLock('k', async () => {
        sequence.push(`${label}-start`);
        await new Promise((r) => setTimeout(r, ms));
        sequence.push(`${label}-end`);
        return label;
      });

    const [a, b] = await Promise.all([op('A', 80), op('B', 20)]);
    expect(a).toBe('A');
    expect(b).toBe('B');
    // The second one must start AFTER the first ends (serialized).
    const aStart = sequence.indexOf('A-start');
    const aEnd = sequence.indexOf('A-end');
    const bStart = sequence.indexOf('B-start');
    expect(aStart).toBeLessThan(aEnd);
    expect(bStart).toBeGreaterThan(aEnd);
  });

  it('returns null on corrupt JSON', async () => {
    // Inject a malformed value directly via the underlying stub.
    client._data.set('test:token:k', { value: 'not-json', expiresAt: 0 });
    expect(await store.get('k')).toBeNull();
  });

  it('lock is released after the wrapped fn resolves', async () => {
    await store.withLock('k', async () => 'done');
    // Lock key should be gone.
    expect(await client.get('test:lock:k')).toBeNull();
  });

  it('lock is released even on error', async () => {
    await expect(
      store.withLock('k', async () => {
        throw new Error('boom');
      }),
    ).rejects.toThrow('boom');
    expect(await client.get('test:lock:k')).toBeNull();
  });
});
