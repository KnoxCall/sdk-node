// PR-12a tests: FileTokenStore + telemetry hooks + next-request telemetry header.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { KnoxCall, FileTokenStore, type TelemetryHooks } from '../src/index.js';
import { redact } from '../src/redacted.js';

function makeStub() {
  const calls: { url: string; method: string; headers: Record<string, string> }[] = [];
  const fetchImpl: typeof fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input as Request).url;
    const headers: Record<string, string> = {};
    if (init?.headers) {
      const h = init.headers as Record<string, string>;
      for (const k of Object.keys(h)) headers[k.toLowerCase()] = h[k];
    }
    calls.push({ url, method: init?.method ?? 'GET', headers });
    if (url.endsWith('/oauth/token')) {
      return new Response(
        JSON.stringify({ access_token: 'kc_live_aaaa', token_type: 'Bearer', expires_in: 3600 }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      );
    }
    return new Response(
      JSON.stringify({ data: [], meta: { total: 0, page: 1, per_page: 20, total_pages: 1, request_id: 'req-abc' } }),
      {
        status: 200,
        headers: { 'Content-Type': 'application/json', 'X-Request-Id': 'req-abc' },
      },
    );
  };
  return { fetchImpl, calls };
}

describe('FileTokenStore', () => {
  let tmpDir: string;
  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'kc-sdk-test-'));
  });
  afterEach(() => {
    try {
      rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  });

  it('persists and reads back a token', async () => {
    const path = join(tmpDir, 'cache.json');
    const store = new FileTokenStore(path);
    await store.set('k', {
      accessToken: redact('kc_live_persisted'),
      expiresAt: Date.now() + 60_000,
      scope: ['routes:read'],
      tokenType: 'Bearer',
    });
    const read = await store.get('k');
    expect(read?.accessToken.expose()).toBe('kc_live_persisted');
    expect(read?.scope).toEqual(['routes:read']);
    expect(read?.tokenType).toBe('Bearer');
  });

  it('returns null for unknown keys', async () => {
    const store = new FileTokenStore(join(tmpDir, 'cache.json'));
    expect(await store.get('missing')).toBeNull();
  });

  it('deletes individual keys', async () => {
    const path = join(tmpDir, 'cache.json');
    const store = new FileTokenStore(path);
    await store.set('a', {
      accessToken: redact('A'),
      expiresAt: Date.now() + 60000,
      scope: [],
      tokenType: 'Bearer',
    });
    await store.set('b', {
      accessToken: redact('B'),
      expiresAt: Date.now() + 60000,
      scope: [],
      tokenType: 'Bearer',
    });
    await store.delete('a');
    expect(await store.get('a')).toBeNull();
    expect(await store.get('b')).not.toBeNull();
  });

  it('survives a fresh store instance against the same file', async () => {
    const path = join(tmpDir, 'cache.json');
    const a = new FileTokenStore(path);
    await a.set('k', {
      accessToken: redact('kc_live_shared'),
      expiresAt: Date.now() + 60000,
      scope: [],
      tokenType: 'Bearer',
    });
    const b = new FileTokenStore(path);
    const read = await b.get('k');
    expect(read?.accessToken.expose()).toBe('kc_live_shared');
  });

  it('single-flight refresh: concurrent withLock calls serialize', async () => {
    const path = join(tmpDir, 'cache.json');
    const store = new FileTokenStore(path);
    const events: string[] = [];

    const op = async (label: string) => {
      return store.withLock('k', async () => {
        events.push(`${label}-start`);
        await new Promise((r) => setTimeout(r, 10));
        events.push(`${label}-end`);
        return label;
      });
    };

    await Promise.all([op('A'), op('B')]);
    // After both finish, both start/end events should appear paired,
    // not interleaved.
    const aStart = events.indexOf('A-start');
    const aEnd = events.indexOf('A-end');
    const bStart = events.indexOf('B-start');
    const bEnd = events.indexOf('B-end');
    expect(aEnd).toBeGreaterThan(aStart);
    expect(bEnd).toBeGreaterThan(bStart);
  });
});

describe('Telemetry hooks', () => {
  it('fires onRequest and onResponse with timing + request id', async () => {
    const { fetchImpl } = makeStub();
    const reqInfos: Array<{ method: string; url: string; attempt: number }> = [];
    const resInfos: Array<{ status: number; durationMs: number; requestId?: string }> = [];

    const telemetry: TelemetryHooks = {
      onRequest: (info) => reqInfos.push({ method: info.method, url: info.url, attempt: info.attempt }),
      onResponse: (info) =>
        resInfos.push({ status: info.status, durationMs: info.durationMs, requestId: info.requestId }),
    };

    const client = new KnoxCall({
      tenant: 'acme',
      baseUrl: 'https://api.example.test',
      bootstrap: { type: 'access_token', accessToken: 'kc_live_x' },
      telemetry,
      fetchImpl,
    });
    await client.routes.list();

    expect(reqInfos.length).toBe(1);
    expect(reqInfos[0].method).toBe('GET');
    expect(reqInfos[0].url).toContain('/v1/routes');
    expect(resInfos.length).toBe(1);
    expect(resInfos[0].status).toBe(200);
    expect(resInfos[0].durationMs).toBeGreaterThanOrEqual(0);
    expect(resInfos[0].requestId).toBe('req-abc');
  });

  it('rides previous-response telemetry on the next request header', async () => {
    const { fetchImpl, calls } = makeStub();
    const client = new KnoxCall({
      tenant: 'acme',
      baseUrl: 'https://api.example.test',
      bootstrap: { type: 'access_token', accessToken: 'kc_live_x' },
      fetchImpl,
    });
    await client.routes.list();
    await client.routes.list();
    // First API call has no telemetry header; second should carry the
    // previous one.
    const apiCalls = calls.filter((c) => c.url.endsWith('/v1/routes'));
    expect(apiCalls[0].headers['x-knoxcall-telemetry']).toBeUndefined();
    expect(apiCalls[1].headers['x-knoxcall-telemetry']).toBeTruthy();
    const parsed = JSON.parse(apiCalls[1].headers['x-knoxcall-telemetry']);
    expect(parsed.lr.s).toBe(200);
    expect(parsed.lr.p).toBe('/v1/routes');
  });

  it('fires onRetry with delay and reason on retryable errors', async () => {
    let attempts = 0;
    const fetchImpl: typeof fetch = async (input) => {
      const url = typeof input === 'string' ? input : (input as Request).url;
      if (url.endsWith('/oauth/token')) {
        return new Response(
          JSON.stringify({ access_token: 'kc_live_x', token_type: 'Bearer', expires_in: 3600 }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      attempts++;
      if (attempts < 2) return new Response(JSON.stringify({ error: 'unavailable' }), { status: 503, headers: { 'Content-Type': 'application/json' } });
      return new Response(
        JSON.stringify({ data: [], meta: { total: 0, page: 1, per_page: 20, total_pages: 1, request_id: 'req-abc' } }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      );
    };

    const retries: Array<{ delayMs: number; status?: number }> = [];
    const client = new KnoxCall({
      tenant: 'acme',
      baseUrl: 'https://api.example.test',
      bootstrap: { type: 'client_credentials', clientId: 'tk_x', clientSecret: 'sec' },
      retry: { maxAttempts: 3, baseDelayMs: 1, maxDelayMs: 5 },
      telemetry: { onRetry: (info) => retries.push({ delayMs: info.delayMs, status: info.status }) },
      fetchImpl,
    });
    await client.routes.list();
    expect(retries.length).toBe(1);
    expect(retries[0].status).toBe(503);
  });
});
