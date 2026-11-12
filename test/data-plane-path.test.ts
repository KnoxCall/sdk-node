// PARITY §5 — where the data plane lives under a proxy base.
//
// On a KnoxCall cloud tenant host the proxy is served ONLY under `/api`
// (server.ts strips the prefix; every other path on that host is the
// dashboard). Until 2026-09-25 call() sent `${proxyBase}${path}`, so every
// documented `path: "/users"` example answered the dashboard HTML on a real
// tenant host, and the five live smokes passed only because each hard-coded
// `path: "/api/get"`. Measured on a local server that day: `GET /api/get` →
// 200 with X-Knox-Upstream-Status; `GET /get` → the SPA branch, no upstream
// call. These pin the URL call() builds for every base shape.
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { KnoxCall } from '../src/index.js';
import { dataPlanePathPrefix } from '../src/core.js';

const ENV_VARS = ['KNOXCALL_PROXY_BASE_URL', 'KNOXCALL_BASE_URL', 'KNOXCALL_API_BASE_URL', 'KNOXCALL_TENANT', 'KNOXCALL_ENVIRONMENT'];
const savedEnv: Record<string, string | undefined> = {};
beforeEach(() => {
  for (const n of ENV_VARS) {
    savedEnv[n] = process.env[n];
    delete process.env[n];
  }
});
afterEach(() => {
  for (const n of ENV_VARS) {
    if (savedEnv[n] === undefined) delete process.env[n];
    else process.env[n] = savedEnv[n];
  }
});

function capture(seen: string[]): typeof fetch {
  return async (input) => {
    seen.push(typeof input === 'string' ? input : input instanceof URL ? input.href : (input as Request).url);
    return new Response('{"ok":true}', { status: 200, headers: { 'Content-Type': 'application/json' } });
  };
}

async function urlOf(opts: Record<string, unknown>, path = '/users'): Promise<string> {
  const seen: string[] = [];
  const client = new KnoxCall({ tenant: 'acme', accessToken: 'kc_live_pre', fetchImpl: capture(seen), ...opts });
  await client.call('r_1', { path });
  expect(seen).toHaveLength(1);
  return seen[0];
}

describe('dataPlanePathPrefix — the rule itself', () => {
  it.each<[string, '' | '/api']>([
    ['https://acme.knoxcall.com', '/api'],
    ['https://acme.knoxcall.com/', '/api'],
    ['https://sandbox-acme.knoxcall.com', '/api'],
    ['http://sandbox-acme.knoxcall.com:3100', '/api'],
    ['https://ACME.KnoxCall.com', '/api'],
    ['https://acme.knoxcall.com/api', ''],
    ['https://acme.knoxcall.com/proxy', ''],
    ['https://api.knoxcall.com', ''],
    ['https://sandbox.knoxcall.com', ''],
    ['https://api-staging.knoxcall.com', ''],
    ['https://sandbox-staging.knoxcall.com', ''],
    ['https://www.knoxcall.com', ''],
    ['https://staging.knoxcall.com', ''],
    ['https://admin.knoxcall.com', ''],
    ['https://a.b.knoxcall.com', ''],
    ['https://knoxcall.com', ''],
    ['https://acme.knoxcall.com.evil.test', ''],
    ['http://localhost:3000', ''],
    ['https://knox.example.com', ''],
    ['not a url', ''],
  ])('%s → %j', (base, want) => {
    expect(dataPlanePathPrefix(base)).toBe(want);
  });
});

describe('call() places the upstream path under the tenant host entry point', () => {
  it('derived sandbox shape', async () => {
    expect(await urlOf({ baseUrl: 'https://sandbox.knoxcall.com' })).toBe('https://sandbox-acme.knoxcall.com/api/users');
  });

  it('derived plain shape', async () => {
    expect(await urlOf({ baseUrl: 'https://api.knoxcall.com' })).toBe('https://acme.knoxcall.com/api/users');
  });

  it('an explicit override naming a tenant host, any port (the live smoke harness)', async () => {
    expect(await urlOf({ baseUrl: 'http://sandbox.knoxcall.com:3100', proxyBaseUrl: 'http://sandbox-acme.knoxcall.com:3100' }, '/get'))
      .toBe('http://sandbox-acme.knoxcall.com:3100/api/get');
  });

  it('the KNOXCALL_PROXY_BASE_URL override behaves the same', async () => {
    process.env.KNOXCALL_PROXY_BASE_URL = 'https://sandbox-acme.knoxcall.com';
    expect(await urlOf({ baseUrl: 'https://sandbox.knoxcall.com' }, '/get')).toBe('https://sandbox-acme.knoxcall.com/api/get');
  });

  it('an override that already carries the entry point is used verbatim — never doubled', async () => {
    expect(await urlOf({ baseUrl: 'https://sandbox.knoxcall.com', proxyBaseUrl: 'https://sandbox-acme.knoxcall.com/api' }, '/get'))
      .toBe('https://sandbox-acme.knoxcall.com/api/get');
  });

  it('a loopback override is verbatim (local dev mounts the proxy at /)', async () => {
    expect(await urlOf({ baseUrl: 'http://localhost:3000', proxyBaseUrl: 'http://localhost:3000' }, '/get')).toBe('http://localhost:3000/get');
  });

  it('a self-hosted base is verbatim', async () => {
    expect(await urlOf({ baseUrl: 'https://knox.example.com' }, '/get')).toBe('https://knox.example.com/get');
  });

  it('a path without a leading slash, and an upstream path that itself starts with /api', async () => {
    expect(await urlOf({ baseUrl: 'https://api.knoxcall.com' }, 'users')).toBe('https://acme.knoxcall.com/api/users');
    expect(await urlOf({ baseUrl: 'https://api.knoxcall.com' }, '/api/v2/tickets')).toBe('https://acme.knoxcall.com/api/api/v2/tickets');
  });

  it('the bare route path is /api/', async () => {
    expect(await urlOf({ baseUrl: 'https://api.knoxcall.com' }, '/')).toBe('https://acme.knoxcall.com/api/');
  });

  it('bound routes inherit it', async () => {
    const seen: string[] = [];
    const client = new KnoxCall({ tenant: 'acme', accessToken: 'kc_live_pre', fetchImpl: capture(seen), baseUrl: 'https://api.knoxcall.com' });
    await client.route('r_1').get('/users');
    expect(seen).toEqual(['https://acme.knoxcall.com/api/users']);
  });
});
