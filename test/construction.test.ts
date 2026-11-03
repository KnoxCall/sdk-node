// Tests for flat construction, env fallbacks, and bound routes (PARITY §2/§6).
// Mirrors knoxcall-python/tests/test_construction.py.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { KnoxCall, BoundRoute, BootstrapError, ClientCredentials, type KnoxCallOptions } from '../src/index.js';

const ENV_VARS = [
  'KNOXCALL_TENANT',
  'KNOXCALL_ENVIRONMENT',
  'KNOXCALL_BASE_URL',
  'KNOXCALL_PROXY_BASE_URL',
  'KNOXCALL_ACCESS_TOKEN',
  'KNOXCALL_API_KEY',
  'KNOXCALL_CLIENT_ID',
  'KNOXCALL_CLIENT_SECRET',
] as const;

let savedEnv: Record<string, string | undefined>;

beforeEach(() => {
  savedEnv = {};
  for (const name of ENV_VARS) {
    savedEnv[name] = process.env[name];
    delete process.env[name];
  }
});

afterEach(() => {
  for (const name of ENV_VARS) {
    if (savedEnv[name] === undefined) delete process.env[name];
    else process.env[name] = savedEnv[name];
  }
});

interface SeenRequest {
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: string;
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function tokenResponse(token = 'kc_live_aaaa'): Response {
  return json(200, { access_token: token, token_type: 'Bearer', expires_in: 3600 });
}

function stubFetch(handler: (req: SeenRequest) => Response | Promise<Response>): typeof fetch {
  return async (input, init) => {
    const url = typeof input === 'string' ? input : (input as Request).url;
    const headers: Record<string, string> = {};
    if (init?.headers) {
      const h = init.headers as Record<string, string>;
      for (const k of Object.keys(h)) headers[k.toLowerCase()] = h[k];
    }
    return handler({
      url,
      method: init?.method ?? 'GET',
      headers,
      body: typeof init?.body === 'string' ? init.body : undefined,
    });
  };
}

const URLS = { baseUrl: 'https://api.example.test', proxyBaseUrl: 'https://acme.example.test' };

// ── Flat credential options ───────────────────────────────────────────────────

describe('flat credential options', () => {
  it('clientId/clientSecret mint identically to a ClientCredentials bootstrap', async () => {
    const seen: SeenRequest[] = [];
    const fetchImpl = stubFetch((req) => {
      if (req.url.endsWith('/oauth/token')) {
        seen.push(req);
        return tokenResponse();
      }
      return json(200, { ok: true });
    });
    const client = new KnoxCall({ tenant: 'acme', clientId: 'tk_x', clientSecret: 'sec', fetchImpl, ...URLS });
    await client.call('r_1', { path: '/x' });

    expect(seen[0].headers['authorization']).toMatch(/^Basic /);
    expect(seen[0].body).toContain('grant_type=client_credentials');
  });

  it('accessToken and apiKey attach Bearer without hitting the token endpoint', async () => {
    for (const cred of [{ accessToken: 'kc_live_pre' }, { apiKey: 'kc_live_pre' }]) {
      const paths: string[] = [];
      const seen: SeenRequest[] = [];
      const fetchImpl = stubFetch((req) => {
        paths.push(new URL(req.url).pathname);
        seen.push(req);
        return json(200, { ok: true });
      });
      const client = new KnoxCall({ tenant: 'acme', fetchImpl, ...URLS, ...cred });
      await client.call('r_1', { path: '/x' });
      expect(paths).not.toContain('/oauth/token');
      expect(seen[0].headers['authorization']).toBe('Bearer kc_live_pre');
    }
  });

  it('sends a legacy tk_ key as x-knoxcall-key on call()', async () => {
    const seen: SeenRequest[] = [];
    const fetchImpl = stubFetch((req) => {
      seen.push(req);
      return json(200, { ok: true });
    });
    const client = new KnoxCall({ tenant: 'acme', apiKey: 'tk_live_legacy', fetchImpl, ...URLS });
    await client.call('r_1', { path: '/x' });

    // proxy OAuth detection matches `Bearer kc_` only — tk_ must use the header
    expect(seen[0].headers['x-knoxcall-key']).toBe('tk_live_legacy');
    expect(seen[0].headers['authorization']).toBeUndefined();
  });

  it('keeps a legacy tk_ key on Authorization for ephemeral() (/v1/proxy accepts any Bearer)', async () => {
    const seen: SeenRequest[] = [];
    const fetchImpl = stubFetch((req) => {
      seen.push(req);
      return json(200, { ok: true });
    });
    const client = new KnoxCall({ tenant: 'acme', apiKey: 'tk_live_legacy', fetchImpl, ...URLS });
    await client.ephemeral('https://upstream.example/x');

    expect(seen[0].url).toBe('https://api.example.test/v1/proxy');
    expect(seen[0].headers['authorization']).toBe('Bearer tk_live_legacy');
    expect(seen[0].headers['x-knoxcall-key']).toBeUndefined();
  });

  it('ephemeral() mode:"transparent" sends X-Knox-Proxy-Mode: transparent (PR2 wrap support)', async () => {
    const seen: SeenRequest[] = [];
    const fetchImpl = stubFetch((req) => { seen.push(req); return json(200, { ok: true }); });
    const client = new KnoxCall({ tenant: 'acme', apiKey: 'kc_live_x', fetchImpl, ...URLS });
    await client.ephemeral('https://api.stripe.com/v1/charges', {
      method: 'POST',
      mode: 'transparent',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'amount=2000&currency=usd',
    });
    expect(seen[0].headers['x-knox-proxy-mode']).toBe('transparent');
    // The raw body is forwarded verbatim, not JSON-re-encoded.
    expect(seen[0].body).toBe('amount=2000&currency=usd');
  });

  it('ephemeral() upstreamAuthorization sends X-Knox-Upstream-Authorization (PR2 wrap support)', async () => {
    const seen: SeenRequest[] = [];
    const fetchImpl = stubFetch((req) => { seen.push(req); return json(200, { ok: true }); });
    const client = new KnoxCall({ tenant: 'acme', apiKey: 'kc_live_x', fetchImpl, ...URLS });
    await client.ephemeral('https://api.stripe.com/v1/charges', {
      method: 'POST',
      mode: 'transparent',
      upstreamAuthorization: 'Bearer sk_live_provider',
      body: 'amount=2000',
    });
    expect(seen[0].headers['x-knox-upstream-authorization']).toBe('Bearer sk_live_provider');
    // The SDK's own KnoxCall credential still authenticates the proxy call.
    expect(seen[0].headers['authorization']).toBe('Bearer kc_live_x');
  });

  it('ephemeral() without the new options is unchanged (no PR2 headers emitted)', async () => {
    const seen: SeenRequest[] = [];
    const fetchImpl = stubFetch((req) => { seen.push(req); return json(200, { ok: true }); });
    const client = new KnoxCall({ tenant: 'acme', apiKey: 'kc_live_x', fetchImpl, ...URLS });
    await client.ephemeral('https://upstream.example/x');
    expect(seen[0].headers['x-knox-proxy-mode']).toBeUndefined();
    expect(seen[0].headers['x-knox-upstream-authorization']).toBeUndefined();
  });

  it('throws BootstrapError on every conflict-matrix combination', () => {
    const bootstrap = new ClientCredentials({ clientId: 'tk_x', clientSecret: 'sec' });
    const conflicts: Partial<KnoxCallOptions>[] = [
      { bootstrap, clientId: 'tk_x' },
      { accessToken: 'kc_a', apiKey: 'kc_b' },
      { apiKey: 'kc_a', clientId: 'tk_x', clientSecret: 's' },
      { clientId: 'tk_x' }, // missing clientSecret
      { clientSecret: 's' }, // missing clientId
    ];
    for (const opts of conflicts) {
      expect(() => new KnoxCall({ tenant: 'acme', ...opts })).toThrow(BootstrapError);
    }
  });
});

// ── Tenant env fallback / zero-arg ────────────────────────────────────────────

describe('tenant resolution', () => {
  it('resolves tenant from KNOXCALL_TENANT and derives the proxy URL from it', () => {
    process.env.KNOXCALL_TENANT = 'envcorp';
    const client = new KnoxCall({ accessToken: 'kc_live_x' });
    expect(client.tenant).toBe('envcorp');
    // proxy URL must derive from the env-resolved tenant
    expect(client.proxyBaseUrl).toBe('https://envcorp.knoxcall.com');
  });

  it('explicit tenant beats KNOXCALL_TENANT', () => {
    process.env.KNOXCALL_TENANT = 'envcorp';
    const client = new KnoxCall({ tenant: 'explicit', accessToken: 'kc_live_x' });
    expect(client.tenant).toBe('explicit');
  });

  it('rejects a non-DNS-label tenant slug before it becomes a data-plane host', () => {
    // A slug like "evil.com#" would yield https://evil.com#.knoxcall.com,
    // whose real host is evil.com — refuse to send the token there.
    expect(() => new KnoxCall({ tenant: 'evil.com#', accessToken: 'kc_live_x' })).toThrow(
      BootstrapError,
    );
    expect(() => new KnoxCall({ tenant: 'a/b', accessToken: 'kc_live_x' })).toThrow(BootstrapError);
  });

  it('rejects a hostile tenant slug discovered from the token response', async () => {
    const fetchImpl = stubFetch((req) => {
      if (req.url.endsWith('/oauth/token')) {
        return json(200, {
          access_token: 'kc_live_a', token_type: 'Bearer',
          expires_in: 3600, tenant: 'evil.com#',
        });
      }
      return json(200, { ok: true });
    });
    const client = new KnoxCall({ clientId: 'tk_x', clientSecret: 's', fetchImpl });
    await expect(client.call('r_1', { path: '/x' })).rejects.toThrow(BootstrapError);
  });

  it('discovers the tenant from the token response and derives the proxy host', async () => {
    const seen: { host?: string } = {};
    const fetchImpl = stubFetch((req) => {
      if (req.url.endsWith('/oauth/token')) {
        return json(200, {
          access_token: 'kc_live_a', token_type: 'Bearer',
          expires_in: 3600, tenant: 'discovered',
        });
      }
      seen.host = new URL(req.url).host;
      return json(200, { ok: true });
    });

    const client = new KnoxCall({ clientId: 'tk_x', clientSecret: 's', fetchImpl });
    const res = await client.call('r_1', { path: '/x' });

    expect(res.status).toBe(200);
    expect(client.tenant).toBe('discovered');
    expect(seen.host).toBe('discovered.knoxcall.com');
  });

  it('discovers via /v1/account for pre-acquired tokens, exactly once', async () => {
    const paths: string[] = [];
    const seen: { host?: string } = {};
    const fetchImpl = stubFetch((req) => {
      const url = new URL(req.url);
      paths.push(url.pathname);
      if (url.pathname === '/v1/account') {
        return json(200, { data: { slug: 'fromaccount', name: 'X' } });
      }
      seen.host = url.host;
      return json(200, { ok: true });
    });

    const client = new KnoxCall({ accessToken: 'kc_live_pre', fetchImpl });
    await client.call('r_1', { path: '/x' });
    await client.call('r_1', { path: '/y' });

    expect(paths.filter((p) => p === '/v1/account')).toHaveLength(1);
    expect(seen.host).toBe('fromaccount.knoxcall.com');
  });

  it('raises an actionable error when the tenant cannot be discovered', async () => {
    const fetchImpl = stubFetch((req) => {
      if (new URL(req.url).pathname === '/v1/account') {
        return json(200, { data: { name: 'no slug here' } });
      }
      return json(200, { ok: true });
    });

    const client = new KnoxCall({ accessToken: 'kc_live_pre', fetchImpl });
    await expect(client.call('r_1', { path: '/x' })).rejects.toThrow(/KNOXCALL_TENANT/);
  });

  it('management requests need no tenant and trigger no discovery', async () => {
    const emptyPage = { data: [], meta: { total: 0, page: 1, per_page: 20, total_pages: 1, request_id: 'req-1' } };
    const fetchImpl = stubFetch((req) => {
      if (req.url.endsWith('/oauth/token')) return tokenResponse();
      return json(200, emptyPage);
    });

    const client = new KnoxCall({ clientId: 'tk_x', clientSecret: 's', fetchImpl, ...URLS });
    expect(await client.routes.list()).toEqual(emptyPage);
    expect(client.tenant).toBeUndefined();
  });

  it('supports zero-arg construction with a fully configured environment', () => {
    process.env.KNOXCALL_TENANT = 'envcorp';
    process.env.KNOXCALL_CLIENT_ID = 'tk_env';
    process.env.KNOXCALL_CLIENT_SECRET = 'sec';
    const client = new KnoxCall();
    expect(client.tenant).toBe('envcorp');
  });
});

// ── Env credential fill ───────────────────────────────────────────────────────

describe('env credential fill', () => {
  it('KNOXCALL_ACCESS_TOKEN wins over KNOXCALL_API_KEY', async () => {
    process.env.KNOXCALL_ACCESS_TOKEN = 'kc_env_token';
    process.env.KNOXCALL_API_KEY = 'kc_env_key';
    const seen: SeenRequest[] = [];
    const fetchImpl = stubFetch((req) => {
      seen.push(req);
      return json(200, { ok: true });
    });
    const client = new KnoxCall({ tenant: 'acme', fetchImpl, ...URLS });
    await client.call('r_1', { path: '/x' });
    expect(seen[0].headers['authorization']).toBe('Bearer kc_env_token');
  });

  it('is skipped entirely when an explicit credential was passed', async () => {
    process.env.KNOXCALL_ACCESS_TOKEN = 'kc_env_token';
    const seen: SeenRequest[] = [];
    const fetchImpl = stubFetch((req) => {
      seen.push(req);
      return json(200, { ok: true });
    });
    const client = new KnoxCall({ tenant: 'acme', accessToken: 'kc_explicit', fetchImpl, ...URLS });
    await client.call('r_1', { path: '/x' });
    expect(seen[0].headers['authorization']).toBe('Bearer kc_explicit');
  });
});

// ── Bound routes ──────────────────────────────────────────────────────────────

function captureClient(seen: { headers?: Record<string, string>; method?: string; url?: string }): KnoxCall {
  const fetchImpl = stubFetch((req) => {
    if (req.url.endsWith('/oauth/token')) return tokenResponse();
    seen.headers = req.headers;
    seen.method = req.method;
    seen.url = req.url;
    return json(200, { ok: true });
  });
  return new KnoxCall({ tenant: 'acme', clientId: 'tk_x', clientSecret: 's', fetchImpl, ...URLS });
}

describe('bound routes', () => {
  it('route() returns a BoundRoute value object', () => {
    const client = captureClient({});
    expect(client.route('r_1')).toBeInstanceOf(BoundRoute);
  });

  it('injects route, environment, and bound headers on every call', async () => {
    const seen: { headers?: Record<string, string>; method?: string; url?: string } = {};
    const client = captureClient(seen);
    const printnode = client.route('r_1', { environment: 'production', headers: { 'X-A': 'bound' } });
    const res = await printnode.get('/computers');

    expect(res.status).toBe(200);
    expect(seen.headers!['x-knoxcall-route']).toBe('r_1');
    expect(seen.headers!['x-knoxcall-environment']).toBe('production');
    expect(seen.headers!['x-a']).toBe('bound');
    expect(seen.url!.endsWith('/computers')).toBe(true);
  });

  it('per-call values beat the bound defaults', async () => {
    const seen: { headers?: Record<string, string>; method?: string; url?: string } = {};
    const client = captureClient(seen);
    const bound = client.route('r_1', { environment: 'production', headers: { 'X-A': 'bound' } });
    await bound.post('/printjobs', { body: { a: 1 }, environment: 'staging', headers: { 'X-A': 'call' } });

    expect(seen.method).toBe('POST');
    expect(seen.headers!['x-knoxcall-environment']).toBe('staging');
    expect(seen.headers!['x-a']).toBe('call');
  });

  it('exposes a generic request() for arbitrary methods', async () => {
    const seen: { headers?: Record<string, string>; method?: string; url?: string } = {};
    const client = captureClient(seen);
    await client.route('r_1').request('DELETE', '/printjobs/42');

    expect(seen.method).toBe('DELETE');
    expect(seen.url!.endsWith('/printjobs/42')).toBe(true);
  });
});

// ── Default environment (PARITY §2) ───────────────────────────────────────────

function captureClientWith(
  seen: { headers?: Record<string, string> },
  opts: Partial<KnoxCallOptions>,
): KnoxCall {
  const fetchImpl = stubFetch((req) => {
    if (req.url.endsWith('/oauth/token')) return tokenResponse();
    seen.headers = req.headers;
    return json(200, { ok: true });
  });
  return new KnoxCall({ tenant: 'acme', clientId: 'tk_x', clientSecret: 's', fetchImpl, ...URLS, ...opts });
}

describe('default environment', () => {
  it('client-level environment applies to call()', async () => {
    const seen: { headers?: Record<string, string> } = {};
    const client = captureClientWith(seen, { environment: 'production' });
    await client.call('r_1', { path: '/x' });
    expect(seen.headers!['x-knoxcall-environment']).toBe('production');
  });

  it('resolution order: per-call > bound > client', async () => {
    const seen: { headers?: Record<string, string> } = {};
    const client = captureClientWith(seen, { environment: 'client-env' });

    await client.route('r_1').get('/x');
    expect(seen.headers!['x-knoxcall-environment']).toBe('client-env');

    await client.route('r_1', { environment: 'bound-env' }).get('/x');
    expect(seen.headers!['x-knoxcall-environment']).toBe('bound-env');

    await client.route('r_1', { environment: 'bound-env' }).get('/x', { environment: 'call-env' });
    expect(seen.headers!['x-knoxcall-environment']).toBe('call-env');
  });

  it('falls back to KNOXCALL_ENVIRONMENT with explicit option winning', () => {
    process.env.KNOXCALL_ENVIRONMENT = 'staging';
    expect(captureClientWith({}, {}).environment).toBe('staging');
    expect(captureClientWith({}, { environment: 'production' }).environment).toBe('production');
  });
});
