// End-to-end SDK tests using a stub fetch implementation.
// Verifies: token acquisition, header injection, retry, error mapping,
// idempotency key generation, DPoP signing.

import { describe, it, expect, vi } from 'vitest';
import { KnoxCall } from '../src/index.js';
import { MemoryTokenStore } from '../src/auth/token-store.js';

interface StubCall {
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: string;
}

function makeStub(opts: {
  tokenResponse?: () => { status: number; body: unknown; headers?: Record<string, string> };
  apiResponse?: () => { status: number; body: unknown; headers?: Record<string, string> };
}) {
  const calls: StubCall[] = [];
  const fetchImpl: typeof fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input as Request).url;
    const headers: Record<string, string> = {};
    if (init?.headers) {
      const h = init.headers as Record<string, string>;
      for (const k of Object.keys(h)) headers[k.toLowerCase()] = h[k];
    }
    const call: StubCall = {
      url,
      method: init?.method ?? 'GET',
      headers,
      body: typeof init?.body === 'string' ? init.body : undefined,
    };
    calls.push(call);

    if (url.endsWith('/oauth/token')) {
      const r = opts.tokenResponse?.() ?? {
        status: 200,
        body: { access_token: 'kc_live_aaaa', token_type: 'Bearer', expires_in: 3600 },
      };
      return new Response(JSON.stringify(r.body), {
        status: r.status,
        headers: { 'Content-Type': 'application/json', ...(r.headers ?? {}) },
      });
    }

    const r = opts.apiResponse?.() ?? {
      status: 200,
      // Real server envelope: paginated lists carry page-based meta.
      body: {
        data: [{ id: 'r_1', name: 'test', slug: null, target_base_url: 'https://x', enabled: true, created_at: '' }],
        meta: { total: 1, page: 1, per_page: 20, total_pages: 1, request_id: 'req-1' },
      },
    };
    return new Response(JSON.stringify(r.body), {
      status: r.status,
      headers: { 'Content-Type': 'application/json', ...(r.headers ?? {}) },
    });
  };
  return { fetchImpl, calls };
}

describe('KnoxCall — token acquisition', () => {
  it('mints a Bearer token via client_credentials and attaches it', async () => {
    const { fetchImpl, calls } = makeStub({});
    const client = new KnoxCall({
      tenant: 'acme',
      baseUrl: 'https://api.example.test',
      bootstrap: { type: 'client_credentials', clientId: 'tk_x', clientSecret: 'sec' },
      tokenStore: new MemoryTokenStore(),
      fetchImpl,
    });
    await client.routes.list();

    expect(calls[0].url).toBe('https://api.example.test/oauth/token');
    expect(calls[0].method).toBe('POST');
    expect(calls[0].headers['authorization']).toMatch(/^Basic /);
    expect(calls[0].body).toContain('grant_type=client_credentials');

    expect(calls[1].url).toBe('https://api.example.test/v1/routes');
    expect(calls[1].headers['authorization']).toBe('Bearer kc_live_aaaa');
    expect(calls[1].headers['knoxcall-version']).toBeTruthy();
  });

  it('caches the token across API calls (single token-endpoint hit)', async () => {
    const { fetchImpl, calls } = makeStub({});
    const client = new KnoxCall({
      tenant: 'acme',
      baseUrl: 'https://api.example.test',
      bootstrap: { type: 'client_credentials', clientId: 'tk_x', clientSecret: 'sec' },
      fetchImpl,
    });
    await client.routes.list();
    await client.routes.list();
    await client.routes.list();
    const tokenCalls = calls.filter((c) => c.url.endsWith('/oauth/token'));
    expect(tokenCalls.length).toBe(1);
  });

  it('uses pre-acquired access token without hitting token endpoint', async () => {
    const { fetchImpl, calls } = makeStub({});
    const client = new KnoxCall({
      tenant: 'acme',
      baseUrl: 'https://api.example.test',
      bootstrap: { type: 'access_token', accessToken: 'kc_live_preset' },
      fetchImpl,
    });
    await client.routes.list();
    const tokenCalls = calls.filter((c) => c.url.endsWith('/oauth/token'));
    expect(tokenCalls.length).toBe(0);
    const apiCall = calls.find((c) => c.url.endsWith('/v1/routes'))!;
    expect(apiCall.headers['authorization']).toBe('Bearer kc_live_preset');
  });

  it('uses OIDC token-exchange when bootstrap is workload identity', async () => {
    const { fetchImpl, calls } = makeStub({});
    const client = new KnoxCall({
      tenant: 'acme',
      baseUrl: 'https://api.example.test',
      bootstrap: { type: 'oidc_token_exchange', subjectToken: 'eyJraWQiOiJ4In0.aGVsbG8.', issuer: 'https://gh' },
      fetchImpl,
    });
    await client.routes.list();
    expect(calls[0].body).toContain('grant_type=urn');
    expect(calls[0].body).toContain('subject_token');
    expect(calls[0].body).toContain('audience=knoxcall');
  });
});

describe('KnoxCall — DPoP binding', () => {
  it('adds DPoP scheme + proof header when dpop="always"', async () => {
    const { fetchImpl, calls } = makeStub({
      tokenResponse: () => ({
        status: 200,
        body: { access_token: 'kc_live_dpop', token_type: 'DPoP', expires_in: 3600 },
      }),
    });
    const client = new KnoxCall({
      tenant: 'acme',
      baseUrl: 'https://api.example.test',
      bootstrap: { type: 'client_credentials', clientId: 'tk_x', clientSecret: 'sec' },
      dpop: 'always',
      fetchImpl,
    });
    await client.routes.list();

    const tokenCall = calls.find((c) => c.url.endsWith('/oauth/token'))!;
    expect(tokenCall.headers['dpop']).toBeTruthy();

    const apiCall = calls.find((c) => c.url.endsWith('/v1/routes'))!;
    expect(apiCall.headers['authorization']).toBe('DPoP kc_live_dpop');
    expect(apiCall.headers['dpop']).toBeTruthy();
    // DPoP proof is a 3-part JWT
    expect(apiCall.headers['dpop'].split('.').length).toBe(3);
  });
});

describe('KnoxCall — idempotency keys', () => {
  it('attaches X-Idempotency-Key on POST', async () => {
    const { fetchImpl, calls } = makeStub({
      apiResponse: () => ({
        status: 200,
        body: {
          data: { id: 'r_1', name: 'created', slug: null, target_base_url: 'x', enabled: true, created_at: '' },
          meta: { request_id: 'req-1' },
        },
      }),
    });
    const client = new KnoxCall({
      tenant: 'acme',
      baseUrl: 'https://api.example.test',
      bootstrap: { type: 'access_token', accessToken: 'kc_live_x' },
      fetchImpl,
    });
    await client.routes.create({ name: 'x', target_base_url: 'y' });
    const apiCall = calls.find((c) => c.url.endsWith('/v1/routes'))!;
    expect(apiCall.headers['x-idempotency-key']).toMatch(/^[0-9A-Z]{26}$/);
  });

  it('does NOT attach X-Idempotency-Key on GET', async () => {
    const { fetchImpl, calls } = makeStub({});
    const client = new KnoxCall({
      tenant: 'acme',
      baseUrl: 'https://api.example.test',
      bootstrap: { type: 'access_token', accessToken: 'kc_live_x' },
      fetchImpl,
    });
    await client.routes.list();
    const apiCall = calls.find((c) => c.url.endsWith('/v1/routes'))!;
    expect(apiCall.headers['x-idempotency-key']).toBeUndefined();
  });

  it('preserves user-provided idempotency key', async () => {
    const { fetchImpl, calls } = makeStub({
      apiResponse: () => ({
        status: 200,
        body: {
          data: { id: 'r_1', name: 'x', slug: null, target_base_url: 'y', enabled: true, created_at: '' },
          meta: { request_id: 'req-1' },
        },
      }),
    });
    const client = new KnoxCall({
      tenant: 'acme',
      baseUrl: 'https://api.example.test',
      bootstrap: { type: 'access_token', accessToken: 'kc_live_x' },
      fetchImpl,
    });
    await client.routes.create({ name: 'x', target_base_url: 'y' }, { idempotencyKey: 'my-key-123' });
    const apiCall = calls.find((c) => c.url.endsWith('/v1/routes'))!;
    expect(apiCall.headers['x-idempotency-key']).toBe('my-key-123');
  });
});

describe('KnoxCall — error mapping + retries', () => {
  it('maps 401 to AuthenticationError', async () => {
    const { fetchImpl } = makeStub({
      apiResponse: () => ({ status: 401, body: { error: 'invalid_token' } }),
    });
    const { AuthenticationError } = await import('../src/index.js');
    const client = new KnoxCall({
      tenant: 'acme',
      baseUrl: 'https://api.example.test',
      bootstrap: { type: 'access_token', accessToken: 'kc_live_x' },
      retry: { maxAttempts: 1, baseDelayMs: 1, maxDelayMs: 1 },
      fetchImpl,
    });
    await expect(client.routes.list()).rejects.toBeInstanceOf(AuthenticationError);
  });

  it('maps 422 to ValidationError with fields', async () => {
    const { fetchImpl } = makeStub({
      apiResponse: () => ({
        status: 422,
        body: { error: 'validation_failed', message: 'bad input', fields: { name: ['required'] } },
      }),
    });
    const { ValidationError } = await import('../src/index.js');
    const client = new KnoxCall({
      tenant: 'acme',
      baseUrl: 'https://api.example.test',
      bootstrap: { type: 'access_token', accessToken: 'kc_live_x' },
      retry: { maxAttempts: 1, baseDelayMs: 1, maxDelayMs: 1 },
      fetchImpl,
    });
    try {
      await client.routes.create({ name: '', target_base_url: '' });
      throw new Error('expected throw');
    } catch (e) {
      expect(e).toBeInstanceOf(ValidationError);
      expect((e as InstanceType<typeof ValidationError>).fields).toEqual({ name: ['required'] });
    }
  });

  it('maps 429 to RateLimitError with retryAfter', async () => {
    const { fetchImpl } = makeStub({
      apiResponse: () => ({
        status: 429,
        body: { error: 'rate_limit_exceeded' },
        headers: { 'retry-after': '60' },
      }),
    });
    const { RateLimitError } = await import('../src/index.js');
    const client = new KnoxCall({
      tenant: 'acme',
      baseUrl: 'https://api.example.test',
      bootstrap: { type: 'access_token', accessToken: 'kc_live_x' },
      retry: { maxAttempts: 1, baseDelayMs: 1, maxDelayMs: 1 },
      fetchImpl,
    });
    try {
      await client.routes.list();
      throw new Error('expected throw');
    } catch (e) {
      expect(e).toBeInstanceOf(RateLimitError);
      expect((e as InstanceType<typeof RateLimitError>).retryAfter).toBe(60);
    }
  });

  it('maps a 503 dependency_unavailable to ServerError — never AuthenticationError — carrying code, request id and Retry-After', async () => {
    const { fetchImpl } = makeStub({
      apiResponse: () => ({
        status: 503,
        body: {
          error: {
            type: 'dependency_unavailable',
            message: 'KnoxCall could not reach its control plane in time. The request was not forwarded; retry after the Retry-After interval.',
            request_id: 'req-dep-1',
            dependency: 'control_plane',
            retry_after: 5,
          },
        },
        headers: { 'retry-after': '5', 'x-request-id': 'req-dep-1' },
      }),
    });
    const { ServerError, AuthenticationError } = await import('../src/index.js');
    const client = new KnoxCall({
      tenant: 'acme',
      baseUrl: 'https://api.example.test',
      bootstrap: { type: 'access_token', accessToken: 'kc_live_x' },
      retry: { maxAttempts: 1, baseDelayMs: 1, maxDelayMs: 1 },
      fetchImpl,
    });
    try {
      await client.routes.list();
      throw new Error('expected throw');
    } catch (e) {
      expect(e).toBeInstanceOf(ServerError);
      expect(e).not.toBeInstanceOf(AuthenticationError);
      const err = e as InstanceType<typeof ServerError>;
      expect(err.status).toBe(503);
      expect(err.code).toBe('dependency_unavailable');
      expect(err.requestId).toBe('req-dep-1');
      expect(err.retryAfter).toBe(5);
    }
  });

  it('a plain 5xx with no Retry-After carries none', async () => {
    const { fetchImpl } = makeStub({
      apiResponse: () => ({ status: 500, body: { error: { type: 'internal_error', message: 'boom', request_id: 'r' } } }),
    });
    const { ServerError } = await import('../src/index.js');
    const client = new KnoxCall({
      tenant: 'acme',
      baseUrl: 'https://api.example.test',
      bootstrap: { type: 'access_token', accessToken: 'kc_live_x' },
      retry: { maxAttempts: 1, baseDelayMs: 1, maxDelayMs: 1 },
      fetchImpl,
    });
    await expect(client.routes.list()).rejects.toSatisfy((e: unknown) =>
      e instanceof ServerError && e.retryAfter === undefined);
  });

  it('honours Retry-After on a 503 before retrying — the wait is the header, not the backoff', async () => {
    let attempts = 0;
    const { fetchImpl } = makeStub({
      apiResponse: () => {
        attempts++;
        if (attempts === 1) {
          return {
            status: 503,
            body: { error: { type: 'dependency_unavailable', message: 'shed', request_id: 'r' } },
            headers: { 'retry-after': '1' },
          };
        }
        return {
          status: 200,
          body: {
            data: [{ id: 'r_1', name: 'ok', slug: null, target_base_url: 'x', enabled: true, created_at: '' }],
            meta: { total: 1, page: 1, per_page: 20, total_pages: 1, request_id: 'req-1' },
          },
        };
      },
    });
    const client = new KnoxCall({
      tenant: 'acme',
      baseUrl: 'https://api.example.test',
      bootstrap: { type: 'access_token', accessToken: 'kc_live_x' },
      retry: { maxAttempts: 2, baseDelayMs: 1, maxDelayMs: 5 },
      fetchImpl,
    });
    const started = Date.now();
    const page = await client.routes.list();
    const elapsed = Date.now() - started;
    expect(attempts).toBe(2);
    expect(page.data[0].id).toBe('r_1');
    // The backoff alone would have waited at most maxDelayMs (5 ms); a wait of
    // at least ~1 s is the header. A LOWER bound, so a loaded box cannot fail it.
    expect(elapsed).toBeGreaterThanOrEqual(900);
  });

  it('retries on 5xx with exponential backoff', async () => {
    let attempts = 0;
    const { fetchImpl, calls } = makeStub({
      apiResponse: () => {
        attempts++;
        if (attempts < 3) return { status: 503, body: { error: 'unavailable' } };
        return {
          status: 200,
          body: {
            data: [{ id: 'r_1', name: 'ok', slug: null, target_base_url: 'x', enabled: true, created_at: '' }],
            meta: { total: 1, page: 1, per_page: 20, total_pages: 1, request_id: 'req-1' },
          },
        };
      },
    });
    const client = new KnoxCall({
      tenant: 'acme',
      baseUrl: 'https://api.example.test',
      bootstrap: { type: 'access_token', accessToken: 'kc_live_x' },
      retry: { maxAttempts: 3, baseDelayMs: 1, maxDelayMs: 5 },
      fetchImpl,
    });
    const res = await client.routes.list();
    expect(res.data[0].name).toBe('ok');
    const apiCalls = calls.filter((c) => c.url.endsWith('/v1/routes'));
    expect(apiCalls.length).toBe(3);
  });

  it('does NOT retry on 4xx other than 408/409/429', async () => {
    const { fetchImpl, calls } = makeStub({
      apiResponse: () => ({ status: 400, body: { error: 'invalid_request' } }),
    });
    const client = new KnoxCall({
      tenant: 'acme',
      baseUrl: 'https://api.example.test',
      bootstrap: { type: 'access_token', accessToken: 'kc_live_x' },
      retry: { maxAttempts: 5, baseDelayMs: 1, maxDelayMs: 5 },
      fetchImpl,
    });
    await expect(client.routes.list()).rejects.toThrow();
    const apiCalls = calls.filter((c) => c.url.endsWith('/v1/routes'));
    expect(apiCalls.length).toBe(1);
  });
});

describe('KnoxCall — Redacted secrets', () => {
  it('never logs the access token via JSON.stringify', async () => {
    const { fetchImpl } = makeStub({});
    const client = new KnoxCall({
      tenant: 'acme',
      baseUrl: 'https://api.example.test',
      bootstrap: { type: 'client_credentials', clientId: 'tk_x', clientSecret: 'sec' },
      fetchImpl,
    });
    await client.routes.list();
    // The token store is internal; we just confirm Redacted's behaviour
    const store = new MemoryTokenStore();
    const { redact } = await import('../src/redacted.js');
    await store.set('k', {
      accessToken: redact('kc_live_supersecret'),
      expiresAt: Date.now() + 60000,
      scope: [],
      tokenType: 'Bearer',
    });
    const cached = await store.get('k');
    expect(JSON.stringify(cached)).not.toContain('kc_live_supersecret');
    expect(JSON.stringify(cached)).toContain('REDACTED');
  });
});
