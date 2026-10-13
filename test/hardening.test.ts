// Hardened request-pipeline tests — mirrors knoxcall-python/tests/test_hardening.py.
// Covers: call() 401 purge+re-mint, transport-failure retry policy (never
// replay mutations), explicit-arg precedence, body encoding, token lifecycle
// (short TTLs, stale fallback, robust parsing), DPoP auto-upgrade,
// Retry-After capping, renames + deprecated aliases, secret hygiene.

import { describe, it, expect, vi } from 'vitest';
import { inspect } from 'util';
import {
  KnoxCall,
  MemoryTokenStore,
  APIConnectionError,
  APIConnectionTimeoutError,
  ConflictError,
  PaymentRequiredError,
  PermissionDeniedError,
  PermissionError,
  AccessToken,
  ClientCredentials,
  OidcTokenExchange,
  AccessTokenBootstrap,
  ClientCredentialsBootstrap,
  OidcTokenExchangeBootstrap,
  type KnoxCallOptions,
} from '../src/index.js';
import { errorFromResponse } from '../src/error.js';
import { redact } from '../src/redacted.js';

interface SeenRequest {
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: BodyInit | null;
  signal?: AbortSignal;
}

function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });
}

function tokenResponse(token = 'kc_live_aaaa', expiresIn: number | string = 3600): Response {
  return json(200, { access_token: token, token_type: 'Bearer', expires_in: expiresIn });
}

/** Shape transport errors the way undici does: cause chain carrying a code. */
function transportError(code: string): Error {
  return Object.assign(new TypeError('fetch failed'), {
    cause: Object.assign(new Error(code), { code }),
  });
}

function makeClient(
  handler: (req: SeenRequest) => Response | Promise<Response>,
  extra?: Partial<KnoxCallOptions>,
): KnoxCall {
  const fetchImpl: typeof fetch = async (input, init) => {
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
      body: init?.body,
      signal: init?.signal ?? undefined,
    });
  };
  return new KnoxCall({
    tenant: 'acme',
    baseUrl: 'https://api.example.test',
    proxyBaseUrl: 'https://acme.example.test',
    bootstrap: new ClientCredentials({ clientId: 'tk_x', clientSecret: 'sec' }),
    retry: { maxAttempts: 3, baseDelayMs: 1, maxDelayMs: 5 },
    fetchImpl,
    ...extra,
  });
}

// ── call() hardening ──────────────────────────────────────────────────────────

describe('call() — 401 purge + re-mint', () => {
  it('purges the cached token and retries once on 401', async () => {
    const minted: string[] = [];
    const seq = ['kc_live_revoked', 'kc_live_fresh'];
    const client = makeClient((req) => {
      if (req.url.endsWith('/oauth/token')) {
        const token = seq.shift()!;
        minted.push(token);
        return tokenResponse(token);
      }
      if (req.headers['authorization'] === 'Bearer kc_live_revoked') {
        return json(401, { error: 'Unauthorized' });
      }
      return json(200, { ok: true });
    });
    const res = await client.call('r_1', { path: '/x' });
    expect(res.status).toBe(200);
    expect(minted).toEqual(['kc_live_revoked', 'kc_live_fresh']);
  });

  it('returns the second 401 as-is instead of looping', async () => {
    let tokenCalls = 0;
    const client = makeClient((req) => {
      if (req.url.endsWith('/oauth/token')) {
        tokenCalls++;
        return tokenResponse('kc_live_bad');
      }
      return json(401, { error: 'Unauthorized' });
    });
    const res = await client.call('r_1', { path: '/x' });
    expect(res.status).toBe(401);
    expect(tokenCalls).toBe(2); // original + the single re-auth, no infinite loop
  });
});

describe('call() — transport-failure retry policy', () => {
  it('retries an idle disconnect for GET only — mutations are never replayed', async () => {
    const state = { getFails: 1, postAttempts: 0 };
    const client = makeClient((req) => {
      if (req.url.endsWith('/oauth/token')) return tokenResponse();
      if (req.method === 'GET') {
        if (state.getFails) {
          state.getFails--;
          throw transportError('ECONNRESET');
        }
        return json(200, { ok: true });
      }
      state.postAttempts++;
      throw transportError('ECONNRESET');
    });
    const res = await client.call('r_1', { path: '/x' });
    expect(res.status).toBe(200); // GET retried transparently
    await expect(client.call('r_1', { method: 'POST', path: '/x', body: { a: 1 } })).rejects.toBeInstanceOf(
      APIConnectionError,
    );
    expect(state.postAttempts).toBe(1); // mutating request NOT replayed
  });

  it('retries a connection-refused even for POST (request never left the machine)', async () => {
    const state = { fails: 1, attempts: 0 };
    const client = makeClient((req) => {
      if (req.url.endsWith('/oauth/token')) return tokenResponse();
      state.attempts++;
      if (state.fails) {
        state.fails--;
        throw transportError('ECONNREFUSED');
      }
      return json(200, { ok: true });
    });
    const res = await client.call('r_1', { method: 'POST', path: '/x', body: { a: 1 } });
    expect(res.status).toBe(200);
    expect(state.attempts).toBe(2);
  });

  it('honors a per-call timeout override', async () => {
    const client = makeClient((req) => {
      if (req.url.endsWith('/oauth/token')) return tokenResponse();
      return new Promise((_, reject) => {
        req.signal?.addEventListener('abort', () =>
          reject(Object.assign(new Error('aborted'), { name: 'AbortError' })),
        );
      });
    });
    // POST so the timeout is not retried; the 30ms override (vs the 30s
    // default) is what keeps this test fast.
    await expect(client.call('r_1', { method: 'POST', path: '/x', timeout: 30 })).rejects.toBeInstanceOf(
      APIConnectionTimeoutError,
    );
  });
});

describe('call() — explicit arguments beat the headers dict', () => {
  it('sends route, environment, and query; caller headers cannot spoof them', async () => {
    const seen: { headers?: Record<string, string>; url?: string } = {};
    const client = makeClient((req) => {
      if (req.url.endsWith('/oauth/token')) return tokenResponse();
      seen.headers = req.headers;
      seen.url = req.url;
      return json(200, { ok: true });
    });
    await client.call('r_1', {
      path: '/x',
      environment: 'production',
      query: { page: 2 },
      headers: { 'x-knoxcall-route': 'spoofed', 'X-Custom': '1' },
    });
    expect(seen.headers!['x-knoxcall-route']).toBe('r_1');
    expect(seen.headers!['x-knoxcall-environment']).toBe('production');
    expect(seen.headers!['x-custom']).toBe('1');
    expect(seen.url).toContain('page=2');
  });

  it('strips caller-supplied proxy-auth headers so SDK auth always wins', async () => {
    const seen: { headers?: Record<string, string> } = {};
    const client = makeClient((req) => {
      if (req.url.endsWith('/oauth/token')) return tokenResponse('kc_live_sdk');
      seen.headers = req.headers;
      return json(200, { ok: true });
    });
    await client.call('r_1', {
      path: '/x',
      headers: {
        // An integrator forwarding untrusted end-user headers must not be able
        // to inject an alternate proxy identity or override the SDK credential.
        'x-knoxcall-agent-id': 'attacker-agent',
        'X-Knoxcall-Agent-Token': 'attacker-token',
        Authorization: 'Bearer kc_live_attacker',
        DPoP: 'forged-proof',
        'x-knoxcall-key': 'tk_attacker',
        // The interceptors' reroute marker (PARITY §21.2) is SDK-owned too: an
        // app must not be able to relabel its own direct calls as intercepted.
        'X-KnoxCall-Origin': 'sdk-intercept',
        'X-Custom': 'ok',
      },
    });
    // The SDK's own credential is the only auth on the wire...
    expect(seen.headers!['authorization']).toBe('Bearer kc_live_sdk');
    // ...and none of the caller's proxy-auth headers survive.
    expect(seen.headers!['x-knoxcall-agent-id']).toBeUndefined();
    expect(seen.headers!['x-knoxcall-agent-token']).toBeUndefined();
    expect(seen.headers!['x-knoxcall-key']).toBeUndefined();
    expect(seen.headers!['dpop']).toBeUndefined();
    expect(seen.headers!['x-knoxcall-origin']).toBeUndefined();
    // Non-auth caller headers still pass through.
    expect(seen.headers!['x-custom']).toBe('ok');
  });

  it('a direct call() carries no x-knoxcall-origin — absence is "direct" on the server (PARITY §21.2)', async () => {
    const seen: { headers?: Record<string, string> } = {};
    const client = makeClient((req) => {
      if (req.url.endsWith('/oauth/token')) return tokenResponse('kc_live_sdk');
      seen.headers = req.headers;
      return json(200, { ok: true });
    });
    await client.call('r_1', { path: '/x' });
    expect(seen.headers!['x-knoxcall-route']).toBe('r_1');
    expect(seen.headers!['x-knoxcall-origin']).toBeUndefined();

    seen.headers = undefined;
    await client.route('r_1').get('/x');
    expect(seen.headers!['x-knoxcall-origin']).toBeUndefined();
  });
});

// ── Body encoding ─────────────────────────────────────────────────────────────

describe('call() — body encoding', () => {
  it('encodes Date via toJSON and applies the jsonReplacer hook', async () => {
    const seen: { body?: string; contentType?: string } = {};
    const client = makeClient(
      (req) => {
        if (req.url.endsWith('/oauth/token')) return tokenResponse();
        seen.body = req.body as string;
        seen.contentType = req.headers['content-type'];
        return json(200, {});
      },
      {
        jsonReplacer: (_k, v) =>
          v instanceof Set ? [...v] : typeof v === 'bigint' ? v.toString() : v,
      },
    );
    await client.call('r_1', {
      method: 'POST',
      path: '/x',
      body: {
        when: new Date('2026-06-10T12:30:00.000Z'),
        tags: new Set(['b', 'b']),
        big: 10n,
      },
    });
    expect(seen.contentType).toBe('application/json');
    const parsed = JSON.parse(seen.body!);
    expect(parsed.when).toBe('2026-06-10T12:30:00.000Z');
    expect(parsed.tags).toEqual(['b']);
    expect(parsed.big).toBe('10');
  });

  it('passes string and Buffer bodies through untouched, honoring caller Content-Type', async () => {
    const seen: { body?: BodyInit | null; contentType?: string } = {};
    const client = makeClient((req) => {
      if (req.url.endsWith('/oauth/token')) return tokenResponse();
      seen.body = req.body;
      seen.contentType = req.headers['content-type'];
      return json(200, {});
    });
    await client.call('r_1', {
      method: 'POST',
      path: '/x',
      body: Buffer.from('%PDF-1.4 raw'),
      headers: { 'Content-Type': 'application/pdf' },
    });
    expect(Buffer.from(seen.body as Uint8Array).toString('utf8')).toBe('%PDF-1.4 raw');
    expect(seen.contentType).toBe('application/pdf');
  });
});

// ── Token lifecycle ───────────────────────────────────────────────────────────

describe('token lifecycle', () => {
  it('does not refetch short-lived tokens every request (refresh-ahead = lifetime/2)', async () => {
    let tokenCalls = 0;
    const client = makeClient((req) => {
      if (req.url.endsWith('/oauth/token')) {
        tokenCalls++;
        return tokenResponse('kc_live_aaaa', 60); // shorter than the 5-min window
      }
      return json(200, { ok: true });
    });
    for (let i = 0; i < 5; i++) {
      await client.call('r_1', { path: '/x' });
    }
    expect(tokenCalls).toBe(1);
  });

  it('tolerates a string expires_in', async () => {
    let tokenCalls = 0;
    const client = makeClient((req) => {
      if (req.url.endsWith('/oauth/token')) {
        tokenCalls++;
        return tokenResponse('kc_live_aaaa', '60');
      }
      return json(200, { ok: true });
    });
    for (let i = 0; i < 5; i++) {
      await client.call('r_1', { path: '/x' });
    }
    expect(tokenCalls).toBe(1);
  });

  it('falls back to a stale-but-valid token when the token endpoint is down', async () => {
    const store = new MemoryTokenStore();
    // Inside the 5-minute refresh-ahead window, but still genuinely valid.
    await store.set('acme:', {
      accessToken: redact('kc_live_stale'),
      expiresAt: Date.now() + 60_000,
      lifetime: 3_600_000,
      scope: [],
      tokenType: 'Bearer',
    });
    const client = makeClient(
      (req) => {
        if (req.url.endsWith('/oauth/token')) return json(503, { error: 'unavailable' });
        return json(200, { auth: req.headers['authorization'] });
      },
      { tokenStore: store },
    );
    const res = await client.call('r_1', { path: '/x' });
    expect(((await res.json()) as { auth: string }).auth).toBe('Bearer kc_live_stale');
  });

  it('raises a typed error on a non-JSON 200 token response (edge-proxy HTML)', async () => {
    const client = makeClient((req) => {
      if (req.url.endsWith('/oauth/token')) {
        return new Response('<html>edge proxy</html>', {
          status: 200,
          headers: { 'Content-Type': 'text/html' },
        });
      }
      return json(200, {});
    });
    await expect(client.call('r_1', { path: '/x' })).rejects.toThrow(/unexpected response/);
  });
});

// ── DPoP auto mode ────────────────────────────────────────────────────────────

describe('DPoP', () => {
  it('auto-upgrades to DPoP when the client record requires it', async () => {
    const client = makeClient((req) => {
      if (req.url.endsWith('/oauth/token')) {
        if (!req.headers['dpop']) {
          return json(400, {
            error: 'invalid_dpop_proof',
            error_description: 'this client requires a DPoP proof on token requests',
          });
        }
        return json(200, { access_token: 'kc_live_dpop', token_type: 'DPoP', expires_in: 3600 });
      }
      return json(200, {
        auth: req.headers['authorization'],
        hasProof: 'dpop' in req.headers,
      });
    }); // dpop: "auto" (default)
    const res = await client.call('r_1', { path: '/x' });
    const body = (await res.json()) as { auth: string; hasProof: boolean };
    expect(body.auth).toMatch(/^DPoP kc_live_dpop/);
    expect(body.hasProof).toBe(true);
  });

  it('errors clearly when the server issues a DPoP token but no keypair is held', async () => {
    const client = makeClient(
      (req) => {
        if (req.url.endsWith('/oauth/token')) {
          return json(200, { access_token: 'kc_live_x', token_type: 'DPoP', expires_in: 3600 });
        }
        return json(200, {});
      },
      { dpop: 'never' },
    );
    await expect(client.call('r_1', { path: '/x' })).rejects.toThrow(/DPoP-bound token/);
  });

  it('rejects unknown dpop modes at construction', () => {
    expect(
      () =>
        new KnoxCall({
          tenant: 'acme',
          bootstrap: new ClientCredentials({ clientId: 'tk_x', clientSecret: 'sec' }),
          dpop: 'sometimes' as never,
        }),
    ).toThrow(/dpop/);
  });
});

// ── request() re-auth + retry policy ──────────────────────────────────────────

describe('request() — re-auth and retry policy', () => {
  it('transparently re-auths once on 401', async () => {
    const emptyPage = { data: [], meta: { total: 0, page: 1, per_page: 20, total_pages: 1, request_id: 'req-1' } };
    const seq = ['kc_live_old', 'kc_live_new'];
    const client = makeClient((req) => {
      if (req.url.endsWith('/oauth/token')) return tokenResponse(seq.shift()!);
      if (req.headers['authorization'] === 'Bearer kc_live_old') {
        return json(401, { error: 'Unauthorized' });
      }
      return json(200, emptyPage);
    });
    await expect(client.routes.list()).resolves.toEqual(emptyPage);
  });

  it('does NOT retry 409 — a real conflict does not resolve by replaying', async () => {
    let apiCalls = 0;
    const client = makeClient(
      (req) => {
        if (req.url.endsWith('/oauth/token')) return tokenResponse();
        apiCalls++;
        return json(409, { error: 'conflict' });
      },
      { retry: { maxAttempts: 5, baseDelayMs: 1, maxDelayMs: 5 } },
    );
    await expect(client.routes.create({ name: 'x', target_base_url: 'y' })).rejects.toBeInstanceOf(ConflictError);
    expect(apiCalls).toBe(1);
  });

  it('honors Retry-After on 429, capped at 30s', async () => {
    vi.useFakeTimers();
    try {
      const emptyPage = { data: [], meta: { total: 0, page: 1, per_page: 20, total_pages: 1, request_id: 'req-1' } };
      let apiCalls = 0;
      const client = makeClient((req) => {
        if (req.url.endsWith('/oauth/token')) return tokenResponse();
        apiCalls++;
        if (apiCalls === 1) return json(429, { error: 'rate_limited' }, { 'retry-after': '600' });
        return json(200, emptyPage);
      });
      let resolved = false;
      const p = client.routes.list().then((r) => {
        resolved = true;
        return r;
      });
      await vi.advanceTimersByTimeAsync(29_999);
      expect(resolved).toBe(false); // 600s clamped to 30s, never less
      await vi.advanceTimersByTimeAsync(1);
      await expect(p).resolves.toEqual(emptyPage);
    } finally {
      vi.useRealTimers();
    }
  });

  it('uses the server Retry-After when below the cap', async () => {
    vi.useFakeTimers();
    try {
      const emptyPage = { data: [], meta: { total: 0, page: 1, per_page: 20, total_pages: 1, request_id: 'req-1' } };
      let apiCalls = 0;
      const client = makeClient((req) => {
        if (req.url.endsWith('/oauth/token')) return tokenResponse();
        apiCalls++;
        if (apiCalls === 1) return json(429, { error: 'rate_limited' }, { 'retry-after': '2' });
        return json(200, emptyPage);
      });
      let resolved = false;
      const p = client.routes.list().then((r) => {
        resolved = true;
        return r;
      });
      await vi.advanceTimersByTimeAsync(1_999);
      expect(resolved).toBe(false);
      await vi.advanceTimersByTimeAsync(1);
      await expect(p).resolves.toEqual(emptyPage);
    } finally {
      vi.useRealTimers();
    }
  });
});

// ── Secret hygiene + naming ───────────────────────────────────────────────────

describe('secret hygiene + naming', () => {
  it('bootstrap inspect/JSON output never leaks secrets', () => {
    const cc = new ClientCredentials({ clientId: 'tk_x', clientSecret: 'hunter2' });
    expect(inspect(cc)).not.toContain('hunter2');
    expect(inspect(cc)).toContain('tk_x'); // client_id is not sensitive
    expect(JSON.stringify(cc)).not.toContain('hunter2');

    const oidc = new OidcTokenExchange({ subjectToken: 'jwt-marker', issuer: 'https://oidc.vercel.com' });
    expect(inspect(oidc)).not.toContain('jwt-marker');
    expect(inspect(oidc)).toContain('https://oidc.vercel.com');
    expect(JSON.stringify(oidc)).not.toContain('jwt-marker');

    const at = new AccessToken({ accessToken: 'kc_live_marker' });
    expect(inspect(at)).not.toContain('kc_live_marker');
    expect(JSON.stringify(at)).not.toContain('kc_live_marker');
  });

  it('keeps deprecated *Bootstrap aliases and defaults the type discriminator', () => {
    expect(ClientCredentialsBootstrap).toBe(ClientCredentials);
    expect(AccessTokenBootstrap).toBe(AccessToken);
    expect(OidcTokenExchangeBootstrap).toBe(OidcTokenExchange);
    const cc = new ClientCredentialsBootstrap({ clientId: 'tk_x', clientSecret: 'sec' });
    expect(cc.type).toBe('client_credentials');
    expect(new AccessToken({ accessToken: 'kc_live_x' }).type).toBe('access_token');
    expect(new OidcTokenExchange({ subjectToken: 'jwt', issuer: 'https://x' }).type).toBe('oidc_token_exchange');
  });

  it('maps 403 to PermissionDeniedError and keeps the deprecated alias', () => {
    const err = errorFromResponse(403, { error: 'forbidden' }, {});
    expect(err).toBeInstanceOf(PermissionDeniedError);
    expect(err.name).toBe('PermissionDeniedError');
    expect(PermissionError).toBe(PermissionDeniedError);
  });

  // A plan/billing limit (type plan_limit) is 402, distinct from a 403 access
  // denial, so callers can show an "upgrade" prompt.
  it('maps 402 plan_limit to PaymentRequiredError', () => {
    const err = errorFromResponse(
      402,
      { error: { type: 'plan_limit', message: 'Vault limit reached. Upgrade your plan.', request_id: 'req-2' } },
      {},
    );
    expect(err).toBeInstanceOf(PaymentRequiredError);
    expect(err.code).toBe('plan_limit');
    expect(err.message).toMatch(/Upgrade/);
    expect(err).not.toBeInstanceOf(PermissionDeniedError);
  });

  // AIGW-52 added a SECOND 402 type: `plan_feature` (the capability is not on
  // the tier) beside `plan_limit` (a counted quota is exhausted). The mapper
  // keys on STATUS, which is exactly why no SDK needed a code change — this
  // asserts that property rather than assuming it.
  it('maps 402 plan_feature to PaymentRequiredError too, preserving the type', () => {
    const err = errorFromResponse(
      402,
      { error: { type: 'plan_feature', message: 'Your free plan does not include compliance packs.', request_id: 'req-3' } },
      {},
    );
    expect(err).toBeInstanceOf(PaymentRequiredError);
    expect(err.code).toBe('plan_feature');
    expect(err).not.toBeInstanceOf(PermissionDeniedError);
  });

  // Audit finding H1: the canonical /v1 error is `{error:{type,message,request_id}}`
  // — the `error` value is an OBJECT. The old mapper coerced it to "[object Object]"
  // and set `code` to the object; these guard the fix.
  it('parses the canonical Shape-A nested error object (no more "[object Object]")', () => {
    const err = errorFromResponse(
      403,
      { error: { type: 'wrong_key_type', message: 'This key type cannot be used here.', request_id: 'req-9' } },
      {},
    );
    expect(err).toBeInstanceOf(PermissionDeniedError);
    expect(err.message).toBe('This key type cannot be used here.');
    expect(err.message).not.toContain('[object');
    expect(err.code).toBe('wrong_key_type');
    expect(err.requestId).toBe('req-9'); // from the body when no header present
  });

  it('prefers the X-Request-Id header for the correlation id when present', () => {
    const err = errorFromResponse(
      404,
      { error: { type: 'not_found', message: 'nope', request_id: 'body-id' } },
      { 'x-request-id': 'header-id' },
    );
    expect(err.requestId).toBe('header-id');
  });

  it('surfaces the human message over the code for the flat Shape-C body', () => {
    const err = errorFromResponse(
      409,
      { error: 'request_in_progress', message: 'A request with this idempotency key is still being processed.' },
      {},
    );
    expect(err.message).toBe('A request with this idempotency key is still being processed.');
    expect(err.code).toBe('request_in_progress');
  });
});
