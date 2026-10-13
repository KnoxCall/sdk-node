// Wrap transport tests (sdk-wrapping PR4). Asserts the wrapped-SDK transport
// re-targets to /v1/proxy in transparent mode, lifts the provider credential
// out-of-band, preserves the request bytes, enforces both-must-agree, and routes
// raw-card / opted-in requests directly to the provider.
//
// Capture is at the SDK's HTTP boundary (the injected fetchImpl), never by
// mocking the wrapper — the same discipline the server tests use.

import { describe, it, expect, vi } from 'vitest';
import { KnoxCall, WrapSandboxMismatchError } from '../src/index.js';

interface Seen {
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: string;
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

/** A fetchImpl that records the KnoxCall-bound request and 200s. */
function makeClient(seen: Seen[], sandbox = false) {
  const fetchImpl: typeof fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input as Request).url;
    const headers: Record<string, string> = {};
    if (init?.headers) for (const [k, v] of Object.entries(init.headers as Record<string, string>)) headers[k.toLowerCase()] = v;
    seen.push({ url, method: init?.method ?? 'GET', headers, body: typeof init?.body === 'string' ? init.body : undefined });
    return json(200, { ok: true });
  };
  return new KnoxCall({
    tenant: 'acme', baseUrl: 'https://api.test', proxyBaseUrl: 'https://acme.test',
    apiKey: 'kc_live_x', sandbox, fetchImpl,
  });
}

const STRIPE_FORM = 'amount=2000&currency=usd&source=tok_visa';

describe('wrap.fetch — transit mode (lift the SDK Authorization)', () => {
  it('re-targets to /v1/proxy in transparent mode, lifts Authorization, preserves the body', async () => {
    const seen: Seen[] = [];
    const wrapped = makeClient(seen).wrap.fetch();
    await wrapped('https://api.stripe.com/v1/charges', {
      method: 'POST',
      headers: { authorization: 'Bearer sk_live_provider', 'content-type': 'application/x-www-form-urlencoded', 'idempotency-key': 'idem-1' },
      body: STRIPE_FORM,
    });
    expect(seen.length).toBe(1);
    const r = seen[0];
    // Goes to KnoxCall's proxy, not Stripe.
    expect(r.url).toBe('https://api.test/v1/proxy');
    expect(r.headers['x-knox-proxy-url']).toBe('https://api.stripe.com/v1/charges');
    expect(r.headers['x-knox-proxy-mode']).toBe('transparent');
    // Provider credential lifted out-of-band; NOT forwarded raw.
    expect(r.headers['x-knox-upstream-authorization']).toBe('Bearer sk_live_provider');
    // KnoxCall's own credential authenticates the proxy call.
    expect(r.headers['authorization']).toBe('Bearer kc_live_x');
    // SDK headers preserved; body byte-identical.
    expect(r.headers['idempotency-key']).toBe('idem-1');
    expect(r.body).toBe(STRIPE_FORM);
  });

  it('enforces both-must-agree: a test key on a live client throws', async () => {
    const wrapped = makeClient([], false).wrap.fetch();
    await expect(wrapped('https://api.stripe.com/v1/charges', {
      method: 'POST', headers: { authorization: 'Bearer sk_test_x' }, body: '',
    })).rejects.toBeInstanceOf(WrapSandboxMismatchError);
  });

  it('enforces both-must-agree: a live key on a sandbox client throws', async () => {
    const wrapped = makeClient([], true).wrap.fetch();
    await expect(wrapped('https://api.stripe.com/v1/charges', {
      method: 'POST', headers: { authorization: 'Bearer sk_live_x' }, body: '',
    })).rejects.toBeInstanceOf(WrapSandboxMismatchError);
  });

  it('accepts a restricted key (rk_) matching the sandbox flag', async () => {
    const seen: Seen[] = [];
    const wrapped = makeClient(seen, false).wrap.fetch();
    await wrapped('https://api.stripe.com/v1/charges', {
      method: 'POST', headers: { authorization: 'Bearer rk_live_restricted' }, body: '',
    });
    expect(seen[0].headers['x-knox-upstream-authorization']).toBe('Bearer rk_live_restricted');
  });

  it('rejects a publishable key (pk_) outright', async () => {
    const wrapped = makeClient([], false).wrap.fetch();
    await expect(wrapped('https://api.stripe.com/v1/charges', {
      method: 'POST', headers: { authorization: 'Bearer pk_live_x' }, body: '',
    })).rejects.toBeInstanceOf(WrapSandboxMismatchError);
  });
});

describe('wrap.fetch — escrow mode', () => {
  it('sends X-Knox-Upstream-Auth-Secret and never a raw key', async () => {
    const seen: Seen[] = [];
    const wrapped = makeClient(seen).wrap.fetch({ credential: { secret: 'wrap-stripe-live' } });
    await wrapped('https://api.stripe.com/v1/charges', {
      method: 'POST',
      headers: { authorization: 'Bearer sk_managed_by_knoxcall', 'content-type': 'application/x-www-form-urlencoded' },
      body: STRIPE_FORM,
    });
    const r = seen[0];
    expect(r.headers['x-knox-upstream-auth-secret']).toBe('wrap-stripe-live');
    // The placeholder key the SDK set is NOT forwarded out-of-band.
    expect(r.headers['x-knox-upstream-authorization']).toBeUndefined();
    // No both-must-agree check in escrow mode (placeholder key ignored).
    expect(r.body).toBe(STRIPE_FORM);
  });

  it('passes a custom scheme through', async () => {
    const seen: Seen[] = [];
    const wrapped = makeClient(seen).wrap.fetch({ credential: { secret: 'wrap-x', scheme: 'none' } });
    await wrapped('https://api.example.com/x', { method: 'POST', body: '' });
    expect(seen[0].headers['x-knox-upstream-auth-scheme']).toBe('none');
  });
});

describe('wrap.fetch — client-side route-around', () => {
  it('sends a raw-card endpoint DIRECTLY to the provider, not through KnoxCall', async () => {
    const seen: Seen[] = [];
    const direct = vi.fn(async () => json(200, { id: 'tok_1' }));
    const onRouteAround = vi.fn();
    const wrapped = makeClient(seen).wrap.fetch({ directFetch: direct as unknown as typeof fetch, onRouteAround });
    await wrapped('https://api.stripe.com/v1/tokens', {
      method: 'POST', headers: { authorization: 'Bearer sk_live_x' }, body: 'card[number]=4242424242424242',
    });
    // Went direct — KnoxCall's fetchImpl was never touched.
    expect(seen.length).toBe(0);
    expect(direct).toHaveBeenCalledTimes(1);
    expect(onRouteAround).toHaveBeenCalledWith(expect.objectContaining({ host: 'api.stripe.com' }));
  });

  it('does NOT route around a normal endpoint', async () => {
    const seen: Seen[] = [];
    const direct = vi.fn(async () => json(200, {}));
    const wrapped = makeClient(seen).wrap.fetch({ directFetch: direct as unknown as typeof fetch });
    await wrapped('https://api.stripe.com/v1/charges', {
      method: 'POST', headers: { authorization: 'Bearer sk_live_x' }, body: STRIPE_FORM,
    });
    expect(direct).not.toHaveBeenCalled();
    expect(seen.length).toBe(1);
    expect(seen[0].url).toBe('https://api.test/v1/proxy');
  });

  it('honours a caller-supplied extra route-around rule', async () => {
    const seen: Seen[] = [];
    const direct = vi.fn(async () => json(200, {}));
    const wrapped = makeClient(seen).wrap.fetch({
      directFetch: direct as unknown as typeof fetch,
      routeAround: [{ host: 'files.stripe.com', reason: 'multipart upload' }],
    });
    await wrapped('https://files.stripe.com/v1/files', { method: 'POST', headers: { authorization: 'Bearer sk_live_x' }, body: 'x' });
    expect(direct).toHaveBeenCalledTimes(1);
    expect(seen.length).toBe(0);
  });
});

// ─── Regression tests for the PR4 adversarial-review findings ──────────────

describe('wrap.fetch — review-hardening regressions', () => {
  it('both-must-agree is not bypassed by a leading space before Bearer (#1)', async () => {
    const wrapped = makeClient([], true).wrap.fetch();
    await expect(wrapped('https://api.stripe.com/v1/charges', {
      method: 'POST', headers: { authorization: ' Bearer sk_live_x' }, body: '',
    })).rejects.toBeInstanceOf(WrapSandboxMismatchError);
  });

  it('a trailing-dot host still routes around (#2)', async () => {
    const seen: Seen[] = [];
    const direct = vi.fn(async () => json(200, {}));
    const wrapped = makeClient(seen).wrap.fetch({ directFetch: direct as unknown as typeof fetch });
    await wrapped('https://api.stripe.com./v1/tokens', {
      method: 'POST', headers: { authorization: 'Bearer sk_live_x' }, body: 'card[number]=4242',
    });
    expect(direct).toHaveBeenCalledTimes(1);   // routed around despite the trailing dot
    expect(seen.length).toBe(0);
  });

  it('preserves the caller AbortSignal (#3)', async () => {
    const seen: Array<{ signal?: AbortSignal }> = [];
    const fetchImpl: typeof fetch = async (_input, init) => {
      seen.push({ signal: init?.signal ?? undefined });
      return json(200, { ok: true });
    };
    const client = new KnoxCall({ tenant: 'acme', baseUrl: 'https://api.test', proxyBaseUrl: 'https://acme.test', apiKey: 'kc_live_x', sandbox: false, fetchImpl });
    const ac = new AbortController();
    await client.wrap.fetch()('https://api.stripe.com/v1/charges', {
      method: 'POST', headers: { authorization: 'Bearer sk_live_x' }, body: '', signal: ac.signal,
    });
    // The proxy fetch received a signal (composed with the client timeout signal).
    expect(seen[0].signal).toBeInstanceOf(AbortSignal);
  });

  it('recovers a Request-object body instead of forwarding empty (#4/#8)', async () => {
    // fetchImpl that decodes the raw body regardless of type (string/bytes).
    const bodies: string[] = [];
    const fetchImpl: typeof fetch = async (_input, init) => {
      const b = init?.body;
      if (typeof b === 'string') bodies.push(b);
      else if (b instanceof Uint8Array) bodies.push(Buffer.from(b).toString('utf8'));
      else if (b instanceof ArrayBuffer) bodies.push(Buffer.from(new Uint8Array(b)).toString('utf8'));
      else bodies.push(`<${typeof b}>`);
      return json(200, { ok: true });
    };
    const client = new KnoxCall({ tenant: 'acme', baseUrl: 'https://api.test', proxyBaseUrl: 'https://acme.test', apiKey: 'kc_live_x', sandbox: false, fetchImpl });
    const reqObj = new Request('https://api.stripe.com/v1/charges', {
      method: 'POST', headers: { authorization: 'Bearer sk_live_x', 'content-type': 'application/x-www-form-urlencoded' }, body: STRIPE_FORM,
    });
    await client.wrap.fetch()(reqObj);
    expect(bodies[0]).toBe(STRIPE_FORM);   // bytes recovered, not an empty body
  });

  it('does NOT synthesize application/json in transparent mode when the SDK sent no Content-Type (#5)', async () => {
    const seen: Seen[] = [];
    const wrapped = makeClient(seen).wrap.fetch();
    await wrapped('https://api.example.com/x', {
      method: 'POST', headers: { authorization: 'Bearer other_scheme_key' }, body: 'raw-bytes',
    });
    // No content-type was set by the caller; the wrapper must not invent one.
    expect(seen[0].headers['content-type']).toBeUndefined();
  });

  it('throws on a malformed escrow credential rather than falling through to transit (#7)', () => {
    const knox = makeClient([]);
    expect(() => knox.wrap.fetch({ credential: {} as any })).toThrow(TypeError);
    expect(() => knox.wrap.fetch({ credential: { secret: '' } })).toThrow(TypeError);
  });

  it('throws on a non-bare routeAround host rather than silently never matching (#10)', () => {
    const knox = makeClient([]);
    expect(() => knox.wrap.fetch({ routeAround: [{ host: 'https://api.stripe.com', reason: 'x' }] }))
      .toThrow(WrapSandboxMismatchError);
  });
});

// ─── PR6: route mode + promoted-route switch hint ──────────────────────────

/** fetchImpl that optionally stamps X-Knox-Promoted-Route on the response. */
function makeClientWithHint(seen: Seen[], hintSlug?: string) {
  const fetchImpl: typeof fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input as Request).url;
    const headers: Record<string, string> = {};
    if (init?.headers) for (const [k, v] of Object.entries(init.headers as Record<string, string>)) headers[k.toLowerCase()] = v;
    seen.push({ url, method: init?.method ?? 'GET', headers, body: typeof init?.body === 'string' ? init.body : undefined });
    const respHeaders: Record<string, string> = { 'Content-Type': 'application/json' };
    if (hintSlug) respHeaders['X-Knox-Promoted-Route'] = hintSlug;
    return new Response(JSON.stringify({ ok: true }), { status: 200, headers: respHeaders });
  };
  return new KnoxCall({ tenant: 'acme', baseUrl: 'https://api.test', proxyBaseUrl: 'https://acme.test', apiKey: 'kc_live_x', sandbox: false, fetchImpl });
}

describe('wrap.fetch — route mode', () => {
  it('sends via the durable route (x-knoxcall-route, no upstream credential)', async () => {
    const seen: Seen[] = [];
    const wrapped = makeClient(seen).wrap.fetch({ route: 'stripe-api' });
    await wrapped('https://api.stripe.com/v1/charges?limit=3', {
      method: 'POST', headers: { authorization: 'Bearer sk_live_x', 'content-type': 'application/x-www-form-urlencoded' }, body: STRIPE_FORM,
    });
    const r = seen[0];
    // Goes to the route data plane with the route header — NOT /v1/proxy.
    expect(r.url).toBe('https://acme.test/v1/charges?limit=3');
    expect(r.headers['x-knoxcall-route']).toBe('stripe-api');
    // The route injects the stored secret: no provider credential travels.
    expect(r.headers['x-knox-upstream-authorization']).toBeUndefined();
    expect(r.headers['x-knox-proxy-url']).toBeUndefined();
    // KnoxCall's own credential still authenticates.
    expect(r.headers['authorization']).toBe('Bearer kc_live_x');
    expect(r.body).toBe(STRIPE_FORM);
  });
});

describe('wrap.fetch — promoted-route hint', () => {
  it('fires onPromoted when a response advertises a promoted route', async () => {
    const seen: Seen[] = [];
    const onPromoted = vi.fn();
    const wrapped = makeClientWithHint(seen, 'stripe-api').wrap.fetch({ onPromoted });
    await wrapped('https://api.stripe.com/v1/charges', { method: 'POST', headers: { authorization: 'Bearer sk_live_x' }, body: '' });
    expect(onPromoted).toHaveBeenCalledWith({ host: 'api.stripe.com', slug: 'stripe-api' });
  });

  it('does NOT auto-switch by default (stays on the ephemeral path)', async () => {
    const seen: Seen[] = [];
    const wrapped = makeClientWithHint(seen, 'stripe-api').wrap.fetch();
    await wrapped('https://api.stripe.com/v1/charges', { method: 'POST', headers: { authorization: 'Bearer sk_live_x' }, body: '' });
    await wrapped('https://api.stripe.com/v1/charges', { method: 'POST', headers: { authorization: 'Bearer sk_live_x' }, body: '' });
    // Both calls stayed ephemeral (/v1/proxy), no route header.
    expect(seen.every((s) => s.url.endsWith('/v1/proxy'))).toBe(true);
    expect(seen.every((s) => s.headers['x-knoxcall-route'] === undefined)).toBe(true);
  });

  it('auto-switches subsequent calls to the route when autoSwitch is on', async () => {
    const seen: Seen[] = [];
    const wrapped = makeClientWithHint(seen, 'stripe-api').wrap.fetch({ autoSwitch: true });
    await wrapped('https://api.stripe.com/v1/charges', { method: 'POST', headers: { authorization: 'Bearer sk_live_x' }, body: '' });
    await wrapped('https://api.stripe.com/v1/charges', { method: 'POST', headers: { authorization: 'Bearer sk_live_x' }, body: '' });
    // First call ephemeral (learns the hint); second call switched to the route.
    expect(seen[0].url).toBe('https://api.test/v1/proxy');
    expect(seen[1].url).toBe('https://acme.test/v1/charges');
    expect(seen[1].headers['x-knoxcall-route']).toBe('stripe-api');
    expect(seen[1].headers['x-knox-upstream-authorization']).toBeUndefined();
  });
});
