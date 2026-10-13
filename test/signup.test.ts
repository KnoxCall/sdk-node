// signup() / claimSignup() — the credential-less standalone helpers for
// POST /v1/signup and POST /v1/signup/claim.
//
// Rewritten 2026-08-28 for the F-25 contract (wave-2 row 2-561): signup no
// longer has a 201 and never returns a credential. Every success case in
// sdk/PARITY.md §11 is covered here — the signup 202, the claim's pending 202,
// the claim's ready 200 — plus the typed-error path. The 202s are SUCCESSES;
// an SDK that maps them to exceptions fails on every poll but the last.

import { describe, it, expect } from 'vitest';
import { signup, claimSignup, SignupError, KnoxCallError } from '../src/index.js';

const SIGNUP_ACCEPTED = {
  data: {
    status: 'pending',
    claim_handle: 'sck_Yy3n0Rz1qF8mKpX2sVb7dH9tLwQ4eJ6uA1cN5gZ8kT0',
    claim_path: '/v1/signup/claim',
    poll_after_seconds: 5,
    expires_at: '2026-08-29T09:14:22.117Z',
    message: 'If this email can be registered, a sign-in link has been sent.',
    documentation: 'https://docs.knoxcall.com',
  },
  meta: { request_id: 'req-signup' },
};

const CLAIM_PENDING = {
  data: {
    status: 'pending',
    message: 'Not ready yet.',
    poll_after_seconds: 5,
    expires_at: '2026-08-29T09:14:22.117Z',
  },
  meta: { request_id: 'req-claim-1' },
};

const CLAIM_READY = {
  data: {
    status: 'ready',
    tenant: { id: 't_1', slug: 'acme', name: 'Acme Inc', region: 'us', plan: 'free' },
    starter: {
      route: { id: 'r_1', name: 'getting-started', target_base_url: 'https://httpbin.org' },
      api_key: { id: 'ak_1', key_id: 'kid', api_key: 'tk_test_once', key_prefix: 'tk_te', key_type: 'test' },
      sandbox_host: 'sandbox-acme.knoxcall.com',
      curl: 'curl ...',
    },
    sandbox: { management_api: 'https://sandbox.knoxcall.com/v1', proxy_host: 'sandbox-acme.knoxcall.com', note: 'n' },
    documentation: 'https://docs.knoxcall.com',
  },
  meta: { request_id: 'req-claim-2' },
};

function stub(status: number, body: unknown, seen?: { url?: string; body?: string }): typeof fetch {
  return (async (url: string, init: RequestInit) => {
    if (seen) {
      seen.url = String(url);
      seen.body = String(init?.body ?? '');
    }
    return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
  }) as unknown as typeof fetch;
}

describe('signup()', () => {
  it('returns the 202 claim handle and never a credential', async () => {
    const seen: { url?: string; body?: string } = {};
    const res = await signup(
      { email: 'dev@example.com', tenant_name: 'Acme Inc' },
      { baseUrl: 'https://api.test', fetch: stub(202, SIGNUP_ACCEPTED, seen) },
    );

    expect(seen.url).toBe('https://api.test/v1/signup');
    expect(res.status).toBe('pending');
    expect(res.claim_handle).toBe('sck_Yy3n0Rz1qF8mKpX2sVb7dH9tLwQ4eJ6uA1cN5gZ8kT0');
    expect(res.poll_after_seconds).toBe(5);
    expect('meta' in res).toBe(false); // envelope unwrapped

    // The contract row 2-561 exists to enforce: no key of any kind here.
    expect(JSON.stringify(res)).not.toMatch(/tk_|kc_live|kc_test/);
    expect((res as Record<string, unknown>).starter).toBeUndefined();
  });

  it('throws SignupError with .status and .type on server error', async () => {
    const err = await signup(
      { email: 'bad', tenant_name: 'x' },
      {
        baseUrl: 'https://api.test',
        fetch: stub(400, { error: { type: 'validation_error', message: 'email is invalid' } }),
      },
    ).catch((e) => e);
    expect(err).toBeInstanceOf(SignupError);
    expect(err).toBeInstanceOf(KnoxCallError); // re-parented into the SDK hierarchy
    expect(err.status).toBe(400);
    expect(err.type).toBe('validation_error');
    expect(err.message).toBe('email is invalid');
  });

  it('throws SignupError when the body has no data even on a 2xx', async () => {
    const err = await signup(
      { email: 'dev@example.com', tenant_name: 'Acme' },
      { baseUrl: 'https://api.test', fetch: stub(200, {}) },
    ).catch((e) => e);
    expect(err).toBeInstanceOf(SignupError);
    expect(err.status).toBe(200);
    expect(err.type).toBeUndefined();
  });
});

describe('claimSignup()', () => {
  it('treats the pending 202 as a SUCCESS, not an error', async () => {
    const seen: { url?: string; body?: string } = {};
    const res = await claimSignup(
      { claim_handle: 'sck_handle' },
      { baseUrl: 'https://api.test', fetch: stub(202, CLAIM_PENDING, seen) },
    );

    expect(seen.url).toBe('https://api.test/v1/signup/claim');
    expect(JSON.parse(seen.body!)).toEqual({ claim_handle: 'sck_handle' });
    expect(res.status).toBe('pending');
    expect(JSON.stringify(res)).not.toMatch(/tk_/);
  });

  it('returns the one-time starter key once the link has been clicked', async () => {
    const res = await claimSignup(
      { claim_handle: 'sck_handle' },
      { baseUrl: 'https://api.test', fetch: stub(200, CLAIM_READY) },
    );

    expect(res.status).toBe('ready');
    // Narrowed by the discriminant — this must compile, not just pass.
    if (res.status !== 'ready') throw new Error('expected a ready claim');
    expect(res.starter.api_key.api_key).toBe('tk_test_once');
    expect(res.starter.api_key.key_type).toBe('test');
    expect(res.tenant.slug).toBe('acme');
  });

  it('throws SignupError when the handle was already collected', async () => {
    const err = await claimSignup(
      { claim_handle: 'sck_handle' },
      {
        baseUrl: 'https://api.test',
        fetch: stub(409, {
          error: { type: 'claim_already_collected', message: 'already collected' },
        }),
      },
    ).catch((e) => e);
    expect(err).toBeInstanceOf(SignupError);
    expect(err.status).toBe(409);
    expect(err.type).toBe('claim_already_collected');
  });
});
