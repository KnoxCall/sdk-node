// exchangeToken() — credential-less RFC 8693 exchange against
// POST /v1/oauth/token (AIGW-26).
//
// Three behaviours a caller gets wrong, all asserted here:
//   1. The response is a BARE OAuth body, not the {data, meta} envelope.
//   2. `resource` is only sent when supplied — sending it empty is a refusal,
//      not "no resource", because dropping it silently would mint an
//      UNCONFINED token while the caller believes it is audience-restricted.
//   3. The path is /v1/oauth/token, NOT the root-host /oauth/token that mints
//      management tokens. Sending one grant to the other is a 400.
//   4. The HOST is the tenant data plane, not the management API. Verified
//      against a running server 2026-08-25: the same request answers 400
//      invalid_grant on acme.knoxcall.com and 401 on api.knoxcall.com, so a
//      caller who guesses the management host reads a "rejected credential"
//      that is really "wrong host". There is therefore no default.

import { describe, it, expect, vi } from 'vitest';
import {
  BootstrapError,
  exchangeToken,
  KnoxCallError,
  TOKEN_EXCHANGE_GRANT,
  ID_TOKEN_TYPE,
  KNOXCALL_AUDIENCE,
} from '../src/index.js';

const OK = {
  access_token: 'kc_live_agt_deadbeef',
  issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
  token_type: 'Bearer',
  expires_in: 900,
  scope: '{"providers":["anthropic"]}',
};

function capture(status: number, body: unknown) {
  const seen: { url?: string; init?: RequestInit } = {};
  const f: typeof fetch = async (url: any, init?: any) => {
    seen.url = String(url);
    seen.init = init;
    return new Response(JSON.stringify(body), {
      status,
      headers: { 'Content-Type': 'application/json' },
    });
  };
  return { f, seen };
}

describe('exchangeToken()', () => {
  it('POSTs the RFC 8693 grant to /v1/oauth/token and returns the bare body', async () => {
    const { f, seen } = capture(200, OK);
    const res = await exchangeToken(
      { subject_token: 'header.payload.sig' },
      { baseUrl: 'https://acme.test', fetch: f },
    );

    expect(seen.url).toBe('https://acme.test/v1/oauth/token');
    const sent = JSON.parse(String(seen.init?.body));
    expect(sent.grant_type).toBe(TOKEN_EXCHANGE_GRANT);
    expect(sent.subject_token_type).toBe(ID_TOKEN_TYPE);
    expect(sent.audience).toBe(KNOXCALL_AUDIENCE);
    expect(sent.subject_token).toBe('header.payload.sig');

    // Bare OAuth body — no envelope to unwrap.
    expect(res.access_token).toBe('kc_live_agt_deadbeef');
    expect(res.expires_in).toBe(900);
    expect('data' in (res as any)).toBe(false);
  });

  it('sends no Authorization header — the subject token IS the credential', async () => {
    const { f, seen } = capture(200, OK);
    await exchangeToken({ subject_token: 'a.b.c' }, { baseUrl: 'https://acme.test', fetch: f });
    const headers = (seen.init?.headers ?? {}) as Record<string, string>;
    expect(Object.keys(headers).map((k) => k.toLowerCase())).not.toContain('authorization');
  });

  it('omits `resource` entirely when the caller did not ask for one', async () => {
    const { f, seen } = capture(200, OK);
    await exchangeToken({ subject_token: 'a.b.c' }, { baseUrl: 'https://acme.test', fetch: f });
    expect('resource' in JSON.parse(String(seen.init?.body))).toBe(false);
  });

  it('forwards `resource` verbatim, including an empty string', async () => {
    // An empty `resource` must reach the server and be refused `invalid_target`.
    // Treating it as absent here would hand back an UNCONFINED agent token to a
    // caller who asked for a confined one.
    const { f, seen } = capture(200, OK);
    await exchangeToken(
      { subject_token: 'a.b.c', resource: '' },
      { baseUrl: 'https://acme.test', fetch: f },
    );
    expect(JSON.parse(String(seen.init?.body)).resource).toBe('');
  });

  it('throws KnoxCallError carrying the RFC 6749 error code', async () => {
    const { f } = capture(400, {
      error: 'invalid_grant',
      error_description: 'No tenant bindings registered for issuer https://token.actions.githubusercontent.com',
    });
    const err = await exchangeToken(
      { subject_token: 'a.b.c' },
      { baseUrl: 'https://acme.test', fetch: f },
    ).catch((e) => e);

    expect(err).toBeInstanceOf(KnoxCallError);
    expect(err.status).toBe(400);
    expect(err.code).toBe('invalid_grant');
    expect(err.message).toContain('No tenant bindings registered');
  });

  it('throws when a 200 carries no access_token', async () => {
    const { f } = capture(200, { token_type: 'Bearer' });
    const err = await exchangeToken(
      { subject_token: 'a.b.c' },
      { baseUrl: 'https://acme.test', fetch: f },
    ).catch((e) => e);
    expect(err).toBeInstanceOf(KnoxCallError);
    expect(err.code).toBe('token_exchange_failed');
  });

  it('does not mask a non-JSON error page as a parse failure', async () => {
    const f: typeof fetch = async () => new Response('<html>502</html>', { status: 502 });
    const err = await exchangeToken(
      { subject_token: 'a.b.c' },
      { baseUrl: 'https://acme.test', fetch: f },
    ).catch((e) => e);
    expect(err).toBeInstanceOf(KnoxCallError);
    expect(err.status).toBe(502);
  });

  it('strips a trailing slash from baseUrl rather than doubling it', async () => {
    const { f, seen } = capture(200, OK);
    await exchangeToken({ subject_token: 'a.b.c' }, { baseUrl: 'https://acme.test/', fetch: f });
    expect(seen.url).toBe('https://acme.test/v1/oauth/token');
  });

  it('derives the tenant data-plane host from a tenant slug', async () => {
    const { f, seen } = capture(200, OK);
    await exchangeToken({ subject_token: 'a.b.c' }, { tenant: 'acme', fetch: f });
    expect(seen.url).toBe('https://acme.knoxcall.com/v1/oauth/token');
  });

  it('derives the sandbox data-plane host', async () => {
    const { f, seen } = capture(200, OK);
    await exchangeToken({ subject_token: 'a.b.c' }, { tenant: 'acme', sandbox: true, fetch: f });
    expect(seen.url).toBe('https://sandbox-acme.knoxcall.com/v1/oauth/token');
  });

  it('refuses to guess a host rather than 401ing against the management API', async () => {
    // api.knoxcall.com answers 401 for this request — the endpoint is not
    // served there. A default would turn "wrong host" into "your CI token was
    // rejected", which is the hardest possible thing to debug.
    const { f } = capture(200, OK);
    const err = await exchangeToken({ subject_token: 'a.b.c' }, { fetch: f }).catch((e) => e);
    expect(err).toBeInstanceOf(BootstrapError);
    expect(err.message).toContain('tenant');
  });

  it('warns when the exchange would cross a plaintext hop', async () => {
  // The subject token IS a credential, so a plaintext hop leaks it. PARITY 15
  // already warns when a CLIENT is constructed against plaintext http; this
  // function deliberately constructs no client, so the control had to be added
  // on this path too or it would exist on one and be absent on the parallel one.
    const warned: string[] = [];
    const spy = vi
      .spyOn(process, 'emitWarning')
      .mockImplementation((m: any) => void warned.push(String(m)));
    try {
      const { f } = capture(200, OK);
      await exchangeToken({ subject_token: 'a.b.c' }, { baseUrl: 'http://evil.example', fetch: f });
      expect(warned.join('\n')).toContain('plaintext HTTP');
    } finally {
      spy.mockRestore();
    }
  });

  it('does not warn for https, or for http on loopback', async () => {
    // The acceptance harness and local dev both use http://127.0.0.1, so a
    // refusal here would be wrong and a warning there would be noise.
    const warned: string[] = [];
    const spy = vi
      .spyOn(process, 'emitWarning')
      .mockImplementation((m: any) => void warned.push(String(m)));
    try {
      const a = capture(200, OK);
      await exchangeToken({ subject_token: 'a.b.c' }, { baseUrl: 'https://acme.test', fetch: a.f });
      const b = capture(200, OK);
      await exchangeToken({ subject_token: 'a.b.c' }, { baseUrl: 'http://127.0.0.1:3000', fetch: b.f });
      expect(warned.filter((w) => w.includes('plaintext HTTP'))).toEqual([]);
    } finally {
      spy.mockRestore();
    }
  });

  it('refuses a tenant slug that is not a DNS label', async () => {
    // The slug becomes the host the workload's OIDC token is sent to.
    const { f } = capture(200, OK);
    for (const bad of ['evil.com#', 'a b', '-lead', 'trail-', '']) {
      const err = await exchangeToken({ subject_token: 'a.b.c' }, { tenant: bad, fetch: f }).catch((e) => e);
      expect(err, `slug ${JSON.stringify(bad)} was accepted`).toBeInstanceOf(BootstrapError);
    }
  });
});
