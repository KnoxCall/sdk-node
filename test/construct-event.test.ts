// Spec-A matrix for constructWebhookEvent / webhooks.constructEvent —
// verify-and-parse in one step, per-format HMAC recompute, replay tolerance,
// typed error on any failure. Mirrors the server's src/webhooks/hmac-formats.ts.
//
// Signature is positional + synchronous — (rawBody, headers, secret, opts) —
// matching the python/go/php/ruby SDKs (PARITY §12).

import { describe, it, expect } from 'vitest';
import { createHmac } from 'crypto';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import {
  KnoxCall,
  constructWebhookEvent,
  WebhookSignatureVerificationError,
  KnoxCallError,
  type RequestWebhookEvent,
  type AuditWebhookEvent,
} from '../src/index.js';

const SECRET = 'whsec_construct_test';

function requestEventBody(overrides?: Record<string, unknown>): string {
  return JSON.stringify({
    event: 'request.completed',
    timestamp: new Date().toISOString(),
    webhook_id: 'wh_1',
    webhook_name: 'orders',
    data: {
      route_id: 'r_1',
      route_name: 'orders-api',
      environment: 'production',
      request: { method: 'POST', path: '/v1/orders', ip: '1.2.3.4' },
      response: { status: 200, latency_ms: 88 },
    },
    ...overrides,
  });
}

function legacyHeaders(body: string, secret = SECRET) {
  const sig = createHmac('sha256', secret).update(body).digest('hex');
  return { 'X-Webhook-Signature': `sha256=${sig}` };
}

describe('constructWebhookEvent — legacy format (default)', () => {
  it('verifies a valid delivery and returns the typed request event', () => {
    const body = requestEventBody();
    const event = constructWebhookEvent(body, legacyHeaders(body), SECRET);
    expect(event.event).toBe('request.completed');
    const req = event as RequestWebhookEvent;
    expect(req.webhook_id).toBe('wh_1');
    expect(req.data.route_name).toBe('orders-api');
    expect(req.data.request.method).toBe('POST');
    expect(req.data.response.status).toBe(200);
  });

  it('header lookup is case-insensitive and accepts Buffer bodies', () => {
    const body = requestEventBody();
    const sig = createHmac('sha256', SECRET).update(body).digest('hex');
    const event = constructWebhookEvent(
      Buffer.from(body, 'utf8'),
      { 'x-WEBHOOK-signature': `sha256=${sig}` },
      SECRET,
    );
    expect(event.event).toBe('request.completed');
  });

  it('rejects the wrong secret with the typed error (message never echoes signature/secret)', () => {
    const body = requestEventBody();
    let err: unknown;
    try {
      constructWebhookEvent(body, legacyHeaders(body, 'whsec_other'), SECRET);
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(WebhookSignatureVerificationError);
    expect(err).toBeInstanceOf(KnoxCallError); // part of the SDK hierarchy
    expect((err as Error).message).not.toContain(SECRET);
    expect((err as Error).message).not.toContain('sha256=');
  });

  it('rejects a missing signature header', () => {
    expect(() => constructWebhookEvent(requestEventBody(), {}, SECRET)).toThrow(
      WebhookSignatureVerificationError,
    );
  });

  it('rejects a stale envelope timestamp, and accepts it when tolerance is disabled', () => {
    const stale = requestEventBody({ timestamp: new Date(Date.now() - 3600_000).toISOString() });
    expect(() => constructWebhookEvent(stale, legacyHeaders(stale), SECRET)).toThrow(
      WebhookSignatureVerificationError,
    );

    // Explicitly disabled tolerance (null or 0) skips the envelope-timestamp check.
    const viaNull = constructWebhookEvent(stale, legacyHeaders(stale), SECRET, {
      toleranceSeconds: null,
    });
    expect(viaNull.event).toBe('request.completed');
    const viaZero = constructWebhookEvent(stale, legacyHeaders(stale), SECRET, {
      toleranceSeconds: 0,
    });
    expect(viaZero.event).toBe('request.completed');
  });

  it('rejects a non-JSON body with the typed error', () => {
    const body = 'this is not json';
    expect(() => constructWebhookEvent(body, legacyHeaders(body), SECRET)).toThrow(
      WebhookSignatureVerificationError,
    );
  });

  it('parses unknown event types (forward compatible)', () => {
    const body = JSON.stringify({
      event: 'lease.expired',
      timestamp: new Date().toISOString(),
      data: { something: 'new' },
    });
    const event = constructWebhookEvent(body, legacyHeaders(body), SECRET);
    expect(event.event).toBe('lease.expired');
    expect((event.data as { something: string }).something).toBe('new');
  });

  it('parses audit.event deliveries (no webhook_id/webhook_name)', () => {
    const body = JSON.stringify({
      event: 'audit.event',
      timestamp: new Date().toISOString(),
      data: { id: 'al_1', action: 'secret.created', resource_type: 'secret', resource_id: null, details: {}, ip_address: null },
    });
    const event = constructWebhookEvent(body, legacyHeaders(body), SECRET) as AuditWebhookEvent;
    expect(event.event).toBe('audit.event');
    expect(event.data.action).toBe('secret.created');
  });
});

describe('constructWebhookEvent — stripe format', () => {
  function stripeHeader(body: string, ts: number, secret = SECRET, extraV1?: string) {
    const sig = createHmac('sha256', secret).update(`${ts}.${body}`).digest('hex');
    return extraV1 !== undefined
      ? { 'Stripe-Signature': `t=${ts},v1=${extraV1},v1=${sig}` }
      : { 'Stripe-Signature': `t=${ts},v1=${sig}` };
  }

  it('round-trips: signs <ts>.<body> and verifies', () => {
    const body = requestEventBody();
    const ts = Math.floor(Date.now() / 1000);
    const event = constructWebhookEvent(body, stripeHeader(body, ts), SECRET, { format: 'stripe' });
    expect(event.event).toBe('request.completed');
  });

  it('accepts multiple v1 entries — any matching one passes (rotated secrets)', () => {
    const body = requestEventBody();
    const ts = Math.floor(Date.now() / 1000);
    const event = constructWebhookEvent(
      body,
      stripeHeader(body, ts, SECRET, 'deadbeef'.repeat(8)),
      SECRET,
      { format: 'stripe' },
    );
    expect(event.event).toBe('request.completed');
  });

  it('rejects a stale header timestamp', () => {
    const body = requestEventBody();
    const ts = Math.floor(Date.now() / 1000) - 3600;
    expect(() =>
      constructWebhookEvent(body, stripeHeader(body, ts), SECRET, { format: 'stripe' }),
    ).toThrow(WebhookSignatureVerificationError);
  });

  it('rejects a malformed Stripe-Signature header', () => {
    expect(() =>
      constructWebhookEvent(
        requestEventBody(),
        { 'Stripe-Signature': 'garbage' },
        SECRET,
        { format: 'stripe' },
      ),
    ).toThrow(WebhookSignatureVerificationError);
  });

  it('rejects a non-numeric t= timestamp instead of silently passing tolerance', () => {
    // A valid signature over a non-numeric timestamp must not slip through:
    // Number("nope") is NaN, and NaN > tolerance is false, so a naive check
    // would accept it. Parity with Python/Go, which raise.
    const body = requestEventBody();
    const sig = createHmac('sha256', SECRET).update(`nope.${body}`).digest('hex');
    expect(() =>
      constructWebhookEvent(
        body,
        { 'Stripe-Signature': `t=nope,v1=${sig}` },
        SECRET,
        { format: 'stripe' },
      ),
    ).toThrow(WebhookSignatureVerificationError);
  });
});

describe('constructWebhookEvent — slack format', () => {
  it('round-trips: signs v0:<ts>:<body> with the timestamp header', () => {
    const body = requestEventBody();
    const ts = Math.floor(Date.now() / 1000);
    const sig = createHmac('sha256', SECRET).update(`v0:${ts}:${body}`).digest('hex');
    const event = constructWebhookEvent(
      body,
      { 'X-Slack-Signature': `v0=${sig}`, 'X-Slack-Request-Timestamp': String(ts) },
      SECRET,
      { format: 'slack' },
    );
    expect(event.event).toBe('request.completed');
  });

  it('rejects a stale slack timestamp and a missing timestamp header', () => {
    const body = requestEventBody();
    const stale = Math.floor(Date.now() / 1000) - 3600;
    const sig = createHmac('sha256', SECRET).update(`v0:${stale}:${body}`).digest('hex');
    expect(() =>
      constructWebhookEvent(
        body,
        { 'X-Slack-Signature': `v0=${sig}`, 'X-Slack-Request-Timestamp': String(stale) },
        SECRET,
        { format: 'slack' },
      ),
    ).toThrow(WebhookSignatureVerificationError);
    expect(() =>
      constructWebhookEvent(body, { 'X-Slack-Signature': `v0=${sig}` }, SECRET, { format: 'slack' }),
    ).toThrow(WebhookSignatureVerificationError);
  });
});

describe('constructWebhookEvent — github / aws-sns / custom formats', () => {
  it('github: verifies X-Hub-Signature-256', () => {
    const body = requestEventBody();
    const sig = createHmac('sha256', SECRET).update(body).digest('hex');
    const event = constructWebhookEvent(
      body,
      { 'X-Hub-Signature-256': `sha256=${sig}` },
      SECRET,
      { format: 'github' },
    );
    expect(event.event).toBe('request.completed');
  });

  it('aws-sns: verifies the base64 signature', () => {
    const body = requestEventBody();
    const sig = createHmac('sha256', SECRET).update(body).digest('base64');
    const event = constructWebhookEvent(
      body,
      { 'x-amz-sns-signature': sig },
      SECRET,
      { format: 'aws-sns' },
    );
    expect(event.event).toBe('request.completed');
  });

  it('custom: verifies against the caller-named header, and requires headerName', () => {
    const body = requestEventBody();
    const sig = createHmac('sha256', SECRET).update(body).digest('hex');
    const event = constructWebhookEvent(
      body,
      { 'X-Acme-Sig': `sha256=${sig}` },
      SECRET,
      { format: 'custom', headerName: 'X-Acme-Sig' },
    );
    expect(event.event).toBe('request.completed');

    expect(() =>
      constructWebhookEvent(body, { 'X-Acme-Sig': `sha256=${sig}` }, SECRET, { format: 'custom' }),
    ).toThrow(WebhookSignatureVerificationError);
  });
});

describe('constructEvent on the webhooks resource', () => {
  it('client.webhooks.constructEvent delegates to the standalone helper', () => {
    const client = new KnoxCall({
      tenant: 'acme',
      baseUrl: 'https://api.test',
      bootstrap: { type: 'access_token', accessToken: 'kc_live_x' },
    });
    const body = requestEventBody();
    const event = client.webhooks.constructEvent(body, legacyHeaders(body), SECRET);
    expect(event.event).toBe('request.completed');
  });
});

describe('constant-time comparison', () => {
  it('the implementation compares via crypto.timingSafeEqual, never ===', () => {
    // Asserted via the implementation, not timing: the signature-compare
    // path must go through timingSafeEqual.
    const here = dirname(fileURLToPath(import.meta.url));
    const src = readFileSync(join(here, '../src/resources/webhooks.ts'), 'utf8');
    expect(src).toContain('timingSafeEqual');
    // No direct equality on the received signature value anywhere.
    expect(src).not.toMatch(/expected\s*===\s*(received|header)/);
  });
});
