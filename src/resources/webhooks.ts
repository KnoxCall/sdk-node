// Webhooks resource — mirrors src/client-api/webhooks.ts

import { createHmac, timingSafeEqual } from "crypto";
import type { APIClient } from "../core.js";
import { WebhookSignatureVerificationError } from "../error.js";
import { type Envelope, type Page, type PageParams, iteratePages, unwrap } from "./shared.js";

/** Row returned by GET /v1/webhooks. */
export interface Webhook {
  id: string;
  name: string;
  description: string | null;
  url: string;
  method: string;
  event_types: string[];
  auth_type: string;
  enabled: boolean;
  last_triggered_at: string | null;
  trigger_count: number;
  success_count: number;
  failure_count: number;
  created_at: string;
}

/** Full detail returned by GET /v1/webhooks/:id. */
export interface WebhookDetail extends Webhook {
  // `request_headers` is deliberately ABSENT (server fix row 2-492): it is
  // accepted on create/update but never returned, because the dispatcher
  // spreads it into the outbound header map alongside the
  // `auth_config`-derived `Authorization`, so a value stored there is
  // indistinguishable from a destination API key. Same reason `secret_key`
  // and `auth_config` have never been on this interface.
  route_filter: string[] | null;
  include_request_body: boolean;
  include_response_body: boolean;
  include_headers: boolean;
  timeout_seconds: number;
  retry_on_failure: boolean;
  max_retries: number;
  last_success_at: string | null;
  last_failure_at: string | null;
}

export type WebhookHmacFormat = "legacy" | "stripe" | "github" | "slack" | "aws-sns" | "custom";

/** POST /v1/webhooks response — `secret_key` is returned ONCE. */
export interface CreateWebhookResponse {
  id: string;
  name: string;
  description: string | null;
  url: string;
  method: string;
  event_types: string[];
  auth_type: string;
  enabled: boolean;
  hmac_key_id: string | null;
  hmac_format: WebhookHmacFormat | null;
  hmac_header_name: string | null;
  created_at: string;
  /** Signing secret — only ever present in this response. */
  secret_key: string;
}

/** PATCH /v1/webhooks/:id response (no secret/hmac fields). */
export interface UpdateWebhookResponse {
  id: string;
  name: string;
  description: string | null;
  url: string;
  method: string;
  event_types: string[];
  auth_type: string;
  enabled: boolean;
  created_at: string;
}

/** Row returned by GET /v1/webhooks/:id/logs. */
export interface WebhookLogEntry {
  id: string;
  /** HTTP method used to deliver the event. */
  http_method: string | null;
  /** URL the delivery was sent to. */
  target_url: string | null;
  /** Always null today — no delivery path records a source IP. */
  source_ip: string | null;
  response_status: number | null;
  response_time_ms: number | null;
  executed_at: string;
  success: boolean;
  error_message: string | null;
}

export interface CreateWebhookInput {
  name: string;
  url: string;
  event_types: string[];
  description?: string;
  method?: string;
  auth_type?: string;
  auth_config?: Record<string, unknown>;
  request_headers?: Record<string, string>;
  route_filter?: string;
  include_request_body?: boolean;
  include_response_body?: boolean;
  include_headers?: boolean;
  timeout_seconds?: number;
  retry_on_failure?: boolean;
  max_retries?: number;
  enabled?: boolean;
}

export type UpdateWebhookInput = Partial<CreateWebhookInput>;

export class WebhooksResource {
  constructor(private readonly client: APIClient) {}

  async list(params?: PageParams): Promise<Page<Webhook>> {
    return this.client.request<Page<Webhook>>({
      method: "GET",
      path: "/v1/webhooks",
      query: params as Record<string, string | number | undefined>,
    });
  }

  iterate(params?: PageParams): AsyncIterableIterator<Webhook> {
    return iteratePages((page) => this.list({ ...params, page }), params?.page ?? 1);
  }

  async get(id: string): Promise<WebhookDetail> {
    return unwrap(await this.client.request<Envelope<WebhookDetail>>({
      method: "GET", path: `/v1/webhooks/${encodeURIComponent(id)}`,
    }));
  }

  /** ``secret_key`` is returned once — save it immediately. */
  async create(input: CreateWebhookInput, opts?: { idempotencyKey?: string }): Promise<CreateWebhookResponse> {
    return unwrap(await this.client.request<Envelope<CreateWebhookResponse>>({
      method: "POST",
      path: "/v1/webhooks",
      body: input,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  async update(id: string, input: UpdateWebhookInput, opts?: { idempotencyKey?: string }): Promise<UpdateWebhookResponse> {
    return unwrap(await this.client.request<Envelope<UpdateWebhookResponse>>({
      method: "PATCH",
      path: `/v1/webhooks/${encodeURIComponent(id)}`,
      body: input,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  async delete(id: string, opts?: { idempotencyKey?: string }): Promise<{ deleted: true }> {
    return unwrap(await this.client.request<Envelope<{ deleted: true }>>({
      method: "DELETE",
      path: `/v1/webhooks/${encodeURIComponent(id)}`,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  async getLogs(id: string, params?: PageParams): Promise<Page<WebhookLogEntry>> {
    return this.client.request<Page<WebhookLogEntry>>({
      method: "GET",
      path: `/v1/webhooks/${encodeURIComponent(id)}/logs`,
      query: params as Record<string, string | number | undefined>,
    });
  }

  /**
   * List the webhook event types that can be subscribed to (value, human
   * label, and description). Static metadata — handy for building dropdowns.
   */
  async listEventTypes(): Promise<{ event_types: WebhookEventType[] }> {
    return unwrap(await this.client.request<Envelope<{ event_types: WebhookEventType[] }>>({
      method: "GET", path: "/v1/webhooks/event-types",
    }));
  }

  /**
   * Send a synthetic ``webhook.test`` event to a webhook's configured URL and
   * return the delivery result. Delivery goes through the same SSRF-pinned
   * egress and HMAC signing as real events.
   */
  async test(id: string, opts?: { idempotencyKey?: string }): Promise<WebhookTestResult> {
    return unwrap(await this.client.request<Envelope<WebhookTestResult>>({
      method: "POST",
      path: `/v1/webhooks/${encodeURIComponent(id)}/test`,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  /**
   * Verify an incoming webhook delivery AND parse it into a typed event, in
   * one step. Throws {@link WebhookSignatureVerificationError} on any failure
   * (missing header, bad signature, stale timestamp, non-JSON body).
   *
   * Also available as the standalone ``constructWebhookEvent`` export.
   */
  constructEvent(
    rawBody: string | Buffer,
    headers: Record<string, string | string[] | undefined>,
    secret: string,
    opts?: ConstructEventOptions,
  ): KnoxWebhookEvent {
    return constructWebhookEvent(rawBody, headers, secret, opts);
  }
}

export interface WebhookEventType {
  value: string;
  label: string;
  description: string;
}

export interface WebhookTestResult {
  success: boolean;
  status?: number;
  response_time_ms: number;
  error?: string;
}

// ── Typed webhook events (delivery envelope from src/webhooks/dispatcher.ts) ──

export type RequestWebhookEventType =
  | "request.received"
  | "request.success"
  | "request.redirect"
  | "request.client_error"
  | "request.server_error"
  | "request.timeout"
  | "request.error"
  | "request.completed";

/** `data` payload on `request.*` events. */
export interface RequestEventData {
  route_id: string;
  route_name: string;
  environment: string | null;
  request: { method: string; path: string; ip: string | null };
  response: { status: number | null; latency_ms: number | null };
}

/** `data` payload on `audit.event` events. */
export interface AuditEventData {
  id: string;
  action: string;
  resource_type: string;
  resource_id: string | null;
  details: Record<string, unknown>;
  ip_address: string | null;
}

export interface RequestWebhookEvent {
  event: RequestWebhookEventType;
  timestamp: string;
  webhook_id: string;
  webhook_name: string;
  data: RequestEventData;
}

export interface AuditWebhookEvent {
  event: "audit.event";
  timestamp: string;
  data: AuditEventData;
}

/**
 * Forward-compatibility fallback: the event-type list is open — deliveries
 * with an event string the SDK doesn't know still verify and parse fine.
 */
export interface UnknownWebhookEvent {
  event: string;
  timestamp: string;
  webhook_id?: string;
  webhook_name?: string;
  data: unknown;
}

export type KnoxWebhookEvent = RequestWebhookEvent | AuditWebhookEvent | UnknownWebhookEvent;

export interface ConstructEventOptions {
  /** HMAC signature format the webhook is configured with. Default "legacy". */
  format?: WebhookHmacFormat;
  /**
   * Replay window in seconds (default 300). For `stripe`/`slack` it is
   * enforced against the signed header timestamp; for the other formats
   * against the parsed envelope's ISO-8601 `timestamp` field. Pass `null`
   * or `0` to explicitly disable the timestamp check.
   */
  toleranceSeconds?: number | null;
  /** Signature header name — required when `format` is "custom". */
  headerName?: string;
}

const SIGNATURE_HEADERS: Record<Exclude<WebhookHmacFormat, "custom">, string> = {
  legacy: "x-webhook-signature",
  stripe: "stripe-signature",
  github: "x-hub-signature-256",
  slack: "x-slack-signature",
  "aws-sns": "x-amz-sns-signature",
};

function headerLookup(
  headers: Record<string, string | string[] | undefined>,
  name: string,
): string | undefined {
  const target = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === target) {
      if (Array.isArray(v)) return v[0];
      return v;
    }
  }
  return undefined;
}

/**
 * Verify an incoming KnoxCall webhook delivery and return the typed event.
 *
 * Recomputes the HMAC-SHA256 signature per the webhook's configured
 * `hmac_format` (mirroring the server's src/webhooks/hmac-formats.ts),
 * compares constant-time, enforces the replay tolerance, then JSON-parses
 * the body. On ANY failure it throws
 * {@link WebhookSignatureVerificationError} — never a partial event, and
 * never echoing the signature or the secret.
 */
export function constructWebhookEvent(
  rawBody: string | Buffer,
  headers: Record<string, string | string[] | undefined>,
  secret: string,
  opts?: ConstructEventOptions,
): KnoxWebhookEvent {
  const input = { rawBody, headers, secret, ...opts };
  const format = input.format ?? "legacy";
  const tolerance = input.toleranceSeconds === undefined ? 300 : input.toleranceSeconds;
  const toleranceEnabled = tolerance !== null && tolerance !== 0;

  const bodyBuf = Buffer.isBuffer(input.rawBody) ? input.rawBody : Buffer.from(input.rawBody, "utf8");
  const bodyStr = bodyBuf.toString("utf8");

  const hmacHex = (signed: string | Buffer) =>
    createHmac("sha256", input.secret).update(signed).digest("hex");
  // Constant-time compare of the expected signature encoding vs the received
  // string (both compared as UTF-8 bytes; a length mismatch short-circuits,
  // which leaks only the length — same approach as Stripe's SDKs).
  const constantTimeEquals = (expected: string, received: string): boolean => {
    const a = Buffer.from(expected, "utf8");
    const b = Buffer.from(received, "utf8");
    if (a.length !== b.length) return false;
    try {
      return timingSafeEqual(a, b);
    } catch {
      return false;
    }
  };
  const nowSeconds = Math.floor(Date.now() / 1000);

  let signatureValid = false;

  if (format === "stripe") {
    const header = headerLookup(input.headers, SIGNATURE_HEADERS.stripe);
    if (!header) throw new WebhookSignatureVerificationError("Missing Stripe-Signature header");
    // Parse t=<ts>,v1=<hex>[,v1=<hex>…] — any matching v1 passes (mirrors
    // Stripe's own tolerance for rotated secrets).
    let ts: string | undefined;
    const v1s: string[] = [];
    for (const pair of header.split(",")) {
      const idx = pair.indexOf("=");
      if (idx === -1) continue;
      const key = pair.slice(0, idx).trim();
      const value = pair.slice(idx + 1).trim();
      if (key === "t") ts = value;
      else if (key === "v1") v1s.push(value);
    }
    if (!ts || v1s.length === 0) {
      throw new WebhookSignatureVerificationError("Malformed Stripe-Signature header");
    }
    if (toleranceEnabled) {
      const tsNum = Number(ts);
      if (!Number.isFinite(tsNum)) {
        throw new WebhookSignatureVerificationError("Malformed Stripe-Signature timestamp");
      }
      if (Math.abs(nowSeconds - tsNum) > tolerance) {
        throw new WebhookSignatureVerificationError("Webhook timestamp outside tolerance");
      }
    }
    const expected = hmacHex(`${ts}.${bodyStr}`);
    signatureValid = v1s.some((v1) => constantTimeEquals(expected, v1));
  } else if (format === "slack") {
    const header = headerLookup(input.headers, SIGNATURE_HEADERS.slack);
    if (!header) throw new WebhookSignatureVerificationError("Missing X-Slack-Signature header");
    const ts = headerLookup(input.headers, "x-slack-request-timestamp");
    if (!ts) throw new WebhookSignatureVerificationError("Missing X-Slack-Request-Timestamp header");
    if (toleranceEnabled) {
      const tsNum = Number(ts);
      if (!Number.isFinite(tsNum)) {
        throw new WebhookSignatureVerificationError("Malformed X-Slack-Request-Timestamp timestamp");
      }
      if (Math.abs(nowSeconds - tsNum) > tolerance) {
        throw new WebhookSignatureVerificationError("Webhook timestamp outside tolerance");
      }
    }
    const expected = `v0=${hmacHex(`v0:${ts}:${bodyStr}`)}`;
    signatureValid = constantTimeEquals(expected, header);
  } else if (format === "aws-sns") {
    const header = headerLookup(input.headers, SIGNATURE_HEADERS["aws-sns"]);
    if (!header) throw new WebhookSignatureVerificationError("Missing x-amz-sns-signature header");
    const expected = createHmac("sha256", input.secret).update(bodyBuf).digest("base64");
    signatureValid = constantTimeEquals(expected, header);
  } else {
    // legacy / github / custom — `sha256=<hex>` over the raw body.
    let headerName: string;
    if (format === "custom") {
      if (!input.headerName) {
        throw new WebhookSignatureVerificationError('headerName is required when format is "custom"');
      }
      headerName = input.headerName;
    } else {
      headerName = SIGNATURE_HEADERS[format];
    }
    const header = headerLookup(input.headers, headerName);
    if (!header) {
      throw new WebhookSignatureVerificationError(`Missing ${headerName} signature header`);
    }
    const expected = `sha256=${hmacHex(bodyBuf)}`;
    // Accept the value with or without the sha256= prefix.
    const received = header.startsWith("sha256=") ? header : `sha256=${header}`;
    signatureValid = constantTimeEquals(expected, received);
  }

  if (!signatureValid) {
    throw new WebhookSignatureVerificationError("Webhook signature verification failed");
  }

  let event: KnoxWebhookEvent;
  try {
    event = JSON.parse(bodyStr) as KnoxWebhookEvent;
  } catch {
    throw new WebhookSignatureVerificationError("Webhook body is not valid JSON");
  }
  if (event === null || typeof event !== "object") {
    throw new WebhookSignatureVerificationError("Webhook body is not a JSON object");
  }

  // Formats without a signed timestamp: enforce tolerance against the
  // delivery envelope's ISO-8601 `timestamp` field (skipped when the
  // tolerance is explicitly disabled).
  if (toleranceEnabled && format !== "stripe" && format !== "slack") {
    const envelopeTs = Date.parse((event as { timestamp?: string }).timestamp ?? "");
    if (Number.isNaN(envelopeTs) || Math.abs(nowSeconds - envelopeTs / 1000) > tolerance) {
      throw new WebhookSignatureVerificationError("Webhook timestamp missing or outside tolerance");
    }
  }

  return event;
}

/**
 * Verify the signature on an incoming webhook payload.
 * Constant-time comparison; signature format is hex-encoded HMAC-SHA256.
 *
 * Also available as ``client.verifySignature()``. Prefer
 * {@link constructWebhookEvent} — it verifies AND parses in one step and
 * supports every configured ``hmac_format``.
 */
export function verifyWebhookSignature(input: {
  rawBody: string | Buffer;
  signature: string;
  secret: string;
  toleranceSeconds?: number;
  timestamp?: number;
}): boolean {
  const body = Buffer.isBuffer(input.rawBody) ? input.rawBody : Buffer.from(input.rawBody, "utf8");

  if (input.timestamp !== undefined && input.toleranceSeconds !== undefined) {
    if (Math.abs(Math.floor(Date.now() / 1000) - input.timestamp) > input.toleranceSeconds) return false;
  }

  const expected = createHmac("sha256", input.secret).update(body).digest("hex");
  if (expected.length !== input.signature.length) return false;
  try {
    return timingSafeEqual(Buffer.from(expected), Buffer.from(input.signature));
  } catch {
    return false;
  }
}
