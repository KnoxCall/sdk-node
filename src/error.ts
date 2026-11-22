// Error hierarchy modeled on Anthropic + Stripe SDKs.
//
// Every error carries the X-Request-Id (RFC 8943) when present so users
// can correlate with KnoxCall server logs.

export class KnoxCallError extends Error {
  readonly status?: number;
  readonly code?: string;
  readonly requestId?: string;
  readonly headers?: Record<string, string>;
  readonly body?: unknown;

  constructor(message: string, init?: {
    status?: number;
    code?: string;
    requestId?: string;
    headers?: Record<string, string>;
    body?: unknown;
  }) {
    super(message);
    this.name = "KnoxCallError";
    this.status = init?.status;
    this.code = init?.code;
    this.requestId = init?.requestId;
    this.headers = init?.headers;
    this.body = init?.body;
  }
}

export class APIConnectionError extends KnoxCallError {
  constructor(message: string, init?: ConstructorParameters<typeof KnoxCallError>[1]) {
    super(message, init);
    this.name = "APIConnectionError";
  }
}

export class APIConnectionTimeoutError extends APIConnectionError {
  constructor(message = "Request timed out", init?: ConstructorParameters<typeof KnoxCallError>[1]) {
    super(message, init);
    this.name = "APIConnectionTimeoutError";
  }
}

export class APIUserAbortError extends KnoxCallError {
  constructor(message = "Request aborted", init?: ConstructorParameters<typeof KnoxCallError>[1]) {
    super(message, init);
    this.name = "APIUserAbortError";
  }
}

export class AuthenticationError extends KnoxCallError {
  constructor(message: string, init?: ConstructorParameters<typeof KnoxCallError>[1]) {
    super(message, init);
    this.name = "AuthenticationError";
  }
}

export class PermissionDeniedError extends KnoxCallError {
  constructor(message: string, init?: ConstructorParameters<typeof KnoxCallError>[1]) {
    super(message, init);
    this.name = "PermissionDeniedError";
  }
}

// Deprecated alias — "PermissionError" shadowed a Python builtin, so all
// SDKs renamed to PermissionDeniedError for parity (see sdk/PARITY.md §1).
/** @deprecated Use {@link PermissionDeniedError}. Removed in 2.0. */
export const PermissionError = PermissionDeniedError;
/** @deprecated Use {@link PermissionDeniedError}. Removed in 2.0. */
export type PermissionError = PermissionDeniedError;

/**
 * HTTP 402 — a plan/billing limit was hit. Two error types share this status:
 * `plan_limit` (a counted quota was reached — routes, secrets, AI agents, MCP
 * servers) and `plan_feature` (the capability itself is not on the tier — custom
 * PII redaction policies, compliance packs, custom prompt-firewall policies).
 * The mapping is on STATUS, so both land here without an SDK change.
 * Distinct from {@link PermissionDeniedError} (403) so a caller can show an
 * "upgrade" prompt rather than an "access denied" one.
 */
export class PaymentRequiredError extends KnoxCallError {
  constructor(message: string, init?: ConstructorParameters<typeof KnoxCallError>[1]) {
    super(message, init);
    this.name = "PaymentRequiredError";
  }
}

export class NotFoundError extends KnoxCallError {
  constructor(message: string, init?: ConstructorParameters<typeof KnoxCallError>[1]) {
    super(message, init);
    this.name = "NotFoundError";
  }
}

export class ConflictError extends KnoxCallError {
  constructor(message: string, init?: ConstructorParameters<typeof KnoxCallError>[1]) {
    super(message, init);
    this.name = "ConflictError";
  }
}

export class ValidationError extends KnoxCallError {
  readonly fields?: Record<string, string[]>;
  constructor(message: string, init?: ConstructorParameters<typeof KnoxCallError>[1] & { fields?: Record<string, string[]> }) {
    super(message, init);
    this.name = "ValidationError";
    this.fields = init?.fields;
  }
}

export class RateLimitError extends KnoxCallError {
  readonly retryAfter?: number;
  constructor(message: string, init?: ConstructorParameters<typeof KnoxCallError>[1] & { retryAfter?: number }) {
    super(message, init);
    this.name = "RateLimitError";
    this.retryAfter = init?.retryAfter;
  }
}

export class ServerError extends KnoxCallError {
  /**
   * Seconds to wait before retrying, from the `Retry-After` header — sent on
   * a `503 dependency_unavailable` (KnoxCall could not reach one of its own
   * dependencies in time and did not serve the request) and honoured by the
   * retry loop exactly as a 429's is (PARITY §4). Absent when the server sent
   * none: a plain 5xx keeps the jittered backoff.
   */
  readonly retryAfter?: number;
  constructor(message: string, init?: ConstructorParameters<typeof KnoxCallError>[1] & { retryAfter?: number }) {
    super(message, init);
    this.name = "ServerError";
    this.retryAfter = init?.retryAfter;
  }
}

// Raised by `constructWebhookEvent` / `webhooks.constructEvent` when an
// incoming webhook delivery fails verification (missing header, signature
// mismatch, stale timestamp, or non-JSON body). The message never echoes
// the signature or the secret.
export class WebhookSignatureVerificationError extends KnoxCallError {
  constructor(message: string, init?: ConstructorParameters<typeof KnoxCallError>[1]) {
    super(message, init);
    this.name = "WebhookSignatureVerificationError";
  }
}

// Thrown by the standalone `signup()` helper when POST /v1/signup fails.
// Carries `.status` (HTTP status, from the base class) and `.type` (the
// server error envelope's machine-readable error type).
export class SignupError extends KnoxCallError {
  /** Machine-readable error type from the server's `{error: {type}}` envelope. */
  readonly type?: string;

  constructor(message: string, init?: ConstructorParameters<typeof KnoxCallError>[1] & { type?: string }) {
    super(message, init);
    this.name = "SignupError";
    this.type = init?.type;
  }
}

export class BootstrapError extends KnoxCallError {
  constructor(message: string, init?: ConstructorParameters<typeof KnoxCallError>[1]) {
    super(message, init);
    this.name = "BootstrapError";
  }
}

/**
 * No usable credential was found by auto-detection (no explicit creds, env
 * token/keys, credentials file, or cloud OIDC). Subclass of BootstrapError so
 * existing `catch (BootstrapError)` still works, but distinctly typed so
 * callers can branch on "not logged in — should I run login()?" vs a genuine
 * misconfiguration. See `KnoxCall.login()` / `ensureLogin()`.
 */
export class NotAuthenticatedError extends BootstrapError {
  constructor(message: string, init?: ConstructorParameters<typeof KnoxCallError>[1]) {
    super(message, init);
    this.name = "NotAuthenticatedError";
  }
}

/**
 * A refusal from the AI **data plane** (`POST {agent_url}/…`), typed.
 *
 * WHY IT IS ITS OWN CLASS. The data plane is not the Management API: it
 * answers `{error, error_description, code}` with the machine-readable code in
 * `error` AND `code` (AIGW-163), and the management plane answers the nested
 * `{error: {type, message, request_id}}`. An `err.code` of `budget_exceeded`
 * and an `err.code` of `not_found` therefore come from different contracts, and
 * a caller who wants to branch on "did the gateway refuse my AI call?" has no
 * way to tell them apart from the status alone.
 *
 * The SDK does NOT make the data-plane call for you — that is the design: you
 * point an existing Anthropic or OpenAI SDK at the agent's `agent_url` and it
 * works unchanged. So this class is exposed with {@link aiGatewayErrorFrom},
 * which turns whatever your provider client hands you (a status, a parsed body,
 * response headers) into the typed error.
 *
 * Re-parented under {@link KnoxCallError}, so an existing
 * `catch (e) { if (e instanceof KnoxCallError) … }` still catches it — the same
 * rule the token-exchange error follows (sdk/PARITY.md §1).
 */
export class AIGatewayError extends KnoxCallError {
  /** The stable identifier. Branch on this, never on the description. */
  readonly code: string;
  /** The human sentence. Rewritten whenever a clearer wording is found. */
  readonly errorDescription: string;
  /**
   * Seconds to wait before retrying, from the `Retry-After` header.
   *
   * Present on a `429` whose reset the gateway knows exactly (a spend cap's UTC
   * rollover, a rate-limit window) and ABSENT rather than guessed otherwise —
   * so `undefined` means "back off on your own schedule", not "retry now".
   */
  readonly retryAfter?: number;

  constructor(message: string, init: ConstructorParameters<typeof KnoxCallError>[1] & {
    code: string;
    errorDescription: string;
    retryAfter?: number;
  }) {
    super(message, init);
    this.name = "AIGatewayError";
    this.code = init.code;
    this.errorDescription = init.errorDescription;
    this.retryAfter = init.retryAfter;
  }
}

/** Does this body look like the AI data plane's envelope? */
export function isAIGatewayErrorBody(body: unknown): boolean {
  if (!body || typeof body !== "object") return false;
  const b = body as Record<string, unknown>;
  return typeof b.error === "string"
    && typeof b.code === "string"
    && typeof b.error_description === "string"
    && b.error === b.code;
}

/**
 * Type a refusal your provider client received from an agent's data-plane URL.
 *
 * Returns `null` when the body is not the data plane's envelope, so a caller can
 * fall through to its own handling rather than being handed a mislabelled error:
 *
 * ```ts
 * const res = await fetch(`${agent.agent_url}/v1/messages`, { … });
 * if (!res.ok) {
 *   const err = aiGatewayErrorFrom(res.status, await res.json(), res.headers);
 *   if (err?.code === "budget_exceeded") await sleep((err.retryAfter ?? 60) * 1000);
 *   throw err ?? new Error(`HTTP ${res.status}`);
 * }
 * ```
 *
 * `headers` accepts a `Headers`, a plain object, or nothing.
 */
export function aiGatewayErrorFrom(
  status: number,
  body: unknown,
  headers?: Headers | Record<string, string>,
): AIGatewayError | null {
  if (!isAIGatewayErrorBody(body)) return null;
  const b = body as Record<string, unknown>;
  const read = (name: string): string | undefined => {
    if (!headers) return undefined;
    if (typeof (headers as Headers).get === "function") {
      return (headers as Headers).get(name) ?? undefined;
    }
    const flat = headers as Record<string, string>;
    return flat[name] ?? flat[name.toLowerCase()];
  };
  const retryAfterRaw = read("retry-after");
  const retryAfter = retryAfterRaw !== undefined && /^\d+$/.test(retryAfterRaw.trim())
    ? Number(retryAfterRaw.trim())
    : undefined;
  return new AIGatewayError(b.error_description as string, {
    status,
    code: b.code as string,
    errorDescription: b.error_description as string,
    requestId: read("x-request-id") ?? (typeof b.request_id === "string" ? b.request_id : undefined),
    retryAfter,
    body,
  });
}

export function errorFromResponse(
  status: number,
  body: unknown,
  headers: Record<string, string>,
): KnoxCallError {
  const bodyObj = (body && typeof body === "object" ? body : {}) as Record<string, unknown>;
  const errField = bodyObj.error;

  // The KnoxCall /v1 API returns errors as `{error:{type,message,request_id}}`
  // (the `error` value is an OBJECT). Treating it as a string — the previous
  // bug — coerced it to "[object Object]" and lost the type + request id. We
  // also stay tolerant of the flat shapes some non-/v1 surfaces still use:
  //   B: {error:"<message>", statusCode, errorId}
  //   C: {error:"<code>", message}
  let message: string;
  let code: string | undefined;
  let bodyRequestId: string | undefined;

  if (errField && typeof errField === "object") {
    // Shape A — the canonical /v1 envelope.
    const e = errField as Record<string, unknown>;
    message = (typeof e.message === "string" && e.message)
      || (typeof e.type === "string" && e.type)
      || `HTTP ${status}`;
    code = typeof e.type === "string" ? e.type : undefined;
    bodyRequestId = typeof e.request_id === "string" ? e.request_id : undefined;
  } else {
    // Flat shapes. Prefer a human `message`/`error_description` over the bare
    // `error` (which is a code string in Shape C, a message in Shape B).
    message = (typeof bodyObj.error_description === "string" && bodyObj.error_description)
      || (typeof bodyObj.message === "string" && bodyObj.message)
      || (typeof errField === "string" && errField)
      || `HTTP ${status}`;
    // AIGW-163: the AI data plane sends the code in BOTH `error` and `code`.
    // Prefer the explicit `code` — a future surface could carry a `code` that
    // is not mirrored, and reading the mirror would silently lose it.
    code = (typeof bodyObj.code === "string" && bodyObj.code)
      || (typeof errField === "string" ? errField : undefined);
    bodyRequestId = (typeof bodyObj.request_id === "string" ? bodyObj.request_id : undefined)
      || (typeof bodyObj.errorId === "string" ? bodyObj.errorId : undefined);
  }

  // Correlation id: the X-Request-Id response header (now emitted by the API)
  // or, failing that, the id carried in the body.
  const requestId = headers["x-request-id"] || bodyRequestId;
  const init = { status, code, requestId, headers, body };
  if (status === 401) return new AuthenticationError(message, init);
  if (status === 402) return new PaymentRequiredError(message, init);
  if (status === 403) return new PermissionDeniedError(message, init);
  if (status === 404) return new NotFoundError(message, init);
  if (status === 409) return new ConflictError(message, init);
  if (status === 422) return new ValidationError(message, { ...init, fields: bodyObj.fields as Record<string, string[]> | undefined });
  if (status === 429) {
    const retryAfter = headers["retry-after"] ? Number(headers["retry-after"]) : undefined;
    return new RateLimitError(message, { ...init, retryAfter });
  }
  if (status >= 500) {
    // A 503 `dependency_unavailable` carries Retry-After (one pool checkout
    // interval); a plain 5xx carries none. Digits only — an HTTP-date is legal
    // but is not delta-seconds, and "retry now" must never be inferred.
    const raw = headers["retry-after"];
    const retryAfter = typeof raw === "string" && /^\d+$/.test(raw.trim()) ? Number(raw.trim()) : undefined;
    return new ServerError(message, { ...init, retryAfter });
  }
  return new KnoxCallError(message, init);
}
