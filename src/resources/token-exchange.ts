// OIDC workload federation — RFC 8693 token exchange against
// `POST /v1/oauth/token` (AIGW-26).
//
// Like `signup`, this is a standalone function and NOT a method on the
// authenticated client, and for a stronger reason: the whole point is that CI
// holds no KnoxCall credential. Constructing a `KnoxCall` client to reach this
// endpoint would require the very secret the flow exists to remove.
//
//   import { exchangeToken } from "@knoxcall/sdk";
//
//   const { access_token } = await exchangeToken(
//     { subject_token: await getGithubActionsIdToken("knoxcall:gateway") },
//     { tenant: "acme" },
//   );
//   // access_token is an agent-kind capability token for POST /v1/ai/...
//
// Supply `resource` — the `resource` field of an MCP server's create/get
// response — to narrow the minted token to `tool` kind, confined to exactly
// that one `/v1/mcp/<slug>` and refused on `/v1/ai`.
//
// THE HOST MATTERS, and getting it wrong looks like a credential failure.
// `/v1/oauth/token` is part of the DATA plane: `src/server.ts` hands `/v1/ai/`,
// `/v1/mcp/` and `/v1/oauth/` to the proxy router only when the request lands
// on a tenant data-plane host (`{slug}.knoxcall.com`, `sandbox-{slug}...`).
// Verified against a running server on 2026-08-25: the same request answers
// 400 `invalid_grant` on `acme.knoxcall.com` and **401** on
// `api.knoxcall.com` — a caller who points this at the management host reads
// that 401 as "my CI token was rejected" when the endpoint is simply not
// served there. So `tenant` (or an explicit `baseUrl`) is REQUIRED: there is
// no safe default to guess.
//
// NOT to be confused with the tenant OAuth 2.1 token endpoint at
// `https://api.knoxcall.com/oauth/token` (root host, no `/v1`), which mints
// `kc_` MANAGEMENT tokens from `client_credentials` and friends. Sending a
// token-exchange grant there is `unsupported_grant_type`, and vice versa.

import { BootstrapError, KnoxCallError, aiGatewayErrorFrom } from "../error.js";
import { isInsecureRemoteUrl, warnOnce } from "../warn.js";

export const TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange";
export const ID_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id_token";
export const KNOXCALL_AUDIENCE = "knoxcall:gateway";

export interface ExchangeTokenInput {
  /**
   * The workload's OIDC id_token, JWS-compact. Its `iss` must match an OIDC
   * binding registered on the tenant, its signature must verify against that
   * issuer's published JWKS, and it must be unexpired.
   */
  subject_token: string;
  /**
   * RFC 8707 resource indicator — the `resource` value from an MCP server's
   * create/get response. Narrows the minted token to `tool` kind and binds the
   * resource into its capability HMAC. Omit for an `agent`-kind token.
   */
  resource?: string;
  /** Defaults to `knoxcall:gateway`; any other value is refused `invalid_target`. */
  audience?: string;
}

/** RFC 8693 §2.2.1 — a bare OAuth body, NOT the `{data, meta}` envelope. */
export interface ExchangeTokenResponse {
  /** The capability token, returned ONCE. */
  access_token: string;
  issued_token_type: "urn:ietf:params:oauth:token-type:access_token";
  token_type: "Bearer";
  /** Lifetime in seconds, from the binding's TTL (server default 900). */
  expires_in: number;
  /**
   * The capability scope, JSON-encoded, for visibility only. The source of
   * truth is the capability HMAC bound into the token.
   */
  scope?: string;
}

/** Options for {@link exchangeToken}. One of `tenant` or `baseUrl` is required. */
export interface ExchangeTokenOptions {
  /**
   * Tenant slug. Resolves to `https://{tenant}.knoxcall.com`, or
   * `https://sandbox-{tenant}.knoxcall.com` when `sandbox` is set — the tenant
   * data-plane hosts, the only ones that serve this endpoint.
   */
  tenant?: string;
  /** Use the Test data space. Ignored when `baseUrl` is given. */
  sandbox?: boolean;
  /** Full data-plane origin. Wins over `tenant`; required for self-hosted. */
  baseUrl?: string;
  fetch?: typeof fetch;
  signal?: AbortSignal;
}

// A tenant slug becomes a hostname, so it must be a bare DNS label. This
// mirrors core.ts's `assertTenantSlug` and exists for the same reason: a slug
// adopted from config or an environment variable that is not one (`evil.com#`)
// would send the workload's OIDC token to an attacker-controlled host.
const TENANT_SLUG_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;

function resolveExchangeBaseUrl(options?: ExchangeTokenOptions): string {
  if (options?.baseUrl) return options.baseUrl.replace(/\/+$/, "");
  const tenant = options?.tenant;
  if (!tenant) {
    throw new BootstrapError(
      "exchangeToken needs a tenant slug or a baseUrl: POST /v1/oauth/token is served only on " +
        "the tenant data-plane host (https://{tenant}.knoxcall.com). Pointing it at " +
        "api.knoxcall.com answers 401, which reads like a rejected subject_token but means the " +
        "endpoint is not there.",
    );
  }
  if (!TENANT_SLUG_RE.test(tenant)) {
    throw new BootstrapError(
      `invalid tenant slug ${JSON.stringify(tenant)} — expected a DNS label; ` +
        "refusing to send a subject token to a host derived from it",
    );
  }
  return options?.sandbox
    ? `https://sandbox-${tenant}.knoxcall.com`
    : `https://${tenant}.knoxcall.com`;
}

/**
 * Exchange a CI OIDC token for a short-lived AI-gateway capability token.
 *
 * Requires no constructed client and no KnoxCall credential: the subject token
 * IS the credential. Failures throw {@link KnoxCallError} carrying the RFC 6749
 * §5.2 `error` code (`invalid_grant`, `invalid_target`,
 * `unsupported_grant_type`, `invalid_request`, `server_error`).
 */
export async function exchangeToken(
  input: ExchangeTokenInput,
  options?: ExchangeTokenOptions,
): Promise<ExchangeTokenResponse> {
  const doFetch = options?.fetch ?? fetch;
  const base = resolveExchangeBaseUrl(options);

  // the request carries the workload OIDC id_token, which IS a credential -- the
  // whole point of the flow. PARITY 15 already warns when a CLIENT is constructed
  // against plaintext http to a non-loopback host, and this function deliberately
  // constructs no client, so without this the control exists on one path and is
  // simply absent on the parallel one. A warning rather than a refusal because the
  // acceptance harness and local dev legitimately use http://127.0.0.1.
  if (isInsecureRemoteUrl(base)) {
    warnOnce(
      "KNOXCALL_INSECURE_TRANSPORT",
      `KnoxCall: exchanging a workload OIDC token over plaintext HTTP to ${base} — the ` +
        "subject token is a credential and is readable on the wire. Use https://.",
    );
  }

  const body: Record<string, string> = {
    grant_type: TOKEN_EXCHANGE_GRANT,
    subject_token: input.subject_token,
    subject_token_type: ID_TOKEN_TYPE,
    audience: input.audience ?? KNOXCALL_AUDIENCE,
  };
  // Only send `resource` when the caller asked for one: an empty string is
  // refused `invalid_target` rather than treated as absent, and rightly so —
  // silently dropping it would mint an UNCONFINED token.
  if (input.resource !== undefined) body.resource = input.resource;

  const res = await doFetch(`${base}/v1/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(body),
    signal: options?.signal,
  });

  let parsed: Partial<ExchangeTokenResponse> & { error?: string; error_description?: string } = {};
  try {
    parsed = (await res.json()) as typeof parsed;
  } catch {
    // Non-JSON body (a proxy error page). Fall through to the status check
    // below rather than masking a 502 as a parse failure.
  }

  if (!res.ok || !parsed.access_token) {
    // AIGW-163: this endpoint is on the TENANT DATA PLANE, so when the AI
    // gateway has failed to boot it is answered by the plane's 503 sentinel —
    // the data-plane envelope with `code: "ai_gateway_unavailable"` and a
    // `Retry-After` — not by an RFC 6749 error. Typing it means a CI job gets
    // "wait 60s and try again" instead of a generic exchange failure. The
    // discriminator is exact: an RFC 6749 body carries no `code` at all.
    const aiErr = aiGatewayErrorFrom(res.status, parsed, res.headers as any);
    if (aiErr) throw aiErr;
    const code = parsed.error ?? "token_exchange_failed";
    const message = parsed.error_description ?? `Token exchange failed with status ${res.status}`;
    throw new KnoxCallError(`${code}: ${message}`, {
      status: res.status,
      code,
      body: parsed,
    });
  }
  return parsed as ExchangeTokenResponse;
}
