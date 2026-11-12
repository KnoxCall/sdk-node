// AI Gateway resource — mirrors src/client-api/ai-gateway.ts
//
// Control-plane for the AI egress gateway: gateways -> agents -> capability
// tokens, plus a usage rollup. Flat methods (listGateways/createAgent/
// mintToken/...) matching this SDK's sub-collection convention (cf. vaults'
// listTokens/tokenize, routes' listActions/createAction).

import type { APIClient } from "../core.js";
import { type Envelope, type Page, type PageParams, iteratePages, unwrap } from "./shared.js";

// ── Gateways ──────────────────────────────────────────────────────────────

/** A gateway row (GET/POST/PATCH /v1/ai-gateway/gateways). */
export interface AIGateway {
  id: string;
  name: string;
  slug: string;
  description: string | null;
  budget_daily_usd: number | null;
  budget_monthly_usd: number | null;
  /** What happens when the gateway's daily/monthly cap is spent (AIGW-150): 'block' refuses on BOTH data planes, 'warn' serves and emits the X-Knox-AI-Budget-* headers. No 'fallback' — that action swaps an agent's route and model, which a gateway does not have. */
  budget_overage_action?: 'block' | 'warn';
  sandbox: boolean;
  created_at: string;
  updated_at: string;
}

export interface CreateGatewayInput {
  name: string;
  slug: string;
  description?: string;
  budget_daily_usd?: number;
  budget_monthly_usd?: number;
  /** What happens when the gateway's daily/monthly cap is spent (AIGW-150): 'block' refuses on BOTH data planes, 'warn' serves and emits the X-Knox-AI-Budget-* headers. No 'fallback' — that action swaps an agent's route and model, which a gateway does not have. Defaults to 'block'. */
  budget_overage_action?: 'block' | 'warn';
}

export interface UpdateGatewayInput {
  name?: string;
  description?: string;
  budget_daily_usd?: number;
  budget_monthly_usd?: number;
  /** What happens when the gateway's daily/monthly cap is spent (AIGW-150): 'block' refuses on BOTH data planes, 'warn' serves and emits the X-Knox-AI-Budget-* headers. No 'fallback' — that action swaps an agent's route and model, which a gateway does not have. */
  budget_overage_action?: 'block' | 'warn';
}

// ── Agents ────────────────────────────────────────────────────────────────

/** An agent row under a gateway. */
export interface AIAgent {
  id: string;
  tenant_id: string;
  gateway_id: string;
  name: string;
  slug: string;
  description: string | null;
  primary_route_id: string | null;
  fallback_route_ids: string[];
  model_allowlist: string[] | null;
  model_denylist: string[] | null;
  default_model: string | null;
  model_rewrite: Record<string, string>;
  budget_daily_usd: number | null;
  budget_monthly_usd: number | null;
  budget_per_call_max_tokens: number | null;
  budget_overage_action: string;
  fallback_agent_id: string | null;
  pii_redact_policy_id: string | null;
  /** AIGW-100: read-only mirror of `pii_response_mode === "detokenize"`. */
  pii_detokenize_response: boolean;
  /** AIGW-100: what happens to the PROMPT before it leaves KnoxCall. */
  pii_request_mode: PiiRequestMode;
  /** AIGW-100: what happens to the provider's answer on the way back. */
  pii_response_mode: PiiResponseMode;
  pii_streaming_holdback_chars: number;
  /**
   * `holdback` | `buffer` | `monitor`. `monitor` reports detections without
   * rewriting the stream, so the raw value reaches the client — read it before
   * concluding a streamed answer was redacted.
   */
  pii_streaming_mode: string;
  /** FinOps attribution labels echoed onto this agent's usage rows. */
  tags: Record<string, string>;
  /**
   * The upstream shape this agent fronts. Set once, at create time, and
   * deliberately not patchable. `null` on an agent whose route shape the
   * backfill did not recognise — render that as "custom", never as a guess.
   */
  provider: string | null;
  cache_mode: string;
  cache_ttl_seconds: number;
  /**
   * `numeric(4,3) NOT NULL` in Postgres, which pg serialises as a STRING --
   * the wire value is `"0.950"`, not `0.95`. Typing it as a number invites
   * `agent.cache_similarity_threshold < 0.9`, which tsc accepts and which
   * compares by coercion, and `.toFixed()` on it throws. The server type
   * (src/ai-gateway/types.ts) and the Go read model both say string.
   */
  cache_similarity_threshold: string;
  cache_embedding_model: string | null;
  streaming_enabled: boolean;
  firewall_policy_id: string | null;
  tool_allowlist: string[];
  output_schema: Record<string, unknown> | null;
  output_validation_action: string;
  data_residency_region: string | null;
  cmek_key_id: string | null;
  status: string;
  paused_reason: string | null;
  /** AIGW-42 routing policy as STORED; the server clamps it on every read. */
  routing_policy: Record<string, unknown>;
  /** AIGW-45. `guardrail_webhook_mode` is the string `"off"` with no hook — never a boolean. */
  guardrail_webhook_url: string | null;
  guardrail_webhook_secret_id: string | null;
  guardrail_webhook_mode: string;
  guardrail_webhook_timeout_ms: number;
  guardrail_webhook_failure_action: string;
  /**
   * The data-plane base URL for this agent —
   * `https://{tenant}.knoxcall.com/v1/ai/{slug}`. Point an AI SDK's `base_url`
   * here and give it a capability token as the API key.
   *
   * Server-computed, not stored: it moves when the agent's `slug` changes. It
   * is an empty string on a deployment where the tenant slug cannot be
   * resolved, so treat an empty value as "not available", never as a URL.
   */
  agent_url: string;
  created_at: string;
  updated_at: string;
  created_by: string | null;
}

/**
 * AIGW-100 — what happens to the PROMPT before it leaves KnoxCall.
 *
 * `tokenize` (the default) replaces detected entities with conversation-scoped,
 * format-preserving tokens before the provider sees them. `off` forwards the
 * prompt exactly as sent, and is the ONLY configuration on which the provider
 * receives the real value.
 *
 * Independent of `pii_response_mode`. Before AIGW-100 request tokenization was
 * gated on the response toggle, so an agent with a PII policy attached and
 * `pii_detokenize_response: false` sent its prompts verbatim.
 */
export type PiiRequestMode = "off" | "tokenize";

/**
 * AIGW-100 — what happens to the provider's answer on the way back.
 *
 * `redact` runs the detector stack (fresh PII in the completion, canary tokens)
 * and leaves `KC_*` tokens as tokens. `detokenize` (the default) also swaps them
 * back to this conversation's originals. There is no `off`: the detector stack
 * runs on every 2xx.
 */
export type PiiResponseMode = "redact" | "detokenize";

/**
 * A provider id the server can compose an upstream route for.
 *
 * Deliberately `string`, not a union. The catalog is server-side and has grown
 * from six to fourteen; an SDK-side enum would reject a provider the API
 * accepts and would need a release to fix (sdk/PARITY.md — "SDKs do not
 * enumerate the list in code"). Pass the string through and surface the
 * server's 400 verbatim, which names the valid set.
 *
 * At the time of writing: `anthropic`, `openai`, `gemini`, `cohere`,
 * `azure-openai`, `ollama`, `groq`, `together`, `mistral`, `deepseek`,
 * `fireworks`, `xai`, `bedrock`, `openai-compatible`.
 *
 * `upstream` is required for the four providers whose endpoint is yours
 * rather than the vendor's: `azure-openai`, `ollama`, `bedrock` and
 * `openai-compatible`. Creating an agent on one of those four without
 * `upstream` is a 400, not a default; `openai-compatible` also needs
 * `default_model`.
 */
export type AIProviderId = string;

export interface CreateAgentInput {
  name: string;
  slug: string;
  description?: string;
  /**
   * The route carrying the upstream provider credential. Supply this OR
   * `provider`, never both (400) — and supplying NEITHER creates an agent
   * with no upstream, whose first data-plane call 502s.
   */
  primary_route_id?: string;
  /**
   * Compose the upstream route instead of supplying `primary_route_id`:
   * KnoxCall creates an `ai-gateway-<slug>` route for this provider,
   * injecting `upstream_secret_id` through the envelope store, and sets
   * `default_model` from its pricebook default.
   *
   * The route is created in the CALLING KEY's data space, because a token
   * minted in one environment is refused against a route in the other.
   */
  provider?: AIProviderId;
  /**
   * REQUIRED with `provider`: the KnoxCall secret holding your provider key.
   * Referenced, never copied — the composed route injects
   * `{{secret_id:<uuid>}}` and the data plane resolves it at call time.
   */
  upstream_secret_id?: string;
  /**
   * Upstream base URL, required for the four providers whose endpoint is
   * yours rather than the vendor's: `azure-openai`, `ollama`, `bedrock` and
   * `openai-compatible`. Ignored for the rest, whose origin is fixed.
   *
   * It is not defaulted: a `bedrock` or `openai-compatible` agent created
   * without `upstream` is refused with a 400 at create time.
   */
  upstream?: string;
  default_model?: string;
  model_allowlist?: string[];
  model_denylist?: string[];
  budget_daily_usd?: number;
  budget_monthly_usd?: number;
  streaming_enabled?: boolean;
  firewall_policy_id?: string;
  pii_redact_policy_id?: string;
  /**
   * AIGW-100. Defaults to `tokenize`. Set `off` only when the payload must
   * reach the provider byte-for-byte (structured tool-use JSON, say) — it means
   * prompts are forwarded unscanned.
   */
  pii_request_mode?: PiiRequestMode;
  /** AIGW-100. Defaults to `detokenize`. */
  pii_response_mode?: PiiResponseMode;
  /**
   * @deprecated AIGW-100 legacy alias for `pii_response_mode` (`true` ->
   * `"detokenize"`, `false` -> `"redact"`). Still accepted; sending both with
   * contradictory values is a 400.
   */
  pii_detokenize_response?: boolean;

  // Everything below is accepted at CREATE and was reachable only by a
  // follow-up PATCH until 2026-09-15. A field that needs create-then-patch
  // cannot be set declaratively: the second call can fail and leave an agent
  // that is not what the caller asked for.
  fallback_route_ids?: string[];
  /** Map of requested model -> substituted model. */
  model_rewrite?: Record<string, string>;
  budget_per_call_max_tokens?: number;
  /** `fallback` needs `fallback_agent_id`, or the overage behaves as `block`. */
  budget_overage_action?: "block" | "warn" | "fallback";
  fallback_agent_id?: string;
  pii_streaming_holdback_chars?: number;
  /**
   * How a STREAMED answer is rewritten. `monitor` REPORTS detections without
   * rewriting, so the raw value reaches the client — observability, not
   * redaction.
   */
  pii_streaming_mode?: "holdback" | "buffer" | "monitor";
  /** FinOps attribution labels echoed onto this agent's usage rows. */
  tags?: Record<string, string>;
  /** `semantic` additionally needs `cache_embedding_model`. */
  cache_mode?: "off" | "exact" | "semantic";
  cache_ttl_seconds?: number;
  /** Cosine floor for a semantic hit, 0–1. Lower means more hits, and more wrong ones. */
  cache_similarity_threshold?: number;
  cache_embedding_model?: string;
  tool_allowlist?: string[];
  /** JSON Schema the answer is validated against. */
  output_schema?: Record<string, unknown>;
  output_validation_action?: "block" | "retry" | "warn";
  /** One of us|eu|uk|ca|au|jp|in — not a cloud region id; anything else is a 400. */
  data_residency_region?: string;
  cmek_key_id?: string;
  /** AIGW-42 retry/fail-over policy. The server normalises and CLAMPS it. */
  routing_policy?: Record<string, unknown>;
  /**
   * AIGW-45. The destination is resolved and refused at write time AND on every
   * call, so a private, loopback, link-local or cloud-metadata address is a 400.
   */
  guardrail_webhook_url?: string;
  guardrail_webhook_secret_id?: string;
  guardrail_webhook_mode?: string;
  guardrail_webhook_timeout_ms?: number;
  guardrail_webhook_failure_action?: string;
}

/**
 * The PATCH …/agents/{id} body.
 *
 * Deliberately NOT `Partial<CreateAgentInput>`, which it was until 2026-09-12
 * and which was wrong in both directions. It offered `provider`,
 * `upstream_secret_id` and `upstream` — create-only fields the server's
 * `UPDATABLE_COLUMNS` does not contain, so TypeScript approved a patch that
 * silently did nothing — and it omitted 23 columns the server does update,
 * including every `cache_*`, `tags`, `output_schema` and the whole guardrail
 * webhook. A typed input is the only thing between a caller and a server
 * capability, so a field missing here is a feature this SDK does not have.
 *
 * Pinned from the server side by
 * `tests/coverage/ai-gateway-sdk-typed-patch-parity.test.ts`.
 */
export interface UpdateAgentInput {
  name?: string;
  /**
   * RENAMES the agent, which MOVES its data-plane URL: `agent_url` is computed
   * from the slug rather than stored, so every caller pointed at the old URL
   * gets a 404 from the moment this resolves. The new URL is on the response.
   */
  slug?: string;
  description?: string | null;
  primary_route_id?: string | null;
  fallback_route_ids?: string[];
  model_allowlist?: string[];
  model_denylist?: string[];
  default_model?: string | null;
  /** Map of requested model -> substituted model. */
  model_rewrite?: Record<string, string>;
  budget_daily_usd?: number | null;
  budget_monthly_usd?: number | null;
  budget_per_call_max_tokens?: number | null;
  /**
   * `fallback` needs `fallback_agent_id`; without one the overage behaves as
   * `block`.
   */
  budget_overage_action?: "block" | "warn" | "fallback";
  fallback_agent_id?: string | null;
  pii_redact_policy_id?: string | null;
  /**
   * AIGW-100. What happens to the PROMPT before it leaves KnoxCall. `off` is
   * the only mode on which the provider receives the real value.
   */
  pii_request_mode?: PiiRequestMode;
  /** AIGW-100. What happens to the provider's answer on the way back. */
  pii_response_mode?: PiiResponseMode;
  /**
   * @deprecated AIGW-100 legacy alias for `pii_response_mode`. Sending both
   * with contradictory values is a 400.
   */
  pii_detokenize_response?: boolean;
  pii_streaming_holdback_chars?: number;
  /**
   * How a STREAMED answer is rewritten. `monitor` REPORTS detections without
   * rewriting, so the raw value reaches the client — an observability mode,
   * not a redaction one.
   */
  pii_streaming_mode?: "holdback" | "buffer" | "monitor";
  /** FinOps attribution labels echoed onto this agent's usage rows. */
  tags?: Record<string, string>;
  /** `semantic` additionally needs `cache_embedding_model`. */
  cache_mode?: "off" | "exact" | "semantic";
  cache_ttl_seconds?: number;
  /** Cosine floor for a semantic hit, 0–1. Lower means more hits, and more wrong ones. */
  cache_similarity_threshold?: number;
  cache_embedding_model?: string | null;
  streaming_enabled?: boolean;
  firewall_policy_id?: string | null;
  tool_allowlist?: string[];
  /** JSON Schema the answer is validated against. */
  output_schema?: Record<string, unknown> | null;
  output_validation_action?: "block" | "retry" | "warn";
  data_residency_region?: string | null;
  cmek_key_id?: string | null;
  /** AIGW-42 retry/fail-over policy. The server normalises and CLAMPS it. */
  routing_policy?: Record<string, unknown>;
  /**
   * AIGW-45. The destination is resolved and refused at write time AND on
   * every call, so a private, loopback, link-local or cloud-metadata address
   * is a 400 here.
   */
  guardrail_webhook_url?: string | null;
  guardrail_webhook_secret_id?: string | null;
  guardrail_webhook_mode?: string;
  guardrail_webhook_timeout_ms?: number;
  guardrail_webhook_failure_action?: string;
}

// ── MCP servers ───────────────────────────────────────────────────────────

/**
 * An MCP server KnoxCall proxies and governs.
 *
 * `connect_url` and `resource` are deliberately DIFFERENT values: `connect_url`
 * is where an MCP client points (the tenant data-plane host), `resource` is the
 * RFC 8707 value a token for this server must be bound to.
 */
/**
 * One person's delegated-OAuth connection to an MCP server (AIGW-190).
 *
 * NEVER carries the stored tokens: `has_refresh_token` is the only thing said
 * about them. A listing that carried ciphertext would be a listing whose next
 * reader has to remember not to log it.
 */
export interface AIMcpGrant {
  id: string;
  /** The tenant directory row this connection belongs to. */
  attributed_user_id: string;
  external_id: string;
  display_name?: string | null;
  scopes: string[];
  status: "active" | "revoked";
  created_at: string;
  last_refreshed_at?: string | null;
  last_used_at?: string | null;
  has_refresh_token: boolean;
}

export interface AIMcpServer {
  /**
   * AIGW-151: the tenant PII policy whose recognizers apply to this server's
   * tool arguments and results. Null = every enabled recognizer this tenant
   * owns, on top of the built-ins. A policy id you do not own is refused 422.
   */
  pii_redact_policy_id?: string | null;
  firewall_policy_id?: string | null;
  /**
   * AIGW-150: the tenant's own external scanner. https only, no embedded
   * credentials, SSRF-checked. `guardrail_webhook_mode` picks the directions:
   * `request` sees the tool ARGUMENTS after redaction and before they leave,
   * `response` sees the tool RESULT before it is returned. There is no
   * streaming carve-out on this plane — every JSON-RPC message is materialised.
   */
  guardrail_webhook_url?: string | null;
  guardrail_webhook_secret_id?: string | null;
  guardrail_webhook_mode?: 'off' | 'request' | 'response' | 'both';
  guardrail_webhook_timeout_ms?: number;
  guardrail_webhook_failure_action?: 'fail_open' | 'fail_closed';
  /**
   * AIGW-152: which Live/Test space this server lives in. READ-ONLY — it comes
   * from the mode of the request that created it, and there is deliberately no
   * way to set it. Reads and writes are confined to the calling key's own space,
   * a capability token reaches only servers in its own space (a `kp_test_` token
   * against a Live server is a 404), and the same slug may exist in both.
   */
  sandbox?: boolean;
  id: string;
  gateway_id: string | null;
  name: string;
  slug: string | null;
  description: string | null;
  /** Only `upstream` can be created today; `collection` is not served yet. */
  server_type: "upstream" | "collection";
  transport: "streamable_http" | "sse" | null;
  upstream_url: string | null;
  /** EMPTY means this server advertises NOTHING. */
  allowed_tools: string[];
  pii_inspection: boolean;
  /** Only `{{secret_id:…}}` references — never a credential. */
  auth: Record<string, unknown>;
  status: string;
  created_at: string;
  updated_at: string;
  connect_url: string;
  resource: string;
}

export interface CreateMcpServerInput {
  /**
   * AIGW-151: the tenant PII policy whose recognizers apply to this server's
   * tool arguments and results. Null = every enabled recognizer this tenant
   * owns, on top of the built-ins. A policy id you do not own is refused 422.
   */
  pii_redact_policy_id?: string | null;
  firewall_policy_id?: string | null;
  /**
   * AIGW-150: the tenant's own external scanner. https only, no embedded
   * credentials, SSRF-checked. `guardrail_webhook_mode` picks the directions:
   * `request` sees the tool ARGUMENTS after redaction and before they leave,
   * `response` sees the tool RESULT before it is returned. There is no
   * streaming carve-out on this plane — every JSON-RPC message is materialised.
   */
  guardrail_webhook_url?: string | null;
  guardrail_webhook_secret_id?: string | null;
  guardrail_webhook_mode?: 'off' | 'request' | 'response' | 'both';
  guardrail_webhook_timeout_ms?: number;
  guardrail_webhook_failure_action?: 'fail_open' | 'fail_closed';
  name: string;
  slug: string;
  /**
   * A public `https://` MCP endpoint. Private, loopback, link-local and
   * cloud-metadata destinations are refused — the request carries your
   * decrypted upstream credential.
   */
  upstream_url: string;
  description?: string;
  transport?: "streamable_http" | "sse";
  /** Empty (the default) means the server advertises nothing. */
  allowed_tools?: string[];
  pii_inspection?: boolean;
  /**
   * Upstream auth. Every header value must reference a KnoxCall secret, e.g.
   * `{ headers: { Authorization: "Bearer {{secret_id:<uuid>}}" } }`. A literal
   * credential is refused with 422.
   */
  auth?: { headers?: Record<string, string>; environment_name?: string };
}

export interface UpdateMcpServerInput {
  /**
   * AIGW-151: the tenant PII policy whose recognizers apply to this server's
   * tool arguments and results. Null = every enabled recognizer this tenant
   * owns, on top of the built-ins. A policy id you do not own is refused 422.
   */
  pii_redact_policy_id?: string | null;
  firewall_policy_id?: string | null;
  /**
   * AIGW-150: the tenant's own external scanner. https only, no embedded
   * credentials, SSRF-checked. `guardrail_webhook_mode` picks the directions:
   * `request` sees the tool ARGUMENTS after redaction and before they leave,
   * `response` sees the tool RESULT before it is returned. There is no
   * streaming carve-out on this plane — every JSON-RPC message is materialised.
   */
  guardrail_webhook_url?: string | null;
  guardrail_webhook_secret_id?: string | null;
  guardrail_webhook_mode?: 'off' | 'request' | 'response' | 'both';
  guardrail_webhook_timeout_ms?: number;
  guardrail_webhook_failure_action?: 'fail_open' | 'fail_closed';
  name?: string;
  description?: string;
  upstream_url?: string;
  transport?: "streamable_http" | "sse";
  allowed_tools?: string[];
  pii_inspection?: boolean;
  auth?: { headers?: Record<string, string>; environment_name?: string };
  /** `active` | `paused`. Use `deleteMcpServer` to archive. */
  status?: "active" | "paused";
}

/** A tool metadata row. It does not widen what the server advertises. */
export interface AIMcpTool {
  id: string;
  mcp_server_id: string;
  tool_name: string;
  route_id: string | null;
  description: string | null;
  input_schema: Record<string, unknown>;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface UpsertMcpToolInput {
  tool_name: string;
  description?: string;
  input_schema?: Record<string, unknown>;
  enabled?: boolean;
}

export interface UpdateMcpToolInput {
  description?: string;
  input_schema?: Record<string, unknown>;
  enabled?: boolean;
}

// ── Tokens ────────────────────────────────────────────────────────────────

/** Capability-token kinds an agent can mint. */
export type AIGatewayTokenKind = "agent" | "read" | "tool" | "oneshot";

/** Row returned by GET .../tokens — NEVER carries the plaintext token. */
export interface AIGatewayTokenListItem {
  id: string;
  name: string | null;
  kind: AIGatewayTokenKind;
  prefix: string;
  dpop_required: boolean;
  expires_at: string | null;
  created_at: string;
  revoked_at: string | null;
}

export interface MintTokenInput {
  name?: string;
  kind?: AIGatewayTokenKind;
  dpop_required?: boolean;
  dpop_jkt?: string;
  /** Defaults to 30 days when omitted; clamped to [60s, 90d]. A non-expiring token cannot be minted. */
  expires_in_seconds?: number;
}

/** POST .../tokens response — `token` is the plaintext, shown ONCE. */
export interface MintTokenResponse {
  id: string;
  name?: string | null;
  kind: AIGatewayTokenKind;
  prefix: string;
  token: string;
  dpop_required: boolean;
  expires_at: string | null;
}

// ── Usage ─────────────────────────────────────────────────────────────────

/** Query params for the usage rollup. */
export interface UsageParams {
  period?: "7d" | "30d" | "90d";
  agent_id?: string;
}

export interface AIGatewayUsageByModel {
  provider: string;
  model: string;
  requests: number;
  input_tokens: number;
  output_tokens: number;
  cost_usd: number;
  unpriced_requests: number;
}

export interface AIGatewayUsageTotals {
  requests: number;
  input_tokens: number;
  output_tokens: number;
  cost_usd: number;
  unpriced_requests: number;
}

/** One row of a FinOps usage export. */
export interface AIGatewayUsageExportRow {
  group: string | null;
  requests: number;
  input_tokens: number;
  output_tokens: number;
  cost_usd: number;
  unpriced_requests: number;
}

export interface AIGatewayUsageExport {
  group_by: string;
  period_days: number;
  rows: AIGatewayUsageExportRow[];
}

export interface AIGatewayUsage {
  period_days: number;
  by_model: AIGatewayUsageByModel[];
  totals: AIGatewayUsageTotals;
}

// ── Firewall policies ─────────────────────────────────────────────────────

/**
 * One heuristic rule inside a firewall policy.
 *
 * `regex` patterns are compiled server-side with a linear-time engine, so
 * lookahead, lookbehind and backreferences are rejected at write time (400)
 * rather than stored and silently skipped when the policy runs.
 */
export interface FirewallRule {
  name: string;
  kind: "regex" | "keyword";
  pattern: string;
  /** Only i, m, s, g, y. Defaults to `i`. Ignored for `keyword`. */
  flags?: string;
}

/**
 * A tenant-scoped prompt-firewall policy, attachable to agents
 * (`firewall_policy_id`) and MCP servers.
 *
 * An agent with NO policy still runs the built-in prompt-injection patterns,
 * but its outcome can never exceed `warn`. Attach a policy with
 * `action: "block"` to have matching requests refused with HTTP 400
 * `firewall_block` on the data plane.
 */
export interface FirewallPolicy {
  id: string;
  tenant_id: string;
  name: string;
  /** Bumped when a policy is re-created under the same name. */
  version: number;
  heuristics: FirewallRule[];
  canary_enabled: boolean;
  vector_classifier_enabled: boolean;
  lakera_enabled: boolean;
  model_classifier_id: string | null;
  action: "block" | "warn" | "tag";
  created_at: string;
}

export interface CreateFirewallPolicyInput {
  /** 2-64 chars. Re-using an existing name creates the next version. */
  name: string;
  heuristics?: FirewallRule[];
  canary_enabled?: boolean;
  action?: "block" | "warn" | "tag";
}

export interface UpdateFirewallPolicyInput {
  heuristics?: FirewallRule[];
  canary_enabled?: boolean;
  action?: "block" | "warn" | "tag";
}

export interface FirewallTestResult {
  matched: boolean;
  matches: Array<{ rule: string; span: [number, number]; matched: string }>;
  /** Rules that could not be compiled and so did not run. Always empty here. */
  skipped: Array<{ rule: string; reason: string }>;
}

// ── PII policies and recognizers ──────────────────────────────────────────

/**
 * What a detector does when it matches.
 *
 * `redact` replaces the value with a placeholder; `tokenize` swaps it for a
 * reversible token the gateway can restore in the response; `warn` records the
 * hit and forwards the value unchanged; `whitelist` exempts the shape from
 * every other detector — a whitelist pattern that matches arbitrary text is a
 * kill switch for the built-in tier, so the server refuses one.
 */
export type PiiAction = "redact" | "tokenize" | "whitelist" | "warn";

/**
 * How a recognizer is executed. `regex` and `aho_corasick` run in-process;
 * the three `presidio_*` kinds are handed to a Presidio sidecar.
 */
export type PiiRecognizerKind =
  | "regex"
  | "aho_corasick"
  | "presidio_pattern"
  | "presidio_ner"
  | "presidio_custom";

/**
 * A tenant-scoped bundle of recognizers plus a default action, attached to an
 * agent through `pii_redact_policy_id`.
 *
 * An EMPTY `recognizer_ids` does not mean "no recognizers" — it means "every
 * enabled recognizer this tenant owns". That is why the server refuses to
 * delete a recognizer a policy still lists: dropping the last id would widen
 * the policy rather than shrink it.
 */
export interface PiiPolicy {
  id: string;
  tenant_id: string;
  name: string;
  version: number;
  recognizer_ids: string[];
  default_action: PiiAction;
  description: string | null;
  created_at: string;
}

export interface CreatePiiPolicyInput {
  /** 2-64 chars (letters, digits, space, underscore, hyphen). Unique per tenant. */
  name: string;
  /**
   * Recognizer ids this tenant owns. A foreign or unknown id is a 400
   * `recognizer_not_found` — stored, it would resolve to nothing at scan time
   * and the policy would silently run fewer detectors than it lists.
   *
   * Omit or pass `[]` for "every enabled recognizer".
   */
  recognizer_ids?: string[];
  /** Default `redact`. */
  default_action?: PiiAction;
  description?: string;
}

export interface UpdatePiiPolicyInput {
  recognizer_ids?: string[];
  default_action?: PiiAction;
  description?: string;
}

/** A tenant's custom PII detector. */
export interface PiiRecognizer {
  id: string;
  tenant_id: string;
  name: string;
  kind: PiiRecognizerKind;
  pattern: string;
  /** Words that must appear nearby for a match to count. */
  context_words: string[];
  confidence: number;
  action: PiiAction;
  /** Token format for `tokenize`; null for the rest. */
  format: string | null;
  /** False mutes the recognizer without losing its definition. */
  enabled: boolean;
  created_at: string;
}

export interface CreatePiiRecognizerInput {
  name: string;
  kind: PiiRecognizerKind;
  /**
   * Compiled server-side with a linear-time engine for `kind: "regex"`, so
   * lookahead, lookbehind and backreferences are a 400 here rather than a
   * recognizer that is skipped at scan time (fail-open).
   */
  pattern: string;
  context_words?: string[];
  /** 0-1, default 0.85. */
  confidence?: number;
  action?: PiiAction;
  format?: string | null;
  enabled?: boolean;
}

export type UpdatePiiRecognizerInput = Partial<CreatePiiRecognizerInput>;

export interface PiiRecognizerTestResult {
  matched: boolean;
  matches: Array<{
    span: [number, number];
    matched: string;
    replacement: string;
    entity_type: string;
  }>;
}

// ── Resource ──────────────────────────────────────────────────────────────

export class AIGatewayResource {
  constructor(private readonly client: APIClient) {}

  // ── Gateways ──────────────────────────────────────────────────────────────

  /** List gateways (paginated). */
  async listGateways(params?: PageParams): Promise<Page<AIGateway>> {
    return this.client.request<Page<AIGateway>>({
      method: "GET",
      path: "/v1/ai-gateway/gateways",
      query: params as Record<string, string | number | undefined>,
    });
  }

  /** Iterate every gateway across all pages. */
  iterateGateways(params?: PageParams): AsyncIterableIterator<AIGateway> {
    return iteratePages((page) => this.listGateways({ ...params, page }), params?.page ?? 1);
  }

  /** Create a gateway. */
  async createGateway(input: CreateGatewayInput, opts?: { idempotencyKey?: string }): Promise<AIGateway> {
    return unwrap(await this.client.request<Envelope<AIGateway>>({
      method: "POST",
      path: "/v1/ai-gateway/gateways",
      body: input,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  /** Fetch one gateway by id. */
  async getGateway(id: string): Promise<AIGateway> {
    return unwrap(await this.client.request<Envelope<AIGateway>>({
      method: "GET",
      path: `/v1/ai-gateway/gateways/${encodeURIComponent(id)}`,
    }));
  }

  /** Update a gateway. */
  async updateGateway(id: string, input: UpdateGatewayInput, opts?: { idempotencyKey?: string }): Promise<AIGateway> {
    return unwrap(await this.client.request<Envelope<AIGateway>>({
      method: "PATCH",
      path: `/v1/ai-gateway/gateways/${encodeURIComponent(id)}`,
      body: input,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  /** Delete a gateway. */
  async deleteGateway(id: string, opts?: { idempotencyKey?: string }): Promise<{ id: string; status: string }> {
    return unwrap(await this.client.request<Envelope<{ id: string; status: string }>>({
      method: "DELETE",
      path: `/v1/ai-gateway/gateways/${encodeURIComponent(id)}`,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  // ── Agents ──────────────────────────────────────────────────────────────

  /** List a gateway's agents (paginated). */
  async listAgents(gatewayId: string, params?: PageParams): Promise<Page<AIAgent>> {
    return this.client.request<Page<AIAgent>>({
      method: "GET",
      path: `/v1/ai-gateway/gateways/${encodeURIComponent(gatewayId)}/agents`,
      query: params as Record<string, string | number | undefined>,
    });
  }

  /** Iterate a gateway's agents across all pages. */
  iterateAgents(gatewayId: string, params?: PageParams): AsyncIterableIterator<AIAgent> {
    return iteratePages((page) => this.listAgents(gatewayId, { ...params, page }), params?.page ?? 1);
  }

  /** Create an agent under a gateway. */
  async createAgent(gatewayId: string, input: CreateAgentInput, opts?: { idempotencyKey?: string }): Promise<AIAgent> {
    return unwrap(await this.client.request<Envelope<AIAgent>>({
      method: "POST",
      path: `/v1/ai-gateway/gateways/${encodeURIComponent(gatewayId)}/agents`,
      body: input,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  /** Fetch one agent by id (flat path, not nested under its gateway). */
  async getAgent(agentId: string): Promise<AIAgent> {
    return unwrap(await this.client.request<Envelope<AIAgent>>({
      method: "GET",
      path: `/v1/ai-gateway/agents/${encodeURIComponent(agentId)}`,
    }));
  }

  /** Update an agent. */
  async updateAgent(agentId: string, input: UpdateAgentInput, opts?: { idempotencyKey?: string }): Promise<AIAgent> {
    return unwrap(await this.client.request<Envelope<AIAgent>>({
      method: "PATCH",
      path: `/v1/ai-gateway/agents/${encodeURIComponent(agentId)}`,
      body: input,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  /** Delete an agent. */
  async deleteAgent(agentId: string, opts?: { idempotencyKey?: string }): Promise<{ id: string; status: string }> {
    return unwrap(await this.client.request<Envelope<{ id: string; status: string }>>({
      method: "DELETE",
      path: `/v1/ai-gateway/agents/${encodeURIComponent(agentId)}`,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  // ── MCP servers ─────────────────────────────────────────────────────────

  /** List a gateway's MCP servers (paginated). */
  async listMcpServers(gatewayId: string, params?: PageParams): Promise<Page<AIMcpServer>> {
    return this.client.request<Page<AIMcpServer>>({
      method: "GET",
      path: `/v1/ai-gateway/gateways/${encodeURIComponent(gatewayId)}/mcp-servers`,
      query: params as Record<string, string | number | undefined>,
    });
  }

  /** Iterate a gateway's MCP servers across all pages. */
  iterateMcpServers(gatewayId: string, params?: PageParams): AsyncIterableIterator<AIMcpServer> {
    return iteratePages((page) => this.listMcpServers(gatewayId, { ...params, page }), params?.page ?? 1);
  }

  /**
   * Register an upstream MCP server under a gateway.
   *
   * `server_type: 'collection'` is not accepted — the data plane does not serve
   * it yet, so a server of that type would fail on every call.
   */
  async createMcpServer(gatewayId: string, input: CreateMcpServerInput, opts?: { idempotencyKey?: string }): Promise<AIMcpServer> {
    return unwrap(await this.client.request<Envelope<AIMcpServer>>({
      method: "POST",
      path: `/v1/ai-gateway/gateways/${encodeURIComponent(gatewayId)}/mcp-servers`,
      body: input,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  /** Fetch one MCP server by id (flat path, not nested under its gateway). */
  async getMcpServer(serverId: string): Promise<AIMcpServer> {
    return unwrap(await this.client.request<Envelope<AIMcpServer>>({
      method: "GET",
      path: `/v1/ai-gateway/mcp-servers/${encodeURIComponent(serverId)}`,
    }));
  }

  /** Update an MCP server (allowlist, upstream, auth, status). */
  async updateMcpServer(serverId: string, input: UpdateMcpServerInput, opts?: { idempotencyKey?: string }): Promise<AIMcpServer> {
    return unwrap(await this.client.request<Envelope<AIMcpServer>>({
      method: "PATCH",
      path: `/v1/ai-gateway/mcp-servers/${encodeURIComponent(serverId)}`,
      body: input,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  /** Archive (soft-delete) an MCP server. */
  async deleteMcpServer(serverId: string, opts?: { idempotencyKey?: string }): Promise<{ id: string; status: string }> {
    return unwrap(await this.client.request<Envelope<{ id: string; status: string }>>({
      method: "DELETE",
      path: `/v1/ai-gateway/mcp-servers/${encodeURIComponent(serverId)}`,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  // ── MCP tools ───────────────────────────────────────────────────────────

  /**
   * List an MCP server's tool rows (paginated).
   *
   * Tool rows are metadata. What a client can call is the intersection of the
   * server's `allowed_tools`, the upstream's real tools, and the token's own
   * tool scope.
   */
  async listMcpTools(serverId: string, params?: PageParams): Promise<Page<AIMcpTool>> {
    return this.client.request<Page<AIMcpTool>>({
      method: "GET",
      path: `/v1/ai-gateway/mcp-servers/${encodeURIComponent(serverId)}/tools`,
      query: params as Record<string, string | number | undefined>,
    });
  }

  /** Iterate an MCP server's tool rows across all pages. */
  iterateMcpTools(serverId: string, params?: PageParams): AsyncIterableIterator<AIMcpTool> {
    return iteratePages((page) => this.listMcpTools(serverId, { ...params, page }), params?.page ?? 1);
  }

  /** Insert or update a tool row by `tool_name`. */
  async upsertMcpTool(serverId: string, input: UpsertMcpToolInput, opts?: { idempotencyKey?: string }): Promise<AIMcpTool> {
    return unwrap(await this.client.request<Envelope<AIMcpTool>>({
      method: "POST",
      path: `/v1/ai-gateway/mcp-servers/${encodeURIComponent(serverId)}/tools`,
      body: input,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  /** Enable, disable or re-describe a tool row. */
  async updateMcpTool(serverId: string, toolId: string, input: UpdateMcpToolInput, opts?: { idempotencyKey?: string }): Promise<AIMcpTool> {
    return unwrap(await this.client.request<Envelope<AIMcpTool>>({
      method: "PATCH",
      path: `/v1/ai-gateway/mcp-servers/${encodeURIComponent(serverId)}/tools/${encodeURIComponent(toolId)}`,
      body: input,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  /** Delete a tool row. */
  async deleteMcpTool(serverId: string, toolId: string, opts?: { idempotencyKey?: string }): Promise<{ id: string; deleted: boolean }> {
    return unwrap(await this.client.request<Envelope<{ id: string; deleted: boolean }>>({
      method: "DELETE",
      path: `/v1/ai-gateway/mcp-servers/${encodeURIComponent(serverId)}/tools/${encodeURIComponent(toolId)}`,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  // ── Delegated-OAuth connections (AIGW-190) ──────────────────────────────
  //
  // A connection holds ONE person's upstream refresh token, envelope-encrypted
  // under the tenant key. Nothing here returns it, redacted or otherwise.
  //
  // There is deliberately no `connectMcpServer`: consent has to be given by the
  // person whose credential it is, so the flow starts from a signed-in KnoxCall
  // session in the admin console. An API key is not a person — a "connect for
  // alice@acme" call would let the key holder finish the flow with their OWN
  // upstream account and produce a grant under Alice's name.

  /** List who has connected their upstream account to this MCP server (paginated). */
  async listMcpGrants(serverId: string, params?: PageParams): Promise<Page<AIMcpGrant>> {
    return this.client.request<Page<AIMcpGrant>>({
      method: "GET",
      path: `/v1/ai-gateway/mcp-servers/${encodeURIComponent(serverId)}/grants`,
      query: params as Record<string, string | number | undefined>,
    });
  }

  /** Iterate this MCP server's connections across all pages. */
  iterateMcpGrants(serverId: string, params?: PageParams): AsyncIterableIterator<AIMcpGrant> {
    return iteratePages((page) => this.listMcpGrants(serverId, { ...params, page }), params?.page ?? 1);
  }

  /** Revoke ONE person's connection. The stored tokens are destroyed, not flagged. */
  async revokeMcpGrant(serverId: string, grantId: string, opts?: { idempotencyKey?: string }): Promise<{ id: string; status: string }> {
    return unwrap(await this.client.request<Envelope<{ id: string; status: string }>>({
      method: "DELETE",
      path: `/v1/ai-gateway/mcp-servers/${encodeURIComponent(serverId)}/grants/${encodeURIComponent(grantId)}`,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  /** Revoke EVERY connection on this server — the offboarding-in-one-call shape. */
  async revokeAllMcpGrants(serverId: string, opts?: { idempotencyKey?: string }): Promise<{ id: string; revoked: number }> {
    return unwrap(await this.client.request<Envelope<{ id: string; revoked: number }>>({
      method: "DELETE",
      path: `/v1/ai-gateway/mcp-servers/${encodeURIComponent(serverId)}/grants`,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  // ── Tokens ──────────────────────────────────────────────────────────────

  /** List an agent's capability tokens (paginated; never returns plaintext). */
  async listTokens(agentId: string, params?: PageParams): Promise<Page<AIGatewayTokenListItem>> {
    return this.client.request<Page<AIGatewayTokenListItem>>({
      method: "GET",
      path: `/v1/ai-gateway/agents/${encodeURIComponent(agentId)}/tokens`,
      query: params as Record<string, string | number | undefined>,
    });
  }

  /** Iterate an agent's tokens across all pages. */
  iterateTokens(agentId: string, params?: PageParams): AsyncIterableIterator<AIGatewayTokenListItem> {
    return iteratePages((page) => this.listTokens(agentId, { ...params, page }), params?.page ?? 1);
  }

  /**
   * Mint a capability token for an agent. The response `token` is the
   * plaintext and is shown ONCE — persist it at the call site.
   */
  async mintToken(agentId: string, input?: MintTokenInput, opts?: { idempotencyKey?: string }): Promise<MintTokenResponse> {
    return unwrap(await this.client.request<Envelope<MintTokenResponse>>({
      method: "POST",
      path: `/v1/ai-gateway/agents/${encodeURIComponent(agentId)}/tokens`,
      body: input ?? {},
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  /** Revoke a capability token. */
  async revokeToken(agentId: string, tokenId: string, opts?: { idempotencyKey?: string }): Promise<{ id: string; revoked: true }> {
    return unwrap(await this.client.request<Envelope<{ id: string; revoked: true }>>({
      method: "DELETE",
      path: `/v1/ai-gateway/agents/${encodeURIComponent(agentId)}/tokens/${encodeURIComponent(tokenId)}`,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  // ── Firewall policies ──────────────────────────────────────────────────

  /** List prompt-firewall policies (paginated). Tenant-scoped, not per gateway. */
  async listFirewallPolicies(params?: PageParams): Promise<Page<FirewallPolicy>> {
    return this.client.request<Page<FirewallPolicy>>({
      method: "GET",
      path: "/v1/ai-gateway/firewall-policies",
      query: params as Record<string, string | number | undefined>,
    });
  }

  /**
   * Every token under a gateway, INCLUDING gateway-level tokens with no agent —
   * the shape `POST /v1/oauth/token` mints for MCP. `listTokens` filters on the
   * agent, so it cannot see them. Plaintext is never returned.
   */
  async listGatewayTokens(gatewayId: string, params?: PageParams): Promise<Page<AIGatewayTokenListItem>> {
    return this.client.request<Page<AIGatewayTokenListItem>>({
      method: "GET",
      path: `/v1/ai-gateway/gateways/${encodeURIComponent(gatewayId)}/tokens`,
      query: params as Record<string, string | number | undefined>,
    });
  }

  /** Iterate every firewall policy across all pages. */
  iterateFirewallPolicies(params?: PageParams): AsyncIterableIterator<FirewallPolicy> {
    return iteratePages((page) => this.listFirewallPolicies({ ...params, page }), params?.page ?? 1);
  }

  /** Create a firewall policy. Re-using an existing name creates version N+1. */
  async createFirewallPolicy(input: CreateFirewallPolicyInput, opts?: { idempotencyKey?: string }): Promise<FirewallPolicy> {
    return unwrap(await this.client.request<Envelope<FirewallPolicy>>({
      method: "POST",
      path: "/v1/ai-gateway/firewall-policies",
      body: input,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  /** Fetch one firewall policy by id. */
  async getFirewallPolicy(id: string): Promise<FirewallPolicy> {
    return unwrap(await this.client.request<Envelope<FirewallPolicy>>({
      method: "GET",
      path: `/v1/ai-gateway/firewall-policies/${encodeURIComponent(id)}`,
    }));
  }

  /** Update a firewall policy in place (the version is not bumped). */
  async updateFirewallPolicy(id: string, input: UpdateFirewallPolicyInput, opts?: { idempotencyKey?: string }): Promise<FirewallPolicy> {
    return unwrap(await this.client.request<Envelope<FirewallPolicy>>({
      method: "PATCH",
      path: `/v1/ai-gateway/firewall-policies/${encodeURIComponent(id)}`,
      body: input,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  /**
   * Delete a firewall policy. Refused with 409 `policy_in_use` while any agent
   * or MCP server is still attached.
   */
  async deleteFirewallPolicy(id: string, opts?: { idempotencyKey?: string }): Promise<{ id: string; deleted: true }> {
    return unwrap(await this.client.request<Envelope<{ id: string; deleted: true }>>({
      method: "DELETE",
      path: `/v1/ai-gateway/firewall-policies/${encodeURIComponent(id)}`,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  /** Iterate every token under a gateway across all pages. */
  iterateGatewayTokens(gatewayId: string, params?: PageParams): AsyncIterableIterator<AIGatewayTokenListItem> {
    return iteratePages((page) => this.listGatewayTokens(gatewayId, { ...params, page }), params?.page ?? 1);
  }

  /**
   * Revoke any token under a gateway, including a gateway-level one. Use this
   * rather than `revokeToken` for a token minted by `POST /v1/oauth/token` —
   * that token has no agent, so the per-agent revoke can never match it.
   */
  async revokeGatewayToken(gatewayId: string, tokenId: string, opts?: { idempotencyKey?: string }): Promise<{ id: string; revoked: boolean }> {
    return unwrap(await this.client.request<Envelope<{ id: string; revoked: boolean }>>({
      method: "DELETE",
      path: `/v1/ai-gateway/gateways/${encodeURIComponent(gatewayId)}/tokens/${encodeURIComponent(tokenId)}`,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  /**
   * Dry-run rules against sample text. Saves nothing. Rules are compiled first,
   * so this refuses exactly what create/update refuse — a pattern that passes
   * here is one that will actually run in the data plane.
   */
  async testFirewallRules(input: { text: string; heuristics?: FirewallRule[] }): Promise<FirewallTestResult> {
    return unwrap(await this.client.request<Envelope<FirewallTestResult>>({
      method: "POST",
      path: "/v1/ai-gateway/firewall-policies/test",
      body: input,
    }));
  }

  // ── PII policies ───────────────────────────────────────────────────────
  //
  // Tenant-scoped, like firewall policies: one policy attaches to any number of
  // agents through `pii_redact_policy_id`. Until AIGW-160 these lived only on
  // the admin plane, so `createAgent` accepted a policy id that no API call
  // could produce.

  /** List PII redaction policies (paginated). Tenant-scoped, not per gateway. */
  async listPiiPolicies(params?: PageParams): Promise<Page<PiiPolicy>> {
    return this.client.request<Page<PiiPolicy>>({
      method: "GET",
      path: "/v1/ai-gateway/pii-policies",
      query: params as Record<string, string | number | undefined>,
    });
  }

  /** Iterate every PII policy across all pages. */
  iteratePiiPolicies(params?: PageParams): AsyncIterableIterator<PiiPolicy> {
    return iteratePages((page) => this.listPiiPolicies({ ...params, page }), params?.page ?? 1);
  }

  /**
   * Create a PII policy. Every id in `recognizer_ids` must be a recognizer this
   * tenant owns — a foreign id is a 400 `recognizer_not_found` rather than a
   * stored value that resolves to nothing at scan time.
   */
  async createPiiPolicy(input: CreatePiiPolicyInput, opts?: { idempotencyKey?: string }): Promise<PiiPolicy> {
    return unwrap(await this.client.request<Envelope<PiiPolicy>>({
      method: "POST",
      path: "/v1/ai-gateway/pii-policies",
      body: input,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  /** Fetch one PII policy by id. */
  async getPiiPolicy(id: string): Promise<PiiPolicy> {
    return unwrap(await this.client.request<Envelope<PiiPolicy>>({
      method: "GET",
      path: `/v1/ai-gateway/pii-policies/${encodeURIComponent(id)}`,
    }));
  }

  /** Update a PII policy in place (the version is not bumped). */
  async updatePiiPolicy(id: string, input: UpdatePiiPolicyInput, opts?: { idempotencyKey?: string }): Promise<PiiPolicy> {
    return unwrap(await this.client.request<Envelope<PiiPolicy>>({
      method: "PATCH",
      path: `/v1/ai-gateway/pii-policies/${encodeURIComponent(id)}`,
      body: input,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  /**
   * Delete a PII policy. Refused with 409 `policy_in_use` while any agent still
   * references it — the foreign key is `ON DELETE SET NULL`, so an unchecked
   * delete would detach every bound agent and turn redaction off for each of
   * them with no error.
   */
  async deletePiiPolicy(id: string, opts?: { idempotencyKey?: string }): Promise<{ id: string; deleted: true }> {
    return unwrap(await this.client.request<Envelope<{ id: string; deleted: true }>>({
      method: "DELETE",
      path: `/v1/ai-gateway/pii-policies/${encodeURIComponent(id)}`,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  // ── PII recognizers ────────────────────────────────────────────────────

  /** List custom PII recognizers (paginated). */
  async listPiiRecognizers(params?: PageParams): Promise<Page<PiiRecognizer>> {
    return this.client.request<Page<PiiRecognizer>>({
      method: "GET",
      path: "/v1/ai-gateway/pii-recognizers",
      query: params as Record<string, string | number | undefined>,
    });
  }

  /** Iterate every PII recognizer across all pages. */
  iteratePiiRecognizers(params?: PageParams): AsyncIterableIterator<PiiRecognizer> {
    return iteratePages((page) => this.listPiiRecognizers({ ...params, page }), params?.page ?? 1);
  }

  /** Create a custom recognizer. */
  async createPiiRecognizer(input: CreatePiiRecognizerInput, opts?: { idempotencyKey?: string }): Promise<PiiRecognizer> {
    return unwrap(await this.client.request<Envelope<PiiRecognizer>>({
      method: "POST",
      path: "/v1/ai-gateway/pii-recognizers",
      body: input,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  /**
   * Dry-run a candidate pattern against sample text. Saves nothing.
   *
   * It compiles with the SAME engine the data plane runs, so a pattern that
   * passes here is one that will actually execute. Do NOT preview with a local
   * `new RegExp`: V8 accepts lookahead, lookbehind and backreferences that the
   * server refuses, so a local preview shows matches for a recognizer that can
   * never run and then 400s on save.
   */
  async testPiiRecognizer(input: {
    pattern: string;
    text: string;
    kind?: PiiRecognizerKind;
    action?: PiiAction;
    context_words?: string[];
    name?: string;
  }): Promise<PiiRecognizerTestResult> {
    return unwrap(await this.client.request<Envelope<PiiRecognizerTestResult>>({
      method: "POST",
      path: "/v1/ai-gateway/pii-recognizers/test",
      body: input,
    }));
  }

  /** Fetch one recognizer by id. */
  async getPiiRecognizer(id: string): Promise<PiiRecognizer> {
    return unwrap(await this.client.request<Envelope<PiiRecognizer>>({
      method: "GET",
      path: `/v1/ai-gateway/pii-recognizers/${encodeURIComponent(id)}`,
    }));
  }

  /**
   * Update a recognizer. The server validates the MERGED state, not the patch,
   * so `{action: "whitelist"}` on its own is still checked against the stored
   * pattern.
   */
  async updatePiiRecognizer(id: string, input: UpdatePiiRecognizerInput, opts?: { idempotencyKey?: string }): Promise<PiiRecognizer> {
    return unwrap(await this.client.request<Envelope<PiiRecognizer>>({
      method: "PATCH",
      path: `/v1/ai-gateway/pii-recognizers/${encodeURIComponent(id)}`,
      body: input,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  /**
   * Delete a recognizer. Refused with 409 `recognizer_in_use` while any PII
   * policy still lists it: an empty `recognizer_ids` means "every enabled
   * recognizer", so dropping the id would WIDEN the policy rather than shrink
   * it. Remove it from each policy first.
   */
  async deletePiiRecognizer(id: string, opts?: { idempotencyKey?: string }): Promise<{ id: string; deleted: true }> {
    return unwrap(await this.client.request<Envelope<{ id: string; deleted: true }>>({
      method: "DELETE",
      path: `/v1/ai-gateway/pii-recognizers/${encodeURIComponent(id)}`,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  // ── Usage ──────────────────────────────────────────────────────────────

  /** Usage rollup across models for a period (default server 7d), optionally scoped to one agent. */
  async usage(params?: UsageParams): Promise<AIGatewayUsage> {
    return unwrap(await this.client.request<Envelope<AIGatewayUsage>>({
      method: "GET",
      path: "/v1/ai-gateway/usage",
      query: params as Record<string, string | undefined>,
    }));
  }

  /**
   * FinOps export: aggregated spend grouped by user | team | agent | model |
   * provider | `tag:<key>`, over a period. Returns the JSON rows.
   */
  async exportUsage(params: {
    group_by: string;
    period?: "7d" | "30d" | "90d";
    agent_id?: string;
  }): Promise<AIGatewayUsageExport> {
    return unwrap(await this.client.request<Envelope<AIGatewayUsageExport>>({
      method: "GET",
      path: "/v1/ai-gateway/usage/export",
      query: { ...params, format: "json" } as Record<string, string | undefined>,
    }));
  }
}
