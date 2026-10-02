// Routes resource — mirrors src/client-api/routes.ts

import type { APIClient } from "../core.js";
import { type Envelope, type Page, type PageParams, iteratePages, unwrap } from "./shared.js";

/** Row returned by GET /v1/routes. */
export interface RouteListItem {
  id: string;
  name: string;
  /** Write-once machine handle — reference the route in code as client.route(slug). */
  slug: string | null;
  /** Derived from the base environment's config; null only when the route has no environment configs. */
  target_base_url: string | null;
  base_environment: string | null;
  enabled: boolean;
  requires_clients: boolean;
  collection_id: string | null;
  created_at: string;
  environment_override_count: number;
  require_signature: boolean | null;
  rate_limit_enabled: boolean | null;
  rate_limit_requests: number | null;
  rate_limit_window_sec: number | null;
  allowed_methods: string[] | null;
}

/** Detail returned by GET /v1/routes/:id. */
export interface Route {
  id: string;
  name: string;
  /** Write-once machine handle — reference the route in code as client.route(slug). */
  slug: string | null;
  /** Derived from the base environment's config; null only when the route has no environment configs. */
  target_base_url: string | null;
  base_environment: string | null;
  enabled: boolean;
  requires_clients: boolean;
  mtls_certificate_id: string | null;
  collection_id: string | null;
  created_at: string;
  environment_override_count: number;
  configured_environments: string[];
  // Present only when a base-environment config row exists:
  payload_structure?: Record<string, unknown>;
  injection_rules?: unknown[];
  ip_allowlist?: string[];
  data_plane_node_id?: string | null;
}

/** Full `routes` row returned by POST /v1/routes and PATCH /v1/routes/:id. */
export interface RouteRecord {
  id: string;
  tenant_id: string;
  name: string;
  slug: string | null;
  sandbox: boolean;
  /** Derived from the base environment's config (echoed from the request on create). */
  target_base_url: string | null;
  enabled: boolean;
  created_at: string;
  requires_clients: boolean;
  base_environment: string | null;
  mtls_certificate_id: string | null;
  egress_server_id: string | null;
  collection_id: string | null;
  favicon_url: string | null;
  favicon_updated_at: string | null;
  favicon_data: string | null;
}

/** Row returned by GET /v1/routes/:id/logs (`api_requests`). */
export interface RouteLogEntry {
  id: string;
  request_id: string;
  ts: string;
  src_ip: string | null;
  method: string;
  path: string;
  status_code: number | null;
  latency_ms: number | null;
  upstream_host: string | null;
  error: string | null;
  environment: string | null;
  rate_limited: boolean;
  signature_valid: boolean | null;
  source_ip_country: string | null;
  source_ip_city: string | null;
}

/** Item returned by GET /v1/routes/:id/environments (bare array). */
export interface RouteEnvironmentSummary {
  environment_name: string;
  target_base_url: string;
  inject_headers_json: Record<string, unknown>;
  inject_body_json: Record<string, unknown>;
  require_signature: boolean;
  signature_tolerance_sec: number;
  rate_limit_enabled: boolean;
  rate_limit_requests: number | null;
  rate_limit_window_sec: number | null;
  rate_limit_burst: number | null;
  allowed_methods: string[] | null;
  /** Per-environment serving switch — false pauses this environment only. */
  enabled: boolean;
  requires_clients: boolean;
  mtls_certificate_id: string | null;
}

// Per-environment enforcement knobs (migration 20260723): requires_clients
// gates client authorization; mtls_certificate_id is the certificate-type
// secret used for upstream mTLS in that environment.

/** Full `route_environment_configs` row returned by PUT /v1/routes/:id/environments/:env. */
export interface RouteEnvironmentConfig {
  id: string;
  route_id: string;
  environment_name: string;
  target_base_url: string;
  inject_headers_json: Record<string, unknown>;
  inject_body_json: Record<string, unknown>;
  created_at: string;
  updated_at: string;
  require_signature: boolean;
  signature_tolerance_sec: number;
  rate_limit_enabled: boolean;
  rate_limit_requests: number | null;
  rate_limit_window_sec: number | null;
  rate_limit_burst: number | null;
  allowed_methods: string[] | null;
  method_configs: unknown[] | null;
  use_method_specific_configs: boolean | null;
  http_method_restrictions_enabled: boolean | null;
  egress_server_id: string | null;
  /** Per-environment serving switch — false pauses this environment only. */
  enabled: boolean;
  requires_clients: boolean;
  mtls_certificate_id: string | null;
  payload_structure: Record<string, unknown>;
  injection_rules: unknown[];
  ip_allowlist: string[];
  data_plane_node_id: string | null;
  intercept_enabled: boolean;
}

export type ListRoutesResponse = Page<RouteListItem>;

export interface CreateRouteInput {
  name: string;
  /** Opt the base environment into transparent interception (agent intercept mode + `wrap.intercept()`). */
  intercept_enabled?: boolean;
  /**
   * Write-once machine handle (1-63 chars, [a-z0-9-]). Omit to derive
   * "{collection}-{name}" automatically; pass null for no slug. Immutable
   * once set — code references can never be broken by a rename.
   */
  slug?: string | null;
  target_base_url: string;
}

export interface UpdateRouteInput {
  name?: string;
  target_base_url?: string;
  enabled?: boolean;
  /** Per-environment field — the PATCH fans the value out to every environment. */
  requires_clients?: boolean;
  /** Per-environment field (base environment): opt the route into transparent interception. */
  intercept_enabled?: boolean;
  /** Per-environment field — the PATCH fans the value out to every environment. */
  mtls_certificate_id?: string | null;
  inject_headers_json?: Record<string, unknown>;
  inject_body_json?: Record<string, unknown>;
  /**
   * @deprecated Never applied to any request. `PATCH /v1/routes/:id` rejects a
   * non-empty value with 400 (wave-2 row 2-273); an empty array is still
   * accepted as a no-op. Body secret injection uses `{{secret_id:<uuid>}}` /
   * `{{secret:<name>}}` placeholders in the request body your client sends.
   * Retained so the API's own explanatory refusal reaches the caller.
   */
  injection_rules?: unknown[];
  ip_allowlist?: string[];
  require_signature?: boolean;
  signature_tolerance_sec?: number;
  rate_limit_enabled?: boolean;
  rate_limit_requests?: number;
  rate_limit_window_sec?: number;
  rate_limit_burst?: number;
  allowed_methods?: string[];
}

export interface RouteEnvironmentInput {
  /** Per-environment serving switch — false pauses this environment only. */
  enabled?: boolean;
  /** Opt this environment into transparent interception (agent intercept mode + `wrap.intercept()`). */
  intercept_enabled?: boolean;
  target_base_url?: string;
  inject_headers_json?: Record<string, unknown>;
  inject_body_json?: Record<string, unknown>;
  /**
   * @deprecated Never applied to any request, and this endpoint never even read
   * it — the handler did not destructure the field, so it was silently dropped
   * on every call. It is now refused with 400 alongside the other `/v1` writers
   * (wave-2 row 2-273). See {@link UpdateRouteInput}.
   */
  injection_rules?: unknown[];
  ip_allowlist?: string[];
  require_signature?: boolean;
  signature_tolerance_sec?: number;
  rate_limit_enabled?: boolean;
  rate_limit_requests?: number;
  rate_limit_window_sec?: number;
  rate_limit_burst?: number;
  allowed_methods?: string[];
}

export class RoutesResource {
  constructor(private readonly client: APIClient) {}

  async list(params?: PageParams): Promise<Page<RouteListItem>> {
    return this.client.request<Page<RouteListItem>>({
      method: "GET",
      path: "/v1/routes",
      query: params as Record<string, string | number | undefined>,
    });
  }

  iterate(params?: PageParams): AsyncIterableIterator<RouteListItem> {
    return iteratePages((page) => this.list({ ...params, page }), params?.page ?? 1);
  }

  async get(id: string): Promise<Route> {
    return unwrap(await this.client.request<Envelope<Route>>({
      method: "GET",
      path: `/v1/routes/${encodeURIComponent(id)}`,
    }));
  }

  async create(input: CreateRouteInput, opts?: { idempotencyKey?: string }): Promise<RouteRecord> {
    return unwrap(await this.client.request<Envelope<RouteRecord>>({
      method: "POST",
      path: "/v1/routes",
      body: input,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  async update(id: string, input: UpdateRouteInput, opts?: { idempotencyKey?: string }): Promise<RouteRecord> {
    return unwrap(await this.client.request<Envelope<RouteRecord>>({
      method: "PATCH",
      path: `/v1/routes/${encodeURIComponent(id)}`,
      body: input,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  async delete(id: string, opts?: { idempotencyKey?: string }): Promise<{ deleted: true }> {
    return unwrap(await this.client.request<Envelope<{ deleted: true }>>({
      method: "DELETE",
      path: `/v1/routes/${encodeURIComponent(id)}`,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  async getLogs(id: string, params?: PageParams): Promise<Page<RouteLogEntry>> {
    return this.client.request<Page<RouteLogEntry>>({
      method: "GET",
      path: `/v1/routes/${encodeURIComponent(id)}/logs`,
      query: params as Record<string, string | number | undefined>,
    });
  }

  async listEnvironments(id: string): Promise<RouteEnvironmentSummary[]> {
    return unwrap(await this.client.request<Envelope<RouteEnvironmentSummary[]>>({
      method: "GET",
      path: `/v1/routes/${encodeURIComponent(id)}/environments`,
    }));
  }

  async upsertEnvironment(
    id: string,
    envName: string,
    input: RouteEnvironmentInput,
    opts?: { idempotencyKey?: string },
  ): Promise<RouteEnvironmentConfig> {
    return unwrap(await this.client.request<Envelope<RouteEnvironmentConfig>>({
      method: "PUT",
      path: `/v1/routes/${encodeURIComponent(id)}/environments/${encodeURIComponent(envName)}`,
      body: input,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  async deleteEnvironment(id: string, envName: string, opts?: { idempotencyKey?: string }): Promise<{ deleted: true }> {
    return unwrap(await this.client.request<Envelope<{ deleted: true }>>({
      method: "DELETE",
      path: `/v1/routes/${encodeURIComponent(id)}/environments/${encodeURIComponent(envName)}`,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  // ── Relay field-actions (declarative field-level encrypt/decrypt/tokenize) ──

  async listActions(id: string): Promise<RouteAction[]> {
    return unwrap(await this.client.request<Envelope<RouteAction[]>>({
      method: "GET", path: `/v1/routes/${encodeURIComponent(id)}/actions`,
    }));
  }

  async createAction(id: string, input: CreateRouteActionInput, opts?: { idempotencyKey?: string }): Promise<RouteAction> {
    return unwrap(await this.client.request<Envelope<RouteAction>>({
      method: "POST",
      path: `/v1/routes/${encodeURIComponent(id)}/actions`,
      body: input,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  async deleteAction(id: string, actionId: string, opts?: { idempotencyKey?: string }): Promise<{ deleted: string }> {
    return unwrap(await this.client.request<Envelope<{ deleted: string }>>({
      method: "DELETE",
      path: `/v1/routes/${encodeURIComponent(id)}/actions/${encodeURIComponent(actionId)}`,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }
}

export interface RouteAction {
  id: string;
  route_id: string;
  tenant_id: string;
  direction: "request" | "response";
  action: "encrypt" | "decrypt" | "tokenize" | "detokenize";
  selectors: string[];
  key_name: string | null;
  data_role: string | null;
  content_type: string;
  sort_order: number;
  enabled: boolean;
}

export interface CreateRouteActionInput {
  direction: "request" | "response";
  action: "encrypt" | "decrypt" | "tokenize" | "detokenize";
  selectors: string[];
  key_name?: string;
  data_role?: string;
  content_type?: string;
  sort_order?: number;
}
