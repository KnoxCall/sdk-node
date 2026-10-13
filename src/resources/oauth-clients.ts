// OAuth Clients resource — mirrors src/client-api/oauth-clients.ts
//
// These handlers bypass the standard success() wrapper: responses are
// `{ data }` with NO meta/request_id, and create/rotate-secret carry an
// optional top-level `warning`. The SDK unwraps `data` and attaches the
// warning as an optional field on the returned object.

import type { APIClient } from "../core.js";

/** OAuth grant types accepted by the server. */
export type OAuthGrantType =
  | "client_credentials"
  | "authorization_code"
  | "refresh_token"
  | "urn:ietf:params:oauth:grant-type:token-exchange"
  | "urn:ietf:params:oauth:grant-type:device_code";

/** Row returned by GET /v1/oauth-clients (bare `{data}` — no meta, no pagination). */
export interface OAuthClient {
  id: string;
  client_id: string;
  name: string;
  type: "confidential" | "public";
  grant_types: OAuthGrantType[];
  allowed_scopes: string[];
  redirect_uris: string[];
  require_dpop: boolean;
  /** Always `true`. PKCE is mandatory on the authorization-code flow: the token endpoint requires a
   *  `code_verifier` from every client, so `false` only ever produced authorization codes that could not
   *  be redeemed. The server refuses `false` with a 400. */
  require_pkce: true;
  /** Always `"opaque"`. The RFC 9068 `"jwt"` format was withdrawn: no KnoxCall resource server accepted it. */
  token_format: "opaque";
  active: boolean;
  revoked_at: string | null;
  created_at: string;
  last_used_at: string | null;
  source_api_key_id: string | null;
  source_key_type: string | null;
  /** `'cli'` on the tenant's auto-provisioned KnoxCall CLI client — protected from update/delete. */
  system_role: string | null;
}

/** GET /v1/oauth-clients/:id response (no source_key_type, plus step_up_scopes). */
export interface OAuthClientDetail extends Omit<OAuthClient, "source_key_type"> {
  step_up_scopes: string[];
}

/** POST /v1/oauth-clients response — `client_secret` is returned ONCE. */
export interface CreateOAuthClientResponse {
  id: string;
  client_id: string;
  /** Plaintext secret (null for public clients) — only ever present here. */
  client_secret: string | null;
  type: "confidential" | "public";
  grant_types: string[];
  allowed_scopes: string[];
  redirect_uris: string[];
  /** Server advisory attached from the response's top-level `warning`. */
  warning?: string;
}

/** POST /v1/oauth-clients/:id/rotate-secret response — `client_secret` is returned ONCE. */
export interface RotateOAuthClientSecretResponse {
  client_id: string;
  /** New plaintext secret — only ever present in this response. */
  client_secret: string;
  /** Server advisory attached from the response's top-level `warning`. */
  warning: string;
}

export interface CreateOAuthClientInput {
  name: string;
  type?: string;
  grant_types?: OAuthGrantType[];
  allowed_scopes?: string[];
  redirect_uris?: string[];
  require_dpop?: boolean;
  /** Optional; the only accepted value is `true` (the server refuses `false` with 400). */
  require_pkce?: true;
  /** Optional; the only accepted value is `"opaque"` (the server refuses anything else with 400). */
  token_format?: "opaque";
  consent_html_template?: string;
  step_up_scopes?: string[];
}

export interface UpdateOAuthClientInput {
  name?: string;
  allowed_scopes?: string[];
  redirect_uris?: string[];
  require_dpop?: boolean;
  /** Optional; the only accepted value is `true` (the server refuses `false` with 400). */
  require_pkce?: true;
  active?: boolean;
  /** Optional; the only accepted value is `"opaque"` (the server refuses anything else with 400). */
  token_format?: "opaque";
  consent_html_template?: string;
  step_up_scopes?: string[];
}

export class OAuthClientsResource {
  constructor(private readonly client: APIClient) {}

  async list(): Promise<OAuthClient[]> {
    const res = await this.client.request<{ data: OAuthClient[] }>({
      method: "GET", path: "/v1/oauth-clients",
    });
    return res.data;
  }

  async get(id: string): Promise<OAuthClientDetail> {
    const res = await this.client.request<{ data: OAuthClientDetail }>({
      method: "GET", path: `/v1/oauth-clients/${encodeURIComponent(id)}`,
    });
    return res.data;
  }

  /** ``client_secret`` is returned once — save it immediately. */
  async create(
    input: CreateOAuthClientInput,
    opts?: { idempotencyKey?: string },
  ): Promise<CreateOAuthClientResponse> {
    const res = await this.client.request<{ data: CreateOAuthClientResponse; warning?: string }>({
      method: "POST",
      path: "/v1/oauth-clients",
      body: input,
      idempotencyKey: opts?.idempotencyKey,
    });
    return res.warning === undefined ? res.data : { ...res.data, warning: res.warning };
  }

  async update(
    id: string,
    input: UpdateOAuthClientInput,
    opts?: { idempotencyKey?: string },
  ): Promise<{ id: string }> {
    const res = await this.client.request<{ data: { id: string } }>({
      method: "PATCH",
      path: `/v1/oauth-clients/${encodeURIComponent(id)}`,
      body: input,
      idempotencyKey: opts?.idempotencyKey,
    });
    return res.data;
  }

  /**
   * Returns new ``client_secret`` once — save immediately.
   *
   * Rotation is containment: every access and refresh token the OLD secret
   * minted is revoked in the same transaction as the re-key, so they stop
   * working immediately rather than at their TTL. A rotation whose revocation
   * cannot complete is refused and the old secret keeps working — you never
   * hold a new secret for a client whose old tokens are still live.
   */
  async rotateSecret(id: string, opts?: { idempotencyKey?: string }): Promise<RotateOAuthClientSecretResponse> {
    const res = await this.client.request<{ data: { client_id: string; client_secret: string }; warning: string }>({
      method: "POST",
      path: `/v1/oauth-clients/${encodeURIComponent(id)}/rotate-secret`,
      body: {},
      idempotencyKey: opts?.idempotencyKey,
    });
    return { ...res.data, warning: res.warning };
  }

  async revoke(id: string, opts?: { idempotencyKey?: string }): Promise<{ revoked: true }> {
    const res = await this.client.request<{ data: { revoked: true } }>({
      method: "DELETE",
      path: `/v1/oauth-clients/${encodeURIComponent(id)}`,
      idempotencyKey: opts?.idempotencyKey,
    });
    return res.data;
  }
}
