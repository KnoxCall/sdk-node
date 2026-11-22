// Secrets resource — mirrors src/client-api/secrets.ts

import type { APIClient } from "../core.js";
import { type Envelope, type Page, type PageParams, iteratePages, unwrap } from "./shared.js";

export type SecretType = "string" | "oauth2" | "certificate";

/**
 * Per-environment metadata, returned in `Secret.environments` by
 * GET /v1/secrets/:id. Never contains the value.
 */
export interface SecretEnvironmentVersion {
  environment_name: string;
  /**
   * Counter of genuine value writes for this environment, starting at 1 when
   * the environment's first value is stored. Incremented ONLY by writes that
   * change the stored value (rotations, admin value/certificate updates,
   * platform-managed custodial key rotation) — never by OAuth2 token
   * refreshes, expiry-override edits, certificate metadata re-parsing, or a
   * re-encryption of the same plaintext under a new tenant key.
   *
   * Compare it against the version your own last write returned to detect a
   * rotation performed outside your tooling. `updated_at` cannot be used for
   * this: it moves for non-value writes too.
   */
  value_version: number;
  /** Last change of ANY kind to this environment's row. */
  updated_at: string;
  /** Per-environment expiry override; null inherits the secret-level expiry. */
  expires_at_override: string | null;
}

/** Row returned by GET /v1/secrets and GET /v1/secrets/:id. */
export interface Secret {
  id: string;
  name: string;
  shortcode_name: string;
  base_environment: string | null;
  secret_type: SecretType;
  collection_id: string | null;
  created_at: string;
  expires_at: string | null;
  strict_expiry_enforcement: boolean;
  environment_count: number;
  /**
   * One entry per environment holding a value, ordered by environment name.
   * Present on GET /v1/secrets/:id; absent on the list endpoint.
   */
  environments?: SecretEnvironmentVersion[];
}

/** POST /v1/secrets response (string secrets, the default type). */
export interface CreateSecretResponse {
  id: string;
  name: string;
  shortcode_name: string;
  base_environment: string;
  environment_count: number;
  secret_type: "string";
  collection_id: string | null;
  expires_at: string | null;
  strict_expiry_enforcement: boolean;
}

/** PUT /v1/secrets/:id/value response. */
export interface SecretValueResponse {
  id: string;
  name: string;
  environment: string;
  /**
   * The environment's value version AFTER this write — 1 when this call stored
   * the environment's first value, otherwise the previous version plus one.
   * It is the version this call produced, so storing it has no read-after-write
   * race with a concurrent rotation.
   */
  value_version: number;
}

/** PATCH /v1/secrets/:id response. */
export interface UpdateSecretResponse {
  id: string;
  name: string;
  expires_at: string | null;
  strict_expiry_enforcement: boolean;
}

/** GET /v1/secrets/:id/oauth2/token response. */
export interface SecretOAuthToken {
  access_token: string;
  expires_at: string | null;
  token_type: string;
  connection_status: string;
}

export interface CreateSecretInput {
  name: string;
  secret_type?: SecretType;
  value: string;
  description?: string;
  environment?: string;
}

/**
 * Input for {@link SecretsResource.createOAuth2}. The proxy uses OAuth2 secrets
 * to inject provider access tokens into upstream requests.
 */
export interface CreateOAuth2SecretInput {
  name: string;
  /** OAuth2 provider key (see the API's provider list, e.g. "google", "custom"). */
  provider: string;
  client_id: string;
  /** Required unless mtls_certificate_id is set, or grant_type is "implicit"/"password". */
  client_secret?: string;
  /** Use a stored mTLS client certificate instead of a client_secret. */
  mtls_certificate_id?: string;
  scopes?: string[];
  auth_url?: string;
  token_url?: string;
  grant_type?: string;
  /** Username for the "password" (ROPC) grant. */
  username?: string;
  /** Password for the "password" (ROPC) grant. */
  password?: string;
  collection_id?: string;
}

/** Input for {@link SecretsResource.createCertificate}. */
export interface CreateCertificateSecretInput {
  name: string;
  /** Certificate material — PEM text, or base64 for binary formats. */
  certificate_content: string;
  private_key?: string;
  passphrase?: string;
  /** One of pem|pfx|p12|crt|cer|key|pkcs7|p7b|p7c. Defaults to "pem". */
  certificate_type?: string;
  collection_id?: string;
}

export interface UpdateSecretInput {
  name?: string;
  description?: string;
  expires_at?: string;
  strict_expiry_enforcement?: boolean;
}

export type ListSecretsResponse = Page<Secret>;

export class SecretsResource {
  constructor(private readonly client: APIClient) {}

  async list(params?: PageParams): Promise<Page<Secret>> {
    return this.client.request<Page<Secret>>({
      method: "GET",
      path: "/v1/secrets",
      query: params as Record<string, string | number | undefined>,
    });
  }

  iterate(params?: PageParams): AsyncIterableIterator<Secret> {
    return iteratePages((page) => this.list({ ...params, page }), params?.page ?? 1);
  }

  async get(id: string): Promise<Secret> {
    return unwrap(await this.client.request<Envelope<Secret>>({
      method: "GET",
      path: `/v1/secrets/${encodeURIComponent(id)}`,
    }));
  }

  async create(input: CreateSecretInput, opts?: { idempotencyKey?: string }): Promise<CreateSecretResponse> {
    return unwrap(await this.client.request<Envelope<CreateSecretResponse>>({
      method: "POST",
      path: "/v1/secrets",
      body: input,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  /**
   * Create an OAuth2-provider secret (the proxy injects the provider's access
   * token into upstream requests). Requires `provider` + `client_id`, and — for
   * most grant types — either `client_secret` or `mtls_certificate_id`. The base
   * {@link create} cannot carry these fields, so use this typed helper.
   */
  async createOAuth2(input: CreateOAuth2SecretInput, opts?: { idempotencyKey?: string }): Promise<CreateSecretResponse> {
    return unwrap(await this.client.request<Envelope<CreateSecretResponse>>({
      method: "POST",
      path: "/v1/secrets/oauth2",
      body: input,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  /** Create a certificate / mTLS secret. Requires `certificate_content`. */
  async createCertificate(input: CreateCertificateSecretInput, opts?: { idempotencyKey?: string }): Promise<CreateSecretResponse> {
    return unwrap(await this.client.request<Envelope<CreateSecretResponse>>({
      method: "POST",
      path: "/v1/secrets/certificate",
      body: input,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  async update(id: string, input: UpdateSecretInput, opts?: { idempotencyKey?: string }): Promise<UpdateSecretResponse> {
    return unwrap(await this.client.request<Envelope<UpdateSecretResponse>>({
      method: "PATCH",
      path: `/v1/secrets/${encodeURIComponent(id)}`,
      body: input,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  /**
   * Rotate the secret value only, without changing other metadata.
   *
   * The response carries the environment's new `value_version`; compare it
   * later against `getSecret(id).environments[].value_version` to detect a
   * rotation performed outside your tooling.
   */
  async setValue(
    id: string,
    input: { value: string; environment?: string },
    opts?: { idempotencyKey?: string },
  ): Promise<SecretValueResponse> {
    return unwrap(await this.client.request<Envelope<SecretValueResponse>>({
      method: "PUT",
      path: `/v1/secrets/${encodeURIComponent(id)}/value`,
      body: input,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  /** Get the current access token for an OAuth2 secret (auto-refreshes if expired). */
  async getOAuthToken(id: string, params?: { environment?: string }): Promise<SecretOAuthToken> {
    return unwrap(await this.client.request<Envelope<SecretOAuthToken>>({
      method: "GET",
      path: `/v1/secrets/${encodeURIComponent(id)}/oauth2/token`,
      query: params as Record<string, string | undefined>,
    }));
  }

  async delete(id: string, opts?: { idempotencyKey?: string }): Promise<{ deleted: true }> {
    return unwrap(await this.client.request<Envelope<{ deleted: true }>>({
      method: "DELETE",
      path: `/v1/secrets/${encodeURIComponent(id)}`,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }
}
