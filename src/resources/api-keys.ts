// API Keys resource — programmatic key management.

import type { APIClient } from "../core.js";
import { type Envelope, type Page, type PageParams, iteratePages, unwrap } from "./shared.js";

/** Row returned by GET /v1/api-keys. */
export interface ApiKey {
  id: string;
  key_id: string;
  key_prefix: string;
  key_type: "test" | "standard" | "access_key";
  name: string;
  active: boolean;
  created_at: string;
  last_used_at: string | null;
  rate_limit_requests: number | null;
  rate_limit_window_sec: number | null;
}

/** A permission role, from GET /v1/roles. */
export interface Role {
  id: string;
  name: string;
  description: string | null;
  /** `role_ids` accepts a role only when this includes "api_key" AND `seeded` is true. */
  applies_to: Array<"user" | "api_key">;
  is_default: boolean;
  /**
   * True for roles the platform creates and maintains. Only a seeded key role
   * is accepted in `role_ids`; `false` marks a custom role, which is being
   * retired (the list still returns existing ones — filter on this).
   */
  seeded: boolean;
}

export interface ListRolesParams extends PageParams {
  subject_kind?: "api_key" | "user";
}

/** POST /v1/api-keys response — `api_key` is returned ONCE. */
export interface CreateApiKeyResponse {
  /** Row UUID — what `revoke()` and role assignments reference. */
  id: string;
  key_id: string;
  /** Plaintext key — only ever present in this response. */
  api_key: string;
  key_prefix: string;
  /** "test" when created in sandbox mode, else "standard". */
  key_type: "test" | "standard";
  name: string;
  /** Role UUIDs attached in the same transaction as the key. */
  role_ids: string[];
  message: string;
}

export class ApiKeysResource {
  constructor(private readonly client: APIClient) {}

  async list(params?: PageParams): Promise<Page<ApiKey>> {
    return this.client.request<Page<ApiKey>>({
      method: "GET", path: "/v1/api-keys",
      query: params as Record<string, string | number | undefined>,
    });
  }

  iterate(params?: PageParams): AsyncIterableIterator<ApiKey> {
    return iteratePages((page) => this.list({ ...params, page }), params?.page ?? 1);
  }

  /**
   * ``api_key`` is returned once — save it immediately.
   *
   * `role_ids` attaches permission roles in the same transaction as the key.
   * Only the SEEDED key roles are accepted (`seeded: true` — Key — Invoke,
   * Key — Read-only, Key — Editor, Key — Infrastructure); any other role is
   * refused `403 forbidden`, because custom roles are being retired. Discover
   * them with `client.roles.list({ subject_kind: "api_key" })` and filter on
   * `seeded`. A key created with no role is default-denied on every
   * policy-gated endpoint.
   *
   * A key can never mint a key more privileged than itself: if a requested role
   * grants something this credential does not hold, the server answers
   * `403 privilege_escalation` (a `PermissionDeniedError` whose `.code` is
   * `"privilege_escalation"`) and names the offending grant verbatim.
   */
  async create(
    input: {
      name: string;
      rate_limit_requests?: number;
      rate_limit_window_sec?: number;
      role_ids?: string[];
    },
    opts?: { idempotencyKey?: string },
  ): Promise<CreateApiKeyResponse> {
    return unwrap(await this.client.request<Envelope<CreateApiKeyResponse>>({
      method: "POST", path: "/v1/api-keys", body: input, idempotencyKey: opts?.idempotencyKey,
    }));
  }

  async revoke(id: string, opts?: { idempotencyKey?: string }): Promise<{ revoked: true }> {
    return unwrap(await this.client.request<Envelope<{ revoked: true }>>({
      method: "DELETE",
      path: `/v1/api-keys/${encodeURIComponent(id)}`,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }
}

/**
 * Read-only role catalog. `/v1` exposes it so `apiKeys.create({ role_ids })`
 * can be written in code instead of by copying a UUID out of a browser URL bar.
 * Only seeded key roles (`seeded: true`) are accepted in `role_ids`. Custom
 * roles are being retired: none can be created, and the list still returns any
 * a tenant already has (`seeded: false`) — filter on `seeded`.
 */
export class RolesResource {
  constructor(private readonly client: APIClient) {}

  async list(params?: ListRolesParams): Promise<Page<Role>> {
    return this.client.request<Page<Role>>({
      method: "GET", path: "/v1/roles",
      query: params as Record<string, string | number | undefined>,
    });
  }

  iterate(params?: ListRolesParams): AsyncIterableIterator<Role> {
    return iteratePages((page) => this.list({ ...params, page }), params?.page ?? 1);
  }
}
