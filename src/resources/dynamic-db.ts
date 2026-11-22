// Dynamic DB Credentials resource — short-lived database credentials.

import type { APIClient } from "../core.js";
import { type Envelope, unwrap } from "./shared.js";

/** Row returned by GET /v1/dyn-db-credentials (bare array) and GET /:name. */
export interface DbConnection {
  id: string;
  name: string;
  engine: "postgres" | "mysql" | "mongo";
  host: string;
  port: number | null;
  database_name: string | null;
  admin_username: string;
  execution_mode: "direct" | "agent_tunnel" | "ssh_tunnel" | "iam";
  agent_id: string | null;
  default_ttl_seconds: number;
  max_ttl_seconds: number;
  connect_options: Record<string, unknown>;
  enabled: boolean;
  created_at: string;
  updated_at: string;
  ssh_host: string | null;
  ssh_port: number | null;
  ssh_username: string | null;
  iam_region: string | null;
  iam_db_user: string | null;
}

/** POST /v1/dyn-db-credentials response. */
export interface CreateDbConnectionResponse {
  id: string;
  name: string;
  engine: "postgres" | "mysql" | "mongo";
  execution_mode: "direct" | "agent_tunnel" | "ssh_tunnel" | "iam";
}

/** Row returned by GET /v1/dyn-db-credentials/:name/roles (bare array). */
export interface DbRole {
  id: string;
  name: string;
  creation_sql_template: string;
  revocation_sql_template: string;
  default_ttl_seconds: number | null;
  max_ttl_seconds: number | null;
  created_at: string;
  updated_at: string;
}

/** POST /v1/dyn-db-credentials/:name/creds/:role response — `password` is returned ONCE. */
export interface MintDbCredentialResponse {
  username: string;
  /** Plaintext credential — only ever present in this response. */
  password: string;
  expires_at: string;
  lease_id: number;
  connection_name: string;
  role_name: string;
}

/** Row inside GET /v1/dyn-db-credentials/leases → `leases`. */
export interface DbLease {
  id: number;
  status: string;
  expires_at: string;
  issued_at: string;
  username: string | null;
  connection_name: string | null;
  role_name: string | null;
  engine: string | null;
}

/**
 * GET /v1/dyn-db-credentials/leases response. Unlike every other list, its
 * pagination really is limit/offset INSIDE the data payload.
 *
 * Only LIVE leases are returned — `status` `active`, `renewing` or `errored`,
 * i.e. every lease whose database user may still exist on your server. A lease
 * that has expired or been revoked has had its user dropped and is neither
 * listed nor counted in `total`.
 *
 * `errored` is included deliberately: renewal was abandoned after five
 * consecutive failures, so nothing is refreshing or expiring that lease. It is
 * also the set counted by the `409 … has N active credential lease(s)` a
 * connection or role delete returns, so anything blocking a delete is listed
 * here and can be revoked.
 */
export interface DbLeaseList {
  leases: DbLease[];
  total: number;
  limit: number;
  offset: number;
}

export class DynamicDbResource {
  constructor(private readonly client: APIClient) {}

  // ── Connection management ──────────────────────────────────────────────────

  async list(): Promise<DbConnection[]> {
    return unwrap(await this.client.request<Envelope<DbConnection[]>>({
      method: "GET", path: "/v1/dyn-db-credentials",
    }));
  }

  async get(name: string): Promise<DbConnection> {
    return unwrap(await this.client.request<Envelope<DbConnection>>({
      method: "GET", path: `/v1/dyn-db-credentials/${encodeURIComponent(name)}`,
    }));
  }

  async create(
    input: {
      name: string;
      engine: string;
      host?: string;
      port?: number;
      database_name?: string;
      admin_username?: string;
      admin_password?: string;
      execution_mode?: string;
      agent_id?: string;
      ssh_host?: string;
      ssh_port?: number;
      ssh_username?: string;
      ssh_private_key?: string;
      ssh_passphrase?: string;
      ssh_host_fingerprint?: string;
      iam_region?: string;
      iam_db_user?: string;
      default_ttl_seconds?: number;
      max_ttl_seconds?: number;
      connect_options?: Record<string, unknown>;
    },
    opts?: { idempotencyKey?: string },
  ): Promise<CreateDbConnectionResponse> {
    return unwrap(await this.client.request<Envelope<CreateDbConnectionResponse>>({
      method: "POST", path: "/v1/dyn-db-credentials", body: input, idempotencyKey: opts?.idempotencyKey,
    }));
  }

  async update(
    name: string,
    input: {
      host?: string;
      port?: number;
      database_name?: string;
      admin_username?: string;
      admin_password?: string;
      default_ttl_seconds?: number;
      max_ttl_seconds?: number;
      connect_options?: Record<string, unknown>;
      agent_id?: string;
      enabled?: boolean;
    },
    opts?: { idempotencyKey?: string },
  ): Promise<{ updated: string }> {
    return unwrap(await this.client.request<Envelope<{ updated: string }>>({
      method: "PATCH", path: `/v1/dyn-db-credentials/${encodeURIComponent(name)}`,
      body: input, idempotencyKey: opts?.idempotencyKey,
    }));
  }

  async delete(name: string, opts?: { idempotencyKey?: string }): Promise<{ deleted: string }> {
    return unwrap(await this.client.request<Envelope<{ deleted: string }>>({
      method: "DELETE", path: `/v1/dyn-db-credentials/${encodeURIComponent(name)}`,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  async rotateSshKey(
    name: string,
    input: { ssh_private_key: string; ssh_passphrase?: string; ssh_host_fingerprint?: string },
    opts?: { idempotencyKey?: string },
  ): Promise<{ rotated: string; fingerprint_updated: boolean }> {
    return unwrap(await this.client.request<Envelope<{ rotated: string; fingerprint_updated: boolean }>>({
      method: "POST",
      path: `/v1/dyn-db-credentials/${encodeURIComponent(name)}/rotate-ssh-key`,
      body: input, idempotencyKey: opts?.idempotencyKey,
    }));
  }

  // ── Roles ──────────────────────────────────────────────────────────────────

  async listRoles(connectionName: string): Promise<DbRole[]> {
    return unwrap(await this.client.request<Envelope<DbRole[]>>({
      method: "GET", path: `/v1/dyn-db-credentials/${encodeURIComponent(connectionName)}/roles`,
    }));
  }

  async createRole(
    connectionName: string,
    input: {
      name: string;
      template?: string;
      creation_sql?: string;
      revocation_sql?: string;
      default_ttl_seconds?: number;
      max_ttl_seconds?: number;
    },
    opts?: { idempotencyKey?: string },
  ): Promise<{ id: string; name: string; connection: string }> {
    return unwrap(await this.client.request<Envelope<{ id: string; name: string; connection: string }>>({
      method: "POST",
      path: `/v1/dyn-db-credentials/${encodeURIComponent(connectionName)}/roles`,
      body: input, idempotencyKey: opts?.idempotencyKey,
    }));
  }

  async updateRole(
    connectionName: string,
    role: string,
    input: { creation_sql?: string; revocation_sql?: string; default_ttl_seconds?: number; max_ttl_seconds?: number },
    opts?: { idempotencyKey?: string },
  ): Promise<{ updated: string }> {
    return unwrap(await this.client.request<Envelope<{ updated: string }>>({
      method: "PATCH",
      path: `/v1/dyn-db-credentials/${encodeURIComponent(connectionName)}/roles/${encodeURIComponent(role)}`,
      body: input, idempotencyKey: opts?.idempotencyKey,
    }));
  }

  async deleteRole(connectionName: string, role: string, opts?: { idempotencyKey?: string }): Promise<{ deleted: string }> {
    return unwrap(await this.client.request<Envelope<{ deleted: string }>>({
      method: "DELETE",
      path: `/v1/dyn-db-credentials/${encodeURIComponent(connectionName)}/roles/${encodeURIComponent(role)}`,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  // ── Credential minting + lease management ───────────────────────────────────

  /** Mint a short-lived credential. ``password`` is returned once — use it immediately. */
  async mint(
    connectionName: string,
    role: string,
    input?: { ttl_seconds?: number },
    opts?: { idempotencyKey?: string },
  ): Promise<MintDbCredentialResponse> {
    return unwrap(await this.client.request<Envelope<MintDbCredentialResponse>>({
      method: "POST",
      path: `/v1/dyn-db-credentials/${encodeURIComponent(connectionName)}/creds/${encodeURIComponent(role)}`,
      body: input ?? {},
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  /**
   * List live leases. `connection` is an exact match on the connection's name,
   * scoped to the caller's Live/Test space.
   */
  async listLeases(params?: { limit?: number; offset?: number; connection?: string }): Promise<DbLeaseList> {
    return unwrap(await this.client.request<Envelope<DbLeaseList>>({
      method: "GET", path: "/v1/dyn-db-credentials/leases",
      query: params as Record<string, string | number | undefined>,
    }));
  }

  async revokeLease(leaseId: number | string, opts?: { idempotencyKey?: string }): Promise<{ revoked: number }> {
    return unwrap(await this.client.request<Envelope<{ revoked: number }>>({
      method: "POST",
      path: `/v1/dyn-db-credentials/leases/${encodeURIComponent(String(leaseId))}/revoke`,
      body: {},
      idempotencyKey: opts?.idempotencyKey,
    }));
  }
}
