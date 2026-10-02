// Clients resource — mTLS / IP-restricted client identities.

import type { APIClient } from "../core.js";
import { type Envelope, type Page, type PageParams, iteratePages, unwrap } from "./shared.js";

/** Row returned by GET /v1/clients. */
export interface Client {
  id: string;
  name: string;
  type: "user" | "server";
  ip_address: string;
  ip_notes: Record<string, unknown>;
  description: string | null;
  enabled: boolean;
  collection_id: string | null;
  created_at: string;
  updated_at: string;
}

/** Detail returned by GET /v1/clients/:id. */
export interface ClientDetail extends Client {
  route_assignments: Array<{ route_id: string; route_name: string; environment_name: string }>;
}

/** Full `clients` row returned by POST /v1/clients and PATCH /v1/clients/:id. */
export interface ClientRecord extends Client {
  tenant_id: string;
  created_by: string | null;
  agent_version: string | null;
  agent_os: string | null;
  agent_arch: string | null;
  agent_hostname: string | null;
  agent_last_seen: string | null;
  agent_mode: string | null;
}

export type ClientCredentialKind =
  | "ip"
  | "mtls_thumbprint"
  | "signature_hmac"
  | "signature_ed25519"
  | "machine_id"
  | "workload_identity";

/**
 * A client credential with secret material stripped
 * (`data.secret_ct` / `data.private_key_pem` are never returned).
 */
export interface ClientCredential {
  id: string;
  client_id: string;
  tenant_id: string;
  kind: ClientCredentialKind;
  label: string | null;
  data: Record<string, unknown>;
  enabled: boolean;
  expires_at: string | null;
  created_at: string;
  updated_at: string;
  last_matched_at: string | null;
}

/**
 * POST /v1/clients/:id/credentials response. For mTLS "issue" mode the
 * one-shot `reveal` carries the certificate + private key — save it now.
 */
export interface CreateClientCredentialResponse extends ClientCredential {
  reveal?: { certificate_pem: string; private_key_pem: string; ca_chain_pem: string };
}

export interface CreateClientInput {
  name: string;
  ip_address?: string;
  type?: string;
  description?: string;
}

export interface UpdateClientInput {
  name?: string;
  ip_address?: string;
  description?: string;
  enabled?: boolean;
}

export class ClientsResource {
  constructor(private readonly client: APIClient) {}

  async list(params?: PageParams): Promise<Page<Client>> {
    return this.client.request<Page<Client>>({
      method: "GET", path: "/v1/clients",
      query: params as Record<string, string | number | undefined>,
    });
  }

  iterate(params?: PageParams): AsyncIterableIterator<Client> {
    return iteratePages((page) => this.list({ ...params, page }), params?.page ?? 1);
  }

  async get(id: string): Promise<ClientDetail> {
    return unwrap(await this.client.request<Envelope<ClientDetail>>({
      method: "GET", path: `/v1/clients/${encodeURIComponent(id)}`,
    }));
  }

  async create(input: CreateClientInput, opts?: { idempotencyKey?: string }): Promise<ClientRecord> {
    return unwrap(await this.client.request<Envelope<ClientRecord>>({
      method: "POST", path: "/v1/clients", body: input, idempotencyKey: opts?.idempotencyKey,
    }));
  }

  async update(id: string, input: UpdateClientInput, opts?: { idempotencyKey?: string }): Promise<ClientRecord> {
    return unwrap(await this.client.request<Envelope<ClientRecord>>({
      method: "PATCH", path: `/v1/clients/${encodeURIComponent(id)}`,
      body: input, idempotencyKey: opts?.idempotencyKey,
    }));
  }

  async delete(id: string, opts?: { idempotencyKey?: string }): Promise<{ deleted: true }> {
    return unwrap(await this.client.request<Envelope<{ deleted: true }>>({
      method: "DELETE", path: `/v1/clients/${encodeURIComponent(id)}`,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  // ── Credentials sub-resource ───────────────────────────────────────────────

  async listCredentials(clientId: string): Promise<ClientCredential[]> {
    return unwrap(await this.client.request<Envelope<ClientCredential[]>>({
      method: "GET", path: `/v1/clients/${encodeURIComponent(clientId)}/credentials`,
    }));
  }

  async createCredential(
    clientId: string,
    input: { kind: string; data: Record<string, unknown>; label?: string },
    opts?: { idempotencyKey?: string },
  ): Promise<CreateClientCredentialResponse> {
    return unwrap(await this.client.request<Envelope<CreateClientCredentialResponse>>({
      method: "POST",
      path: `/v1/clients/${encodeURIComponent(clientId)}/credentials`,
      body: input,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  async updateCredential(
    clientId: string,
    credentialId: string,
    input: { enabled?: boolean; label?: string },
    opts?: { idempotencyKey?: string },
  ): Promise<ClientCredential> {
    return unwrap(await this.client.request<Envelope<ClientCredential>>({
      method: "PATCH",
      path: `/v1/clients/${encodeURIComponent(clientId)}/credentials/${encodeURIComponent(credentialId)}`,
      body: input,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  async deleteCredential(clientId: string, credentialId: string, opts?: { idempotencyKey?: string }): Promise<{ deleted: true }> {
    return unwrap(await this.client.request<Envelope<{ deleted: true }>>({
      method: "DELETE",
      path: `/v1/clients/${encodeURIComponent(clientId)}/credentials/${encodeURIComponent(credentialId)}`,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }
}
