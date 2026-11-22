// PKI resource — customer-facing CA, cert issuance, CRL.

import type { APIClient } from "../core.js";
import { type Envelope, unwrap } from "./shared.js";

/** CA root row (GET /v1/pki/roots — bare array). */
export interface CaRoot {
  id: string;
  tenant_id: string;
  name: string;
  cert_pem: string;
  subject: string;
  subject_fields: Record<string, unknown> | null;
  not_before: string;
  not_after: string;
  status: "active" | "retired" | "revoked";
  created_at: string;
  sandbox: boolean;
}

/** CA role row (GET /v1/pki/roots/:name/roles — bare array). */
export interface CaRole {
  id: string;
  ca_root_id: string;
  name: string;
  allowed_domains: string[];
  allow_subdomains: boolean;
  allow_wildcards: boolean;
  max_ttl_seconds: number;
  default_ttl_seconds: number;
  key_algorithm: "ecdsa-p256";
}

/** POST /v1/pki/roots response. */
export interface CreateCaRootResponse {
  root: CaRoot;
  intermediate_not_after: string;
}

/** POST /v1/pki/roots/:name/issue/:role response — `private_key_pem` is returned ONCE. */
export interface IssueCertResponse {
  serial_hex: string;
  cert_pem: string;
  /** Leaf private key — only ever present in this response. */
  private_key_pem: string;
  ca_chain_pem: string;
  not_before: string;
  not_after: string;
}

export class PkiResource {
  constructor(private readonly client: APIClient) {}

  async listRoots(): Promise<CaRoot[]> {
    return unwrap(await this.client.request<Envelope<CaRoot[]>>({
      method: "GET", path: "/v1/pki/roots",
    }));
  }

  async createRoot(
    input: { name: string; subject: Record<string, unknown> },
    opts?: { idempotencyKey?: string },
  ): Promise<CreateCaRootResponse> {
    return unwrap(await this.client.request<Envelope<CreateCaRootResponse>>({
      method: "POST", path: "/v1/pki/roots", body: input, idempotencyKey: opts?.idempotencyKey,
    }));
  }

  /** Raw PEM text (text/x-pem-file) — no JSON wrapper. */
  async getRootCert(name: string): Promise<string> {
    return this.client.request({ method: "GET", path: `/v1/pki/roots/${encodeURIComponent(name)}/cert` });
  }

  async rotateIntermediate(name: string, opts?: { idempotencyKey?: string }): Promise<{ intermediate_id: string; not_after: string }> {
    return unwrap(await this.client.request<Envelope<{ intermediate_id: string; not_after: string }>>({
      method: "POST",
      path: `/v1/pki/roots/${encodeURIComponent(name)}/rotate-intermediate`,
      body: {},
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  /** Raw CRL text (text/plain) — no JSON wrapper. */
  async getCrl(name: string): Promise<string> {
    return this.client.request({ method: "GET", path: `/v1/pki/roots/${encodeURIComponent(name)}/crl` });
  }

  async listRoles(rootName: string): Promise<CaRole[]> {
    return unwrap(await this.client.request<Envelope<CaRole[]>>({
      method: "GET", path: `/v1/pki/roots/${encodeURIComponent(rootName)}/roles`,
    }));
  }

  async createRole(
    rootName: string,
    input: {
      role_name: string;
      allowed_domains?: string[];
      allow_subdomains?: boolean;
      allow_wildcards?: boolean;
      max_ttl_seconds?: number;
      default_ttl_seconds?: number;
    },
    opts?: { idempotencyKey?: string },
  ): Promise<CaRole> {
    return unwrap(await this.client.request<Envelope<CaRole>>({
      method: "POST",
      path: `/v1/pki/roots/${encodeURIComponent(rootName)}/roles`,
      body: input,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  /** ``private_key_pem`` is returned once — store it immediately. */
  async issueCert(
    rootName: string,
    role: string,
    input: {
      subject: Record<string, unknown>;
      san_dns?: string[];
      san_ip?: string[];
      ttl_seconds?: number;
    },
    opts?: { idempotencyKey?: string },
  ): Promise<IssueCertResponse> {
    return unwrap(await this.client.request<Envelope<IssueCertResponse>>({
      method: "POST",
      path: `/v1/pki/roots/${encodeURIComponent(rootName)}/issue/${encodeURIComponent(role)}`,
      body: input,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  async revokeCert(
    rootName: string,
    input: { serial_hex: string; reason?: string },
    opts?: { idempotencyKey?: string },
  ): Promise<{ revoked: boolean }> {
    return unwrap(await this.client.request<Envelope<{ revoked: boolean }>>({
      method: "POST",
      path: `/v1/pki/roots/${encodeURIComponent(rootName)}/revoke`,
      body: input,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }
}
