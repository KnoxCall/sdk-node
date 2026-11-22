// Crypto / Transit resource — Vault-style encryption-as-a-service.

import type { APIClient } from "../core.js";
import { type Envelope, unwrap } from "./shared.js";

/** Full transit key row (GET /v1/crypto/keys/:name, POST /v1/crypto/keys). */
export interface CryptoKey {
  id: string;
  tenant_id: string;
  name: string;
  key_type: string;
  mode: "cloud-only" | "bundled";
  current_version: number;
  deletion_allowed: boolean;
  description: string | null;
  created_at: string;
  updated_at: string;
  created_by: string | null;
  sandbox: boolean;
}

/** Projection returned by GET /v1/crypto/keys (bare array — no pagination). */
export interface CryptoKeySummary {
  id: string;
  name: string;
  key_type: string;
  mode: "cloud-only" | "bundled";
  current_version: number;
  deletion_allowed: boolean;
  description: string | null;
  created_at: string;
  updated_at: string;
}

/** POST /v1/inspect response — ciphertext metadata, no decryption. */
export interface InspectResult {
  encrypted: boolean;
  scheme?: "kc";
  version?: number;
  datatype?: string;
  key_ref?: { tenantId: string; appKeyId: string; keyVersion: number };
  /** Non-reversible fingerprint of the CIPHERTEXT bytes — safe to expose. */
  fingerprint?: string;
}

/**
 * GET /v1/encrypt/sealing-bundle response — the public bits a browser needs
 * to seal values client-side. No private material.
 */
export interface SealingBundle {
  /** base64url-encoded raw EC point of the tenant's ecdh public key. */
  public_key_raw: string;
  key_ref: { tenant_id: string; app_key_id: string; key_version: number };
}

/** POST /v1/client-tokens response. */
export interface ClientTokenResponse {
  /** Single-use capability token — hand to the browser/agent. */
  token: string;
  expires_at: string;
  action: string;
  /** `tokenize` only — the resolved vault the capability is bound to. */
  vault_id?: string;
  /** `tokenize` only — the normalized, deduped, sorted origin binding. */
  origins?: string[];
}

/**
 * POST /v1/client-tokens request.
 *
 * A union, because the two bindings are mutually exclusive: the payload-pinned
 * actions take the exact `data` they are bound to, and `tokenize` — whose value
 * does not exist yet — takes a vault and the page origins it may be presented
 * from instead.
 */
export type MintClientTokenInput =
  | { action: "decrypt" | "detokenize"; data: string; role?: string; ttl_seconds?: number }
  | {
      action: "tokenize";
      /** Vault name or id. Resolved against your tenant and the current Live/Test space. */
      vault: string;
      /**
       * 1-10 exact page origins, each `https://host[:port]` with no path,
       * query, fragment, credentials or trailing slash. Wildcards are not
       * supported in any form — list each origin, or mint per page.
       */
      origins: string[];
      role?: string;
      ttl_seconds?: number;
    };

export class CryptoResource {
  constructor(private readonly client: APIClient) {}

  // ── Key management ──────────────────────────────────────────────────────────

  async listKeys(): Promise<CryptoKeySummary[]> {
    return unwrap(await this.client.request<Envelope<CryptoKeySummary[]>>({
      method: "GET", path: "/v1/crypto/keys",
    }));
  }

  async getKey(name: string): Promise<CryptoKey> {
    return unwrap(await this.client.request<Envelope<CryptoKey>>({
      method: "GET", path: `/v1/crypto/keys/${encodeURIComponent(name)}`,
    }));
  }

  async createKey(
    input: { name: string; mode: string; description?: string; key_type?: string },
    opts?: { idempotencyKey?: string },
  ): Promise<CryptoKey> {
    return unwrap(await this.client.request<Envelope<CryptoKey>>({
      method: "POST", path: "/v1/crypto/keys", body: input, idempotencyKey: opts?.idempotencyKey,
    }));
  }

  /**
   * Raise or lower the key's destroy safety latch (`deletion_allowed`).
   *
   * A version can only be destroyed while this is `true`, and every new key
   * ships with it `false`. `destroyKeyVersion` on a key with the latch down is
   * refused with a **409** (`deletion_not_allowed`) — a client error, never
   * retry it unchanged; raise the latch, destroy, then lower it again.
   */
  async updateKey(
    name: string,
    input: { deletion_allowed: boolean },
    opts?: { idempotencyKey?: string },
  ): Promise<{ name: string; deletion_allowed: boolean }> {
    return unwrap(await this.client.request<Envelope<{ name: string; deletion_allowed: boolean }>>({
      method: "PATCH",
      path: `/v1/crypto/keys/${encodeURIComponent(name)}`,
      body: input,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  async rotateKey(name: string, opts?: { idempotencyKey?: string }): Promise<{ new_version: number }> {
    return unwrap(await this.client.request<Envelope<{ new_version: number }>>({
      method: "POST",
      path: `/v1/crypto/keys/${encodeURIComponent(name)}/rotate`,
      body: {},
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  async destroyKeyVersion(name: string, version: number, opts?: { idempotencyKey?: string }): Promise<{ destroyed: number }> {
    return unwrap(await this.client.request<Envelope<{ destroyed: number }>>({
      method: "DELETE",
      path: `/v1/crypto/keys/${encodeURIComponent(name)}/versions/${version}`,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  async getPublicKey(
    name: string,
    params?: { version?: number },
  ): Promise<{ pem: string; jwk: Record<string, unknown>; key_version: number }> {
    return unwrap(await this.client.request<Envelope<{ pem: string; jwk: Record<string, unknown>; key_version: number }>>({
      method: "GET",
      path: `/v1/crypto/keys/${encodeURIComponent(name)}/public-key`,
      query: params as Record<string, number | undefined>,
    }));
  }

  // ── Encryption / decryption ─────────────────────────────────────────────────

  async encrypt(
    name: string,
    input: { plaintext?: string; plaintext_b64?: string },
    opts?: { idempotencyKey?: string },
  ): Promise<{ ciphertext: string; key_version: number }> {
    return unwrap(await this.client.request<Envelope<{ ciphertext: string; key_version: number }>>({
      method: "POST",
      path: `/v1/crypto/keys/${encodeURIComponent(name)}/encrypt`,
      body: input,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  async decrypt(
    name: string,
    input: { ciphertext: string },
    params?: { format?: string },
    opts?: { idempotencyKey?: string },
  ): Promise<{ plaintext_b64?: string; plaintext?: string; key_version: number }> {
    return unwrap(await this.client.request<Envelope<{ plaintext_b64?: string; plaintext?: string; key_version: number }>>({
      method: "POST",
      path: `/v1/crypto/keys/${encodeURIComponent(name)}/decrypt`,
      body: input,
      query: params as Record<string, string | undefined>,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  async rewrap(
    name: string,
    input: { ciphertext: string },
    opts?: { idempotencyKey?: string },
  ): Promise<{ ciphertext: string; key_version: number }> {
    return unwrap(await this.client.request<Envelope<{ ciphertext: string; key_version: number }>>({
      method: "POST",
      path: `/v1/crypto/keys/${encodeURIComponent(name)}/rewrap`,
      body: input,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  // ── Portable kc: encryption (structure-preserving, top-level /v1) ────────────
  // Distinct from the keyed transit encrypt() above: these take arbitrary
  // JSON and return the same shape with scalar leaves swapped for portable,
  // self-describing `kc:` ciphertext strings. Backed by ecdh-p256 keys.

  async encryptData(
    data: unknown,
    input?: { key?: string; role?: string },
    opts?: { idempotencyKey?: string },
  ): Promise<{ ciphertext: unknown; key: string; key_version: number }> {
    return unwrap(await this.client.request<Envelope<{ ciphertext: unknown; key: string; key_version: number }>>({
      method: "POST",
      path: "/v1/encrypt",
      body: { data, key: input?.key, role: input?.role },
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  async decryptData(
    data: unknown,
    input?: { role?: string },
    opts?: { idempotencyKey?: string },
  ): Promise<{ plaintext: unknown }> {
    return unwrap(await this.client.request<Envelope<{ plaintext: unknown }>>({
      method: "POST",
      path: "/v1/decrypt",
      body: { data, role: input?.role },
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  async inspect(value: string): Promise<InspectResult> {
    return unwrap(await this.client.request<Envelope<InspectResult>>({
      method: "POST", path: "/v1/inspect", body: { value },
    }));
  }

  /**
   * Fetch the public sealing bundle for an ecdh key (default key when `key`
   * is omitted): the public key + key_ref a browser needs to seal values
   * client-side. Contains no private material — your backend fetches this
   * with its API key and hands the JSON to the page.
   */
  async getSealingBundle(params?: { key?: string }): Promise<SealingBundle> {
    return unwrap(await this.client.request<Envelope<SealingBundle>>({
      method: "GET",
      path: "/v1/encrypt/sealing-bundle",
      query: params as Record<string, string | undefined>,
    }));
  }

  // Mint a single-use client-side capability token. Hand the returned `token`
  // to a browser/agent so it can perform exactly one bound operation without
  // an API key. Three actions, two bindings:
  //
  //   decrypt / detokenize   payload-pinned to the exact `data` — reveal it
  //                          once via POST /v1/client/{decrypt,detokenize}.
  //   tokenize               bound to a `vault` and a closed set of `origins`
  //                          — the page puts a value INTO that vault via
  //                          POST /v1/client/tokenize, from one of those
  //                          origins, without the value reaching your servers.
  //
  // The consume endpoints are browser operations and live in @knoxcall/browser,
  // deliberately not here (see sdk/PARITY.md).
  async mintClientToken(
    input: MintClientTokenInput,
    opts?: { idempotencyKey?: string },
  ): Promise<ClientTokenResponse> {
    return unwrap(await this.client.request<Envelope<ClientTokenResponse>>({
      method: "POST",
      path: "/v1/client-tokens",
      body: input,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  // ── Signing / verification ──────────────────────────────────────────────────

  async sign(
    name: string,
    input: { data?: string; data_b64?: string; rsa_padding?: string; hash?: string },
    opts?: { idempotencyKey?: string },
  ): Promise<{ signature: string; key_version: number }> {
    return unwrap(await this.client.request<Envelope<{ signature: string; key_version: number }>>({
      method: "POST",
      path: `/v1/crypto/keys/${encodeURIComponent(name)}/sign`,
      body: input,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  async verify(
    name: string,
    input: { data?: string; data_b64?: string; signature: string; rsa_padding?: string; hash?: string },
  ): Promise<{ valid: boolean; key_version: number }> {
    return unwrap(await this.client.request<Envelope<{ valid: boolean; key_version: number }>>({
      method: "POST",
      path: `/v1/crypto/keys/${encodeURIComponent(name)}/verify`,
      body: input,
    }));
  }

  // ── JWT ─────────────────────────────────────────────────────────────────────

  async signJwt(
    name: string,
    input: { claims: Record<string, unknown>; header_overrides?: Record<string, unknown> },
    opts?: { idempotencyKey?: string },
  ): Promise<{ token: string; key_version: number; alg: string }> {
    return unwrap(await this.client.request<Envelope<{ token: string; key_version: number; alg: string }>>({
      method: "POST",
      path: `/v1/crypto/keys/${encodeURIComponent(name)}/jwt`,
      body: input,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  async verifyJwt(
    name: string,
    input: { token: string; expected?: Record<string, unknown> },
  ): Promise<{ valid: boolean; claims?: Record<string, unknown>; key_version?: number; alg?: string; error?: string; kid?: string }> {
    return unwrap(await this.client.request<Envelope<{
      valid: boolean; claims?: Record<string, unknown>; key_version?: number; alg?: string; error?: string; kid?: string;
    }>>({
      method: "POST",
      path: `/v1/crypto/keys/${encodeURIComponent(name)}/jwt/verify`,
      body: input,
    }));
  }

  // ── Webhook signing ─────────────────────────────────────────────────────────

  async signWebhook(
    name: string,
    input: { payload?: string; payload_b64?: string; timestamp_seconds?: number; format?: string },
    opts?: { idempotencyKey?: string },
  ): Promise<{ signature_header: string; timestamp_seconds: number; key_version: number; format: string }> {
    return unwrap(await this.client.request<Envelope<{
      signature_header: string; timestamp_seconds: number; key_version: number; format: string;
    }>>({
      method: "POST",
      path: `/v1/crypto/keys/${encodeURIComponent(name)}/webhook-sign`,
      body: input,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }
}
