// Vaults resource — data tokenization.

import type { APIClient } from "../core.js";
import { type Envelope, type Page, type PageParams, iteratePages, unwrap } from "./shared.js";

/** Full vault row (GET /v1/vaults list rows, POST, PATCH). */
export interface Vault {
  id: string;
  tenant_id: string;
  name: string;
  token_format: string;
  crypto_key_id: string;
  // 'managed' (default): KnoxCall stores the encrypted value behind a
  // format-preserving lookup token. 'dual': KnoxCall stores only the key;
  // tokenize returns a portable kc: ciphertext the customer stores.
  custody_mode: "managed" | "dual";
  default_ttl_seconds: number | null;
  metadata_jsonb: Record<string, unknown>;
  description: string | null;
  enabled: boolean;
  created_at: string;
  updated_at: string;
  created_by: string | null;
  sandbox: boolean;
}

/** GET /v1/vaults/:nameOrId response — the vault plus live token stats. */
export interface VaultDetail extends Vault {
  stats: { token_count: number; active_count: number; expiring_in_24h: number };
}

/**
 * The CARD's own expiry month and year, for a `pan` vault only.
 *
 * NOT `ttl_seconds`, which is how long the TOKEN lives. Both fields or neither;
 * the year is four digits (`2029`, never `29`). Supplying them subscribes the
 * token to the `vault.token.expiring` webhook, emitted 60 and 30 days before the
 * card expires. Offering them to a non-`pan` vault is a `validation_error`.
 */
export interface CardExpiry {
  card_exp_month?: number;
  card_exp_year?: number;
}

/** POST /v1/vaults/:nameOrId/tokens response. */
export interface Token {
  id: string;
  token: string;
  expires_at: string | null;
  created_at: string;
  /**
   * The LAST DAY of the card's expiry month (`2029-07-31`), or null. A token
   * created before 2026-09-17, or one whose tokenize call named no expiry,
   * carries null and cannot be backfilled — the expiry was never captured.
   */
  card_expires_on?: string | null;
  /**
   * BIN intelligence: how the issuer funds the card, and the issuer's country
   * as ISO 3166-1 alpha-2, derived from the card's first six digits.
   *
   * BOTH ARE NULL ON EVERY TOKEN TODAY, and will be until KnoxCall licenses a
   * BIN table. Treat them as optional indefinitely — they are also null for
   * every non-`pan` vault and for any BIN a future table does not carry.
   */
  card_funding_type?: 'credit' | 'debit' | 'prepaid' | null;
  card_issuing_country?: string | null;
}

/** Row returned by GET /v1/vaults/:nameOrId/tokens (paginated). */
export interface VaultTokenListItem extends Token {
  created_by_api_key_id: string | null;
  created_by_user_id: string | null;
}

/** GET /v1/vaults/:nameOrId/tokens/:idOrToken (detokenize) response. */
export interface DetokenizeResponse extends Token {
  value: string;
  value_b64: string;
  metadata: Record<string, unknown> | null;
  crypto_key_version: number;
}

export class VaultsResource {
  constructor(private readonly client: APIClient) {}

  async list(params?: PageParams): Promise<Page<Vault>> {
    return this.client.request<Page<Vault>>({
      method: "GET", path: "/v1/vaults",
      query: params as Record<string, string | number | undefined>,
    });
  }

  iterate(params?: PageParams): AsyncIterableIterator<Vault> {
    return iteratePages((page) => this.list({ ...params, page }), params?.page ?? 1);
  }

  async get(nameOrId: string): Promise<VaultDetail> {
    return unwrap(await this.client.request<Envelope<VaultDetail>>({
      method: "GET", path: `/v1/vaults/${encodeURIComponent(nameOrId)}`,
    }));
  }

  async create(
    input: { name: string; token_format?: string; custody_mode?: "managed" | "dual"; default_ttl_seconds?: number; description?: string; metadata_jsonb?: Record<string, unknown> },
    opts?: { idempotencyKey?: string },
  ): Promise<Vault> {
    return unwrap(await this.client.request<Envelope<Vault>>({
      method: "POST", path: "/v1/vaults", body: input, idempotencyKey: opts?.idempotencyKey,
    }));
  }

  async update(
    nameOrId: string,
    input: { default_ttl_seconds?: number; description?: string; enabled?: boolean; metadata_jsonb?: Record<string, unknown> },
    opts?: { idempotencyKey?: string },
  ): Promise<Vault> {
    return unwrap(await this.client.request<Envelope<Vault>>({
      method: "PATCH", path: `/v1/vaults/${encodeURIComponent(nameOrId)}`,
      body: input, idempotencyKey: opts?.idempotencyKey,
    }));
  }

  async delete(nameOrId: string, opts?: { idempotencyKey?: string }): Promise<{ deleted: true }> {
    return unwrap(await this.client.request<Envelope<{ deleted: true }>>({
      method: "DELETE", path: `/v1/vaults/${encodeURIComponent(nameOrId)}`,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  async rotate(nameOrId: string, opts?: { idempotencyKey?: string }): Promise<{ new_version: number }> {
    return unwrap(await this.client.request<Envelope<{ new_version: number }>>({
      method: "POST", path: `/v1/vaults/${encodeURIComponent(nameOrId)}/rotate`,
      body: {}, idempotencyKey: opts?.idempotencyKey,
    }));
  }

  // ── Token operations ────────────────────────────────────────────────────────

  async tokenize(
    nameOrId: string,
    input: { value: string; metadata?: Record<string, unknown>; ttl_seconds?: number } & CardExpiry,
    opts?: { idempotencyKey?: string },
  ): Promise<Token> {
    return unwrap(await this.client.request<Envelope<Token>>({
      method: "POST", path: `/v1/vaults/${encodeURIComponent(nameOrId)}/tokens`,
      body: input, idempotencyKey: opts?.idempotencyKey,
    }));
  }

  async bulkTokenize(
    nameOrId: string,
    input: { values: Array<{ value: string; metadata?: Record<string, unknown>; ttl_seconds?: number } & CardExpiry> },
    opts?: { idempotencyKey?: string },
  ): Promise<{ tokens: Token[]; count: number }> {
    return unwrap(await this.client.request<Envelope<{ tokens: Token[]; count: number }>>({
      method: "POST", path: `/v1/vaults/${encodeURIComponent(nameOrId)}/tokens/bulk`,
      body: input, idempotencyKey: opts?.idempotencyKey,
    }));
  }

  async listTokens(
    nameOrId: string,
    params?: PageParams,
  ): Promise<Page<VaultTokenListItem>> {
    return this.client.request<Page<VaultTokenListItem>>({
      method: "GET", path: `/v1/vaults/${encodeURIComponent(nameOrId)}/tokens`,
      query: params as Record<string, string | number | undefined>,
    });
  }

  iterateTokens(nameOrId: string, params?: PageParams): AsyncIterableIterator<VaultTokenListItem> {
    return iteratePages((page) => this.listTokens(nameOrId, { ...params, page }), params?.page ?? 1);
  }

  /** Retrieve the plaintext value for a token. */
  async detokenize(nameOrId: string, idOrToken: string): Promise<DetokenizeResponse> {
    return unwrap(await this.client.request<Envelope<DetokenizeResponse>>({
      method: "GET",
      path: `/v1/vaults/${encodeURIComponent(nameOrId)}/tokens/${encodeURIComponent(idOrToken)}`,
    }));
  }

  async updateToken(
    nameOrId: string,
    idOrToken: string,
    input: { metadata: Record<string, unknown> },
    opts?: { idempotencyKey?: string },
  ): Promise<{ updated: true }> {
    return unwrap(await this.client.request<Envelope<{ updated: true }>>({
      method: "PATCH",
      path: `/v1/vaults/${encodeURIComponent(nameOrId)}/tokens/${encodeURIComponent(idOrToken)}`,
      body: input, idempotencyKey: opts?.idempotencyKey,
    }));
  }

  async deleteToken(
    nameOrId: string,
    idOrToken: string,
    opts?: { idempotencyKey?: string },
  ): Promise<{ deleted: true }> {
    return unwrap(await this.client.request<Envelope<{ deleted: true }>>({
      method: "DELETE",
      path: `/v1/vaults/${encodeURIComponent(nameOrId)}/tokens/${encodeURIComponent(idOrToken)}`,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }
}
