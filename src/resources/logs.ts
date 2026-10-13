// Request Logs resource — the per-call proxy log, and Merkle inclusion proofs.
//
// Distinct from `auditLogs`, which is the CHANGE log (who edited what). This is
// the record of requests that went THROUGH the proxy, and `proof()` is the
// evidence that a given entry existed, unaltered, when it was anchored.

import type { APIClient } from "../core.js";
import {
  type CursorPage,
  type CursorParams,
  type Envelope,
  iterateCursor,
} from "./shared.js";

/**
 * One proxied request.
 *
 * The first twelve fields are exactly what the Merkle anchor commits to, in
 * that order. Everything after `ts` is operational detail and is NOT part of
 * the leaf — so a verifier reconstructing the leaf hash uses the first twelve
 * and nothing else.
 */
export interface RequestLog {
  /**
   * Row id, a DECIMAL STRING. `api_requests.id` is a bigint; JSON numbers are
   * doubles and cannot hold one exactly past 2^53, so it is never a number.
   */
  id: string;
  /** Stable per-request id, also returned in the `X-Request-Id` header. Dedupe on this. */
  request_id: string;
  tenant_id: string;
  route_id: string | null;
  /** Identity tier — absent (not null) unless the caller holds `log:read_identity`. */
  matched_client_id?: string | null;
  /** Identity tier. How the caller was attributed: `ip`, `mtls_thumbprint`, … */
  identification_method?: string | null;
  method: string | null;
  status_code: number | null;
  /** Identity tier. Host form, without a prefix length. */
  src_ip?: string | null;
  environment: string | null;
  /**
   * Live/Test partition. `null` on rows written before the partition existed,
   * which are treated as Live. Null, false and true are three distinct facts
   * and the anchor keeps them apart.
   */
  sandbox: boolean | null;
  ts: string;

  path: string | null;
  latency_ms: number | null;
  upstream_host: string | null;
  error: string | null;
  rate_limited: boolean | null;
  proxy_mode: string | null;
  /**
   * How the call arrived at the Route: `sdk_intercept` when a KnoxCall SDK's
   * route-aware interceptor rerouted a third-party SDK's request (PARITY
   * §21.2), `direct` for a plain `call()` and for every row written before the
   * marker existed. Informational only.
   */
  client_origin: "direct" | "sdk_intercept";
  /** Opaque resume token. Pass the last row's value as `cursor`. */
  cursor: string;
}

export interface ListRequestLogsParams extends CursorParams {
  /** Only requests handled by this route. */
  route_id?: string;
  /** Only requests that returned this status. */
  status_code?: number;
}

/** One step of an inclusion proof. */
export interface ProofStep {
  /** Hex sibling hash. */
  hash: string;
  /** True when the sibling is the RIGHT operand: hash(accumulator, sibling). */
  right: boolean;
}

/** Why a proof could not be produced. Absent when `verified` is true. */
export type ProofFailureReason =
  | "not_yet_anchored"
  | "range_incomplete"
  | "range_grew"
  | "root_mismatch"
  | "row_not_in_range"
  | "anchor_range_too_large";

export interface RequestLogProof extends RequestLog {
  /** Whether any anchor covers this row yet. */
  anchored: boolean;
  /** Whether the anchored range still recomputes to the root it recorded. Absent when `anchored` is false. */
  verified?: boolean;
  reason?: ProofFailureReason;
  /** A sentence explaining `reason` in context. */
  detail?: string;
  observed_leaf_count?: number;
  recomputed_root?: string | null;
  anchor?: {
    id: string;
    /** Position in the hash-chained critical audit log, as a decimal string. */
    sequence_number: string;
    anchored_at: string;
    algo: string;
    /** Hex root committed by the anchor. */
    merkle_root: string;
    leaf_count: number;
    from_id: string;
    to_id: string;
    /** Hex row hash of the anchor's own audit-chain entry. Ties the root to the chain. */
    chain_row_hash: string | null;
  };
  leaf_index?: number;
  /** Hex SHA-256 of this row's canonical leaf bytes. */
  leaf_hash?: string;
  /** Absent whenever `verified` is not true — a proof never accompanies a failed verification. */
  proof?: ProofStep[];
  verification?: {
    algo: string;
    /** Field order the leaf was serialised in. Fixed forever. */
    leaf_fields: string[];
    /** The canonicalisation and domain-separation scheme, in prose. */
    note: string;
  };
  _redacted?: string[];
}

export class LogsResource {
  constructor(private readonly client: APIClient) {}

  /**
   * One page of the request log feed.
   *
   * Keyset, not offset: ordering is ascending `cursor` and stable across calls.
   * Delivery is AT LEAST ONCE — dedupe on `request_id`. `meta.next_cursor` is
   * OPAQUE; pass it back verbatim.
   *
   * `meta.next_cursor === null` means you have drained the feed to the
   * watermark, NOT that it has ended — poll again later with your last non-null
   * cursor.
   */
  async list(params?: ListRequestLogsParams): Promise<CursorPage<RequestLog>> {
    return this.client.request<CursorPage<RequestLog>>({
      method: "GET",
      path: "/v1/logs",
      query: params as Record<string, string | number | undefined>,
    });
  }

  /**
   * Walk the feed from `params.cursor`, yielding rows until it is drained to
   * the watermark. See `iterateCursor` for why this terminates rather than
   * polling forever.
   */
  iterate(params?: ListRequestLogsParams): AsyncIterableIterator<RequestLog> {
    return iterateCursor(
      (cursor) => this.list({ ...params, cursor }),
      params?.cursor,
    );
  }

  /** Fetch a single request by its `request_id` (the `X-Request-Id` header value). */
  async get(requestId: string): Promise<RequestLog> {
    const res = await this.client.request<Envelope<RequestLog>>({
      method: "GET",
      path: `/v1/logs/${encodeURIComponent(requestId)}`,
    });
    return res.data;
  }

  /**
   * Merkle inclusion proof for one request.
   *
   * Resolves for every outcome — read `anchored` and `verified` rather than
   * catching. `verified: false` with `reason: "range_incomplete"` is the
   * expected result for an old entry whose range has since been trimmed by
   * retention, and is NOT a sign of tampering; `reason: "root_mismatch"` is.
   */
  async proof(requestId: string): Promise<RequestLogProof> {
    const res = await this.client.request<Envelope<RequestLogProof>>({
      method: "GET",
      path: `/v1/logs/${encodeURIComponent(requestId)}/proof`,
    });
    return res.data;
  }
}
