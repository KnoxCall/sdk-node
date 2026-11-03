// Audit Logs resource.

import type { APIClient } from "../core.js";
import {
  type Page,
  type PageParams,
  type CursorPage,
  type CursorParams,
  iteratePages,
  iterateCursor,
} from "./shared.js";

/** Row returned by GET /v1/audit-logs. */
export interface AuditLogEntry {
  id: string;
  action: string;
  resource_type: string;
  resource_id: string | null;
  /**
   * Free-form event context — shape varies by action. Always sanitised by the
   * server (credential-shaped values and URL userinfo removed). `{}` when
   * `details_redacted` is true.
   */
  details: Record<string, unknown>;
  /**
   * `true` when `details` was withheld from this caller: a user-bound token
   * whose holder may not read audit details (only Admins and Owners may). API
   * keys and OAuth clients holding `audit_log:list` always receive sanitised
   * details. Optional because older servers do not send it.
   */
  details_redacted?: boolean;
  ip_address: string | null;
  created_at: string;
}

/**
 * Filters for the cursor feed. `action` is exact; `action_prefix` subscribes to
 * a whole SURFACE and is the one a SIEM shipper wants — `ai_gateway.` covers
 * every AI-gateway action INCLUDING names added after the integration was
 * built, which exact-match cannot.
 */
export interface AuditEventsParams extends CursorParams {
  action?: string;
  action_prefix?: string;
  resource_type?: string;
}

export interface ListAuditLogsParams extends PageParams {
  /** Filter to a single action (exact match). */
  action?: string;
  /** Filter to a single resource type (exact match). */
  resource_type?: string;
}

export class AuditLogsResource {
  constructor(private readonly client: APIClient) {}

  async list(params?: ListAuditLogsParams): Promise<Page<AuditLogEntry>> {
    return this.client.request<Page<AuditLogEntry>>({
      method: "GET",
      path: "/v1/audit-logs",
      query: params as Record<string, string | number | undefined>,
    });
  }

  iterate(params?: ListAuditLogsParams): AsyncIterableIterator<AuditLogEntry> {
    return iteratePages((page) => this.list({ ...params, page }), params?.page ?? 1);
  }

  /**
   * One page of the keyset audit event feed — the endpoint a SIEM shipper
   * should use.
   *
   * `list()` is offset-paginated over `created_at DESC`, which is right for a
   * console and wrong for a feed: rows written while you page shift the offsets
   * underneath you, so events are skipped or repeated with no way to tell
   * which. This is ordered by a monotonic sequence and resumes from an opaque
   * cursor.
   *
   * Delivery is AT LEAST ONCE — dedupe on `id`. `meta.next_cursor` is OPAQUE;
   * pass it back verbatim rather than parsing it. `null` means the feed is
   * drained to the watermark, not that it has ended.
   */
  async events(params?: AuditEventsParams): Promise<CursorPage<AuditLogEntry>> {
    return this.client.request<CursorPage<AuditLogEntry>>({
      method: "GET",
      path: "/v1/audit-logs/events",
      query: params as Record<string, string | number | undefined>,
    });
  }

  /** Walk the event feed until it is drained to the watermark. */
  iterateEvents(params?: AuditEventsParams): AsyncIterableIterator<AuditLogEntry> {
    return iterateCursor(
      (cursor) => this.events({ ...params, cursor }),
      params?.cursor,
    );
  }
}
