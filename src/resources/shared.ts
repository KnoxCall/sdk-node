// Response envelope + pagination primitives shared by every resource.
//
// The server wraps every JSON response in `{ data, meta }`
// (src/client-api/helpers.ts). Single-object methods unwrap `data`;
// paginated lists return the typed envelope as-is and take `page` /
// `per_page` query params (server default 20, cap 100).
//
// TWO endpoints are keyset/cursor paginated instead, and deliberately so:
// `GET /v1/audit-logs/events` and `GET /v1/logs`. Offset pagination over a
// table that is being written to skips and repeats rows with no way to tell
// which, which is fine for a console and wrong for a feed. Use `CursorPage`
// and `iterateCursor` for those. (Earlier revisions of this comment said
// there was no cursor pagination anywhere on the API; that stopped being true
// when the audit event feed shipped.)

/** Meta on non-paginated success responses. */
export interface ResponseMeta {
  request_id?: string;
  [key: string]: unknown;
}

/** Meta on paginated list responses (src/client-api/helpers.ts `paginated()`). */
export interface PageMeta {
  total: number;
  page: number;
  per_page: number;
  total_pages: number;
  request_id: string;
}

/** The `{data, meta}` wrapper the server puts around every JSON response. */
export interface Envelope<T> {
  data: T;
  meta?: ResponseMeta;
}

/** A single page of a paginated list, mirroring the server envelope exactly. */
export interface Page<T> {
  data: T[];
  meta: PageMeta;
}

/** Query params accepted by every paginated list endpoint. */
export interface PageParams {
  /** 1-based page number. Server default 1. */
  page?: number;
  /** Items per page. Server default 20, cap 100. */
  per_page?: number;
}

/** Unwrap a `{data, meta}` envelope to its `data`. */
export function unwrap<T>(envelope: Envelope<T>): T {
  return envelope.data;
}

/**
 * Walk a paginated endpoint page by page, yielding individual items.
 * Starts at `startPage` (default 1) and stops when the server reports
 * `page >= meta.total_pages` or (defensively) an empty page comes back.
 */
export async function* iteratePages<T>(
  fetchPage: (page: number) => Promise<Page<T>>,
  startPage = 1,
): AsyncIterableIterator<T> {
  let page = startPage;
  while (true) {
    const res = await fetchPage(page);
    for (const item of res.data) yield item;
    if (res.data.length === 0) return;
    if (res.meta && page >= res.meta.total_pages) return;
    page += 1;
  }
}

/**
 * Meta on a keyset/cursor feed (`GET /v1/audit-logs/events`, `GET /v1/logs`).
 *
 * `next_cursor` is OPAQUE. Pass it back verbatim; never parse, compare or
 * reconstruct it — the server may change its encoding, and a client that
 * decodes it breaks the resume contract the first time that happens.
 */
export interface CursorMeta {
  /** Pass as `cursor` on the next call. `null` means the feed is drained to the watermark — NOT that it has ended. */
  next_cursor: string | null;
  limit: number;
  /** Always `at_least_once`. Consumers MUST dedupe. */
  delivery: string;
  /** The field to dedupe on: `id` for audit events, `request_id` for request logs. */
  dedupe_on: string;
  /** How far the feed trails real time, in seconds. */
  watermark_seconds: number;
  /** Tiers withheld from every row, e.g. `["identity"]`. */
  _redacted?: string[];
  request_id?: string;
  [key: string]: unknown;
}

/** One page of a cursor feed. */
export interface CursorPage<T> {
  data: T[];
  meta: CursorMeta;
}

/** Query params common to every cursor feed. */
export interface CursorParams {
  /** The opaque `meta.next_cursor` from the previous response. Omit to start at the beginning. */
  cursor?: string;
  /** Rows per page. */
  limit?: number;
}

/**
 * Walk a cursor feed, yielding individual rows.
 *
 * Stops when the server reports `next_cursor: null`, which means "drained to
 * the watermark". That is NOT the end of the feed: to keep following it, call
 * again later with the last non-null cursor you saw. This helper therefore
 * terminates rather than polling — a generator that blocked forever would be
 * impossible to use from a batch job.
 *
 * Delivery is AT LEAST ONCE. Dedupe on `meta.dedupe_on`.
 */
export async function* iterateCursor<T>(
  fetchPage: (cursor?: string) => Promise<CursorPage<T>>,
  startCursor?: string,
): AsyncIterableIterator<T> {
  let cursor = startCursor;
  while (true) {
    const res = await fetchPage(cursor);
    for (const item of res.data) yield item;
    const next = res.meta?.next_cursor ?? null;
    if (next === null) return;
    cursor = next;
  }
}
