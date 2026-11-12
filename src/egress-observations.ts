// Uncovered-egress observations (PARITY §21.3; founder decisions 2026-09-26).
//
// A route-aware interceptor sees every outbound request the process makes,
// and sends only the covered ones through KnoxCall. The rest go direct — and
// among them are calls that carry a credential the platform does not hold:
// "uncovered egress". This module records those (host, first path segment,
// method, credential header NAME) in memory and reports the aggregate to
// `POST /v1/wrap/egress-observations`, so the dashboard can show a tenant
// which credentials are still leaving their process un-custodied.
//
// What is recorded is bounded on purpose, and the bound is the feature:
//   • names, never values — the credential header's NAME, never its value;
//   • the FIRST path segment only — never the query string, never the body,
//     never a deeper path;
//   • counts per (host, segment, method, header) with first/last seen.
//
// Only a DIRECT decision with reason `unlisted` is observed. `own_host`,
// `route_around`, `kill_switch`, `outside_context` and `unparseable` are
// never reported — the first two are the platform's own traffic and the
// caller's explicit "send this direct" rule, the others are the kill switch
// and the scoping the caller asked for.
//
// Nothing here may add latency to, throw into, or alter the application's
// request: `record()` is synchronous and cheap, the flush is a background
// timer (unref'd) or a fire-and-forget promise, and every failure is
// swallowed after one warning. The reporter is process memory only.

import type { EgressObservation, EgressObservationsReport } from "./resources/wrap.js";
import { isIP } from "node:net";
import { normaliseHost } from "./intercept-resolver.js";
import { warnOnce } from "./warn.js";

/** Header names (lower-case) that carry a credential. The shared fixture pins this list. */
export const CREDENTIAL_HEADER_ALLOWLIST: readonly string[] = [
  "authorization",
  "proxy-authorization",
  "x-api-key",
  "api-key",
  "apikey",
  "x-apikey",
  "x-auth-token",
  "x-access-token",
  "x-token",
  "token",
  "x-secret",
  "x-secret-key",
  "x-client-secret",
  "ocp-apim-subscription-key",
  "x-goog-api-key",
  "x-amz-security-token",
  "x-shopify-access-token",
  "klaviyo-api-key",
  "x-hubspot-api-key",
];

/** A lower-cased header name ending in one of these also counts. */
export const CREDENTIAL_HEADER_SUFFIXES: readonly string[] = ["-api-key", "-token", "-secret", "-auth"];

/** The methods the server accepts (upper-case). Anything else would be dropped as `invalid_method`. */
export const OBSERVATION_METHODS: readonly string[] = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE"];

const ALLOWLIST_INDEX = new Map(CREDENTIAL_HEADER_ALLOWLIST.map((n, i) => [n, i]));
// The server's shape check (src/wrap/egress-observations.ts): an RFC 9110
// token of letters, digits, `_` and `-`, at most 64 characters.
const HEADER_NAME_RE = /^[a-z0-9][a-z0-9_-]*$/;
const MAX_HEADER_NAME_LENGTH = 64;
const FIRST_SEGMENT_RE = /^\/[A-Za-z0-9._~!$&'()*+,;=:@%-]{0,255}$/;

/** Whether a header NAME (any casing) is credential-bearing — exactly the server's rule. */
export function isCredentialHeaderName(name: string): boolean {
  const n = String(name ?? "").trim().toLowerCase();
  if (!n || n.length > MAX_HEADER_NAME_LENGTH || !HEADER_NAME_RE.test(n)) return false;
  if (ALLOWLIST_INDEX.has(n)) return true;
  return CREDENTIAL_HEADER_SUFFIXES.some((s) => n.length > s.length && n.endsWith(s));
}

/**
 * The credential header NAME to report for a request, or null when none is
 * present. Allowlist entries win in allowlist order; then the
 * lexicographically smallest suffix match. A header whose value is empty
 * after trimming never counts. Only names are read — the values are looked
 * at solely to discard empties and are never returned.
 */
export function credentialHeaderName(headers: Record<string, string> | Iterable<[string, string]>): string | null {
  let best: string | null = null;
  let bestRank = Number.POSITIVE_INFINITY;
  let bestSuffix: string | null = null;
  const entries: Iterable<[string, string]> =
    typeof (headers as Iterable<[string, string]>)[Symbol.iterator] === "function" && !isPlainObject(headers)
      ? (headers as Iterable<[string, string]>)
      : Object.entries(headers as Record<string, string>);
  for (const [rawName, rawValue] of entries) {
    const name = String(rawName ?? "").trim().toLowerCase();
    if (!name) continue;
    if (String(rawValue ?? "").trim() === "") continue;
    const rank = ALLOWLIST_INDEX.get(name);
    if (rank !== undefined) {
      if (rank < bestRank) {
        bestRank = rank;
        best = name;
      }
      continue;
    }
    if (isCredentialHeaderName(name)) {
      if (bestSuffix === null || name < bestSuffix) bestSuffix = name;
    }
  }
  return best ?? bestSuffix;
}

function isPlainObject(v: unknown): boolean {
  return typeof v === "object" && v !== null && !Array.isArray(v) && typeof (v as Map<unknown, unknown>).entries !== "function";
}

// ── a credential in the first path segment (server #1022) ───────────────────
// Some APIs put a credential in the path (Telegram's `/bot<id>:<secret>/...`).
// The server stores such a segment as `/`; the SDK applies the SAME rule
// before sending, so the value never leaves the process. Deliberately wide: a
// false positive costs one segment of dashboard detail.

/** Longer than this and a single segment is not a resource name. */
export const MAX_PLAIN_FIRST_SEGMENT_LENGTH = 64;

const CREDENTIAL_SEGMENT_PREFIXES: readonly RegExp[] = [
  /^bot\d+:/i,
  /^(sk|pk|rk)_(live|test)_/i,
  /^sk-/,
  /^xox[abposr]-/,
  /^gh[pousr]_/,
  /^github_pat_/,
  /^glpat-/,
  /^shp(at|ca|pa|ss)_/,
  /^(AKIA|ASIA)[0-9A-Z]{12,}/,
  /^AIza[0-9A-Za-z_-]{20,}/,
  /^eyJ[A-Za-z0-9_-]{8,}/,
  /^SG\./,
];

function mixesClasses(run: string): boolean {
  return [/[a-z]/, /[A-Z]/, /[0-9]/].filter((re) => re.test(run)).length >= 2;
}

/** Whether a first segment (`/` + one segment) looks like it carries a credential — the server's rule, raw and percent-decoded. */
export function firstSegmentLooksLikeCredential(firstSegment: string): boolean {
  const raw = String(firstSegment ?? "").replace(/^\//, "");
  if (raw.length === 0) return false;
  let decoded = raw;
  try {
    decoded = decodeURIComponent(raw);
  } catch {
    // best-effort: a malformed %-sequence is judged on the raw form alone.
  }
  for (const s of new Set([raw, decoded])) {
    if (s.length > MAX_PLAIN_FIRST_SEGMENT_LENGTH) return true;
    if (CREDENTIAL_SEGMENT_PREFIXES.some((re) => re.test(s))) return true;
    for (const run of s.match(/[A-Za-z0-9_-]{24,}/g) ?? []) {
      if (mixesClasses(run)) return true;
    }
  }
  return false;
}

/** `/` or `/<first path segment>` of the URL — never the query, never deeper. */
export function observationFirstSegment(url: string | URL): string {
  let u: URL;
  try {
    u = url instanceof URL ? url : new URL(url);
  } catch {
    return "/";
  }
  const path = u.pathname || "/";
  const seg = path.replace(/^\//, "").split("/", 1)[0] ?? "";
  return `/${seg}`;
}

/** One identifying tuple, before aggregation. */
export interface ObservationInput {
  host: string;
  firstSegment: string;
  method: string;
  headerName: string;
}

/**
 * The whole classifier, pure: what would be recorded for this request, or
 * null. The caller has ALREADY decided the request is direct + unlisted;
 * this only answers "does it carry a credential, and under which name".
 */
export function observationFor(
  url: string,
  method: string,
  headers: Record<string, string> | Iterable<[string, string]>,
): ObservationInput | null {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  const host = normaliseHost(parsed.hostname);
  // An IP literal is never a Route target; the server drops it (`ip_literal`).
  if (!host || isIP(host) !== 0) return null;
  const upper = String(method || "GET").toUpperCase();
  if (!OBSERVATION_METHODS.includes(upper)) return null;
  const raw = observationFirstSegment(parsed);
  // A credential-shaped segment is reported as `/` — the entry is kept.
  const firstSegment = firstSegmentLooksLikeCredential(raw) ? "/" : raw;
  if (!FIRST_SEGMENT_RE.test(firstSegment)) return null;
  const headerName = credentialHeaderName(headers);
  if (!headerName) return null;
  return { host, firstSegment, method: upper, headerName };
}

/** `KNOXCALL_OBSERVE_UNCOVERED=off|false|0` turns the reporter off (read when a transport is built). */
export function observeUncoveredDisabledByEnv(): boolean {
  const v = process.env.KNOXCALL_OBSERVE_UNCOVERED;
  return typeof v === "string" && ["off", "0", "false"].includes(v.trim().toLowerCase());
}

export interface ObservationFlushInfo {
  accepted: number;
  dropped: number;
}

export interface EgressObservationReporterOptions {
  /** Performs `POST /v1/wrap/egress-observations` with at most `maxPerRequest` observations. */
  report: (observations: EgressObservation[]) => Promise<EgressObservationsReport>;
  /** Fires after each accepted flush request (never per observation). */
  onFlush?: (info: ObservationFlushInfo) => void;
  /** Runs the report inside the SDK's own suppressed context so it is never itself intercepted. */
  runSuppressed?: <T>(fn: () => T) => T;
  /** Whether an error from `report` means the key lacks the gate (stop for good). Default: status 403. */
  isForbidden?: (err: unknown) => boolean;
  /** Timer flush interval, ms (default 60 000, ±10% jitter). */
  flushIntervalMs?: number;
  /** Flush immediately once this many distinct keys accumulate (default 200). */
  flushAtKeys?: number;
  /** Hard cap on distinct keys held; beyond it new keys are dropped (default 1 000). */
  maxKeys?: number;
  /** Observations per request (default 200 — the server's ceiling). */
  maxPerRequest?: number;
  /** Test seams. */
  setTimeoutImpl?: typeof setTimeout;
  now?: () => number;
  random?: () => number;
}

interface Entry {
  host: string;
  first_segment: string;
  method: string;
  header_name: string;
  count: number;
  first_seen: number;
  last_seen: number;
}

const DEFAULT_FLUSH_INTERVAL_MS = 60_000;
const DEFAULT_FLUSH_AT_KEYS = 200;
const DEFAULT_MAX_KEYS = 1_000;
const DEFAULT_MAX_PER_REQUEST = 200;

function defaultIsForbidden(err: unknown): boolean {
  return typeof err === "object" && err !== null && (err as { status?: unknown }).status === 403;
}

/**
 * In-memory aggregation of uncovered-egress observations for ONE handle /
 * transport, flushed in the background. Single-flight; bounded; never throws.
 */
export class EgressObservationReporter {
  readonly #opts: EgressObservationReporterOptions;
  readonly #buffer = new Map<string, Entry>();
  readonly #setTimeout: typeof setTimeout;
  readonly #now: () => number;
  readonly #random: () => number;
  readonly #interval: number;
  readonly #flushAt: number;
  readonly #maxKeys: number;
  readonly #maxPerRequest: number;
  #timer: ReturnType<typeof setTimeout> | null = null;
  #inflight: Promise<void> | null = null;
  #stopped = false;
  #forbidden = false;
  #overflowWarned = false;

  constructor(opts: EgressObservationReporterOptions) {
    this.#opts = opts;
    this.#setTimeout = opts.setTimeoutImpl ?? setTimeout;
    this.#now = opts.now ?? (() => Date.now());
    this.#random = opts.random ?? Math.random;
    this.#interval = opts.flushIntervalMs ?? DEFAULT_FLUSH_INTERVAL_MS;
    this.#flushAt = opts.flushAtKeys ?? DEFAULT_FLUSH_AT_KEYS;
    this.#maxKeys = opts.maxKeys ?? DEFAULT_MAX_KEYS;
    this.#maxPerRequest = opts.maxPerRequest ?? DEFAULT_MAX_PER_REQUEST;
  }

  /** Distinct keys currently held. */
  get size(): number {
    return this.#buffer.size;
  }

  /** True after `stop()`. */
  get stopped(): boolean {
    return this.#stopped;
  }

  /** True once the endpoint answered 403: reporting is off for the life of this reporter. */
  get forbidden(): boolean {
    return this.#forbidden;
  }

  /** The observations that would be sent now (a copy). */
  pending(): EgressObservation[] {
    return [...this.#buffer.values()].map(toWire);
  }

  /** Record one uncovered credentialed call. Synchronous, never throws. */
  record(obs: ObservationInput): void {
    if (this.#stopped || this.#forbidden) return;
    const key = `${obs.host}\u0000${obs.firstSegment}\u0000${obs.method}\u0000${obs.headerName}`;
    const at = this.#now();
    const hit = this.#buffer.get(key);
    if (hit) {
      hit.count += 1;
      hit.last_seen = at;
      return;
    }
    if (this.#buffer.size >= this.#maxKeys) {
      if (!this.#overflowWarned) {
        this.#overflowWarned = true;
        warnOnce(
          "KNOXCALL_EGRESS_OBSERVATIONS_OVERFLOW",
          `KnoxCall: more than ${this.#maxKeys} distinct uncovered-egress observations are pending; new ones are dropped until the next flush.`,
        );
      }
      return;
    }
    this.#buffer.set(key, {
      host: obs.host,
      first_segment: obs.firstSegment,
      method: obs.method,
      header_name: obs.headerName,
      count: 1,
      first_seen: at,
      last_seen: at,
    });
    if (this.#buffer.size >= this.#flushAt) {
      void this.flush();
      return;
    }
    this.#arm();
  }

  /** Send what is pending now. Single-flight: concurrent callers share one flush. Never rejects. */
  flush(): Promise<void> {
    if (this.#inflight) return this.#inflight;
    this.#inflight = this.#doFlush().finally(() => {
      this.#inflight = null;
    });
    return this.#inflight;
  }

  /** Stop the timer and flush once more. Idempotent. */
  stop(): Promise<void> {
    if (this.#stopped) return this.#inflight ?? Promise.resolve();
    this.#stopped = true;
    if (this.#timer) {
      clearTimeout(this.#timer);
      this.#timer = null;
    }
    return this.flush();
  }

  async #doFlush(): Promise<void> {
    if (this.#timer) {
      clearTimeout(this.#timer);
      this.#timer = null;
    }
    if (this.#forbidden || this.#buffer.size === 0) return;
    const batch = [...this.#buffer.values()].map(toWire);
    this.#buffer.clear();
    const run = this.#opts.runSuppressed ?? (<T,>(fn: () => T) => fn());
    const isForbidden = this.#opts.isForbidden ?? defaultIsForbidden;
    for (let i = 0; i < batch.length; i += this.#maxPerRequest) {
      const chunk = batch.slice(i, i + this.#maxPerRequest);
      let res: EgressObservationsReport;
      try {
        res = await run(() => this.#opts.report(chunk));
      } catch (err) {
        if (isForbidden(err)) {
          // The key lacks `routes:read`: reporting is off for good. Anything
          // recorded from here on is dropped at the door.
          this.#forbidden = true;
          this.#buffer.clear();
          warnOnce(
            "KNOXCALL_EGRESS_OBSERVATIONS_FORBIDDEN",
            "KnoxCall: the credential cannot report uncovered-egress observations (HTTP 403 — it lacks `routes:read`); " +
              "reporting is off for this interceptor. Grant the scope, or set observeUncovered: false to silence this.",
          );
          return;
        }
        // best-effort: telemetry. The batch is dropped — never retried in a
        // loop, never surfaced into the application's own request.
        warnOnce(
          "KNOXCALL_EGRESS_OBSERVATIONS_FAILED",
          `KnoxCall: reporting uncovered-egress observations failed (${err instanceof Error ? err.message : String(err)}); the batch was dropped.`,
        );
        return;
      }
      try {
        this.#opts.onFlush?.({ accepted: Number(res?.accepted ?? 0), dropped: Number(res?.dropped ?? 0) });
      } catch {
        // best-effort: a caller's hook must never break the reporter.
      }
    }
  }

  #arm(): void {
    if (this.#stopped || this.#timer) return;
    const jitter = 1 + (this.#random() * 0.2 - 0.1); // ±10%
    const delay = Math.max(1, Math.round(this.#interval * jitter));
    const t = this.#setTimeout(() => {
      this.#timer = null;
      void this.flush();
    }, delay);
    (t as { unref?: () => void }).unref?.();
    this.#timer = t;
  }
}

function toWire(e: Entry): EgressObservation {
  return {
    host: e.host,
    first_segment: e.first_segment,
    method: e.method,
    header_name: e.header_name,
    count: e.count,
    first_seen: new Date(e.first_seen).toISOString(),
    last_seen: new Date(e.last_seen).toISOString(),
  };
}
