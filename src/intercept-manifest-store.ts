// The SDK-side copy of the intercept manifest — fetched, held, refreshed
// (route-aware-interception-plan.md §2.5). One per wrapper instance; process
// memory only; dropped on uninstall.
//
//   - polls at the manifest's `ttl_seconds` (±10% jitter, timer unref'd so it
//     never keeps a process alive), single-flight, never more than one refresh
//     in flight;
//   - keeps the last GOOD manifest when a refresh fails (stale-but-valid, the
//     same posture §3 takes for tokens) and backs off exponentially;
//   - a 401/403/404 from the manifest endpoint — the credential lacks
//     `routes:read`, or an older server — is NOT a routing failure: the store
//     warns once, behaves as "no manifest" (so every listed host stays on the
//     ephemeral path exactly as before this feature), and re-checks slowly;
//   - out-of-cycle refreshes (a route-mode refusal, a promoted-route hint,
//     an explicit `refresh()`) are rate-limited so a burst of refusals costs
//     one management call, not one per request.
//
// Discovery failing open is deliberate and bounded: it can only leave a host on
// the path it was on before the manifest existed. The DATA-PLANE hop is where
// fail-closed lives (D4), and that is in resources/wrap.ts.

import type { InterceptManifest, InterceptManifestRoute } from "./resources/wrap.js";
import { KnoxCallError } from "./error.js";
import { warnOnce } from "./warn.js";

export interface ManifestRefreshInfo {
  reason: string;
  version: string | null;
  added: InterceptManifestRoute[];
  removed: InterceptManifestRoute[];
}

export interface InterceptManifestStoreOptions {
  /**
   * Performs `GET /v1/wrap/intercept-manifest` for the wrapper's environment.
   * `ifNoneMatch` is the version the store holds (absent on the first poll):
   * send it as `If-None-Match: W/"<version>"` and resolve to `null` on the
   * server's `304` — the store then keeps its manifest, resets the TTL clock
   * and fires no `onRefresh`. A zero-argument function is accepted and simply
   * polls unconditionally.
   */
  fetchManifest: (opts: { ifNoneMatch?: string }) => Promise<InterceptManifest | null>;
  /** Fires after every refresh whose entries changed. */
  onRefresh?: (info: ManifestRefreshInfo) => void;
  /** Fires when a refresh failed (the store keeps its last good manifest). */
  onError?: (err: unknown) => void;
  /** Minimum gap between out-of-cycle refreshes, ms (default 5000). */
  minRefreshGapMs?: number;
  /** Test seam: the timer factory (defaults to setTimeout). */
  setTimeoutImpl?: typeof setTimeout;
  /** Test seam: the clock (defaults to Date.now). */
  now?: () => number;
  /** Test seam: jitter source in [0,1) (defaults to Math.random). */
  random?: () => number;
}

const DEFAULT_TTL_SECONDS = 60;
const MAX_BACKOFF_FACTOR = 8;
/** After a permission/not-found refusal, re-check at this multiple of the TTL. */
const PERMISSION_RECHECK_FACTOR = 10;

function entryKey(e: InterceptManifestRoute): string {
  return `${e.host}\u0000${e.base_path}\u0000${e.slug}`;
}

export class InterceptManifestStore {
  #manifest: InterceptManifest | null = null;
  #version: string | null = null;
  #inflight: Promise<InterceptManifest | null> | null = null;
  #timer: ReturnType<typeof setTimeout> | null = null;
  #stopped = false;
  #failures = 0;
  #permissionDenied = false;
  #lastRefreshAt = 0;
  #lastError: unknown = null;
  readonly #opts: InterceptManifestStoreOptions;
  readonly #setTimeout: typeof setTimeout;
  readonly #now: () => number;
  readonly #random: () => number;
  /** Resolves after the FIRST refresh attempt settles — success or failure; never rejects. */
  readonly ready: Promise<void>;
  #resolveReady!: () => void;

  constructor(opts: InterceptManifestStoreOptions) {
    this.#opts = opts;
    this.#setTimeout = opts.setTimeoutImpl ?? setTimeout;
    this.#now = opts.now ?? (() => Date.now());
    this.#random = opts.random ?? Math.random;
    this.ready = new Promise<void>((resolve) => {
      this.#resolveReady = resolve;
    });
  }

  /** The last good manifest, or null before the first success / after a permission refusal. */
  get(): InterceptManifest | null {
    return this.#manifest;
  }

  get version(): string | null {
    return this.#version;
  }

  get lastError(): unknown {
    return this.#lastError;
  }

  /** True once the manifest endpoint refused the credential (warned once; re-checked slowly). */
  get permissionDenied(): boolean {
    return this.#permissionDenied;
  }

  /** Kick off the first refresh and the poll loop. Idempotent. */
  start(): void {
    if (this.#stopped || this.#timer) return;
    void this.refresh("start", { force: true });
  }

  /** Stop polling and drop the manifest. The store cannot be restarted. */
  stop(): void {
    this.#stopped = true;
    if (this.#timer) {
      clearTimeout(this.#timer);
      this.#timer = null;
    }
    this.#manifest = null;
    this.#version = null;
    this.#resolveReady();
  }

  /**
   * Refresh now. Single-flight: concurrent callers share one fetch. Rate-limited
   * unless `force`: an out-of-cycle refresh inside `minRefreshGapMs` of the last
   * one returns the current manifest without a call.
   */
  async refresh(reason: string, opts: { force?: boolean } = {}): Promise<InterceptManifest | null> {
    if (this.#stopped) return null;
    if (this.#inflight) return this.#inflight;
    const gap = this.#opts.minRefreshGapMs ?? 5000;
    if (!opts.force && this.#now() - this.#lastRefreshAt < gap) return this.#manifest;

    this.#inflight = this.#doRefresh(reason).finally(() => {
      // Clear the flight BEFORE signalling ready: a caller that does
      // `await ready; refresh()` must start a new fetch, not be coalesced into
      // the one that just settled.
      this.#inflight = null;
      this.#resolveReady();
    });
    return this.#inflight;
  }

  async #doRefresh(reason: string): Promise<InterceptManifest | null> {
    this.#lastRefreshAt = this.#now();
    try {
      // Every poll after the first is conditional on the held version; the
      // server answers 304 (→ null) when nothing changed, and that is a
      // success: keep the manifest, restart the TTL clock, fire no hook.
      const next = await this.#opts.fetchManifest(this.#version ? { ifNoneMatch: this.#version } : {});
      const prev = this.#manifest;
      this.#failures = 0;
      this.#permissionDenied = false;
      this.#lastError = null;
      if (next === null) {
        this.#schedule((prev?.ttl_seconds || DEFAULT_TTL_SECONDS) * 1000);
        return this.#manifest;
      }
      if (!prev || prev.version !== next.version) {
        const before = new Map((prev?.routes ?? []).map((e) => [entryKey(e), e]));
        const after = new Map(next.routes.map((e) => [entryKey(e), e]));
        const added = [...after.entries()].filter(([k]) => !before.has(k)).map(([, e]) => e);
        const removed = [...before.entries()].filter(([k]) => !after.has(k)).map(([, e]) => e);
        this.#manifest = next;
        this.#version = next.version;
        if (added.length || removed.length || !prev) {
          this.#opts.onRefresh?.({ reason, version: next.version, added, removed });
        }
      }
      this.#schedule((next.ttl_seconds || DEFAULT_TTL_SECONDS) * 1000);
      return this.#manifest;
    } catch (err) {
      this.#lastError = err;
      this.#opts.onError?.(err);
      const status = err instanceof KnoxCallError ? err.status : undefined;
      if (status === 401 || status === 403 || status === 404) {
        // Not a routing failure: the credential cannot read routes, or the
        // server predates the manifest. Every listed host stays ephemeral, as
        // it was before this feature existed. Warn once, re-check slowly.
        this.#permissionDenied = true;
        this.#manifest = null;
        this.#version = null;
        warnOnce(
          "KNOXCALL_INTERCEPT_MANIFEST_UNAVAILABLE",
          `KnoxCall intercept manifest unavailable (HTTP ${status}): route-aware interception is off for this client — ` +
            `listed hosts use the ephemeral proxy. Grant the credential \`routes:read\` (or upgrade the server) to enable it.`,
        );
        this.#schedule(DEFAULT_TTL_SECONDS * 1000 * PERMISSION_RECHECK_FACTOR);
      } else {
        // Transport or server fault: keep the last good manifest, back off.
        this.#failures = Math.min(this.#failures + 1, 30);
        const factor = Math.min(2 ** (this.#failures - 1), MAX_BACKOFF_FACTOR);
        const base = (this.#manifest?.ttl_seconds || DEFAULT_TTL_SECONDS) * 1000;
        this.#schedule(Math.min(base * factor, base * MAX_BACKOFF_FACTOR));
      }
      return this.#manifest;
    }
    // `ready` is signalled by refresh()'s finally, after the flight is cleared.
  }

  #schedule(baseMs: number): void {
    if (this.#stopped) return;
    if (this.#timer) clearTimeout(this.#timer);
    const jitter = 1 + (this.#random() * 0.2 - 0.1); // ±10%
    const delay = Math.max(1000, Math.round(baseMs * jitter));
    const t = this.#setTimeout(() => {
      this.#timer = null;
      void this.refresh("poll", { force: true });
    }, delay);
    (t as { unref?: () => void }).unref?.();
    this.#timer = t;
  }
}
