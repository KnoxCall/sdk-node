// Workload-identity credential provider — WIF plan Phase 4.3.
//
// `exchangeToken` is one-shot: it trades one OIDC assertion for one capability
// token and hands the caller an `expires_in` to manage. That is fine for a
// script that makes one call and exits, and wrong for anything long-lived — a
// polling worker, a long CI job, an agent process — where the token silently
// expires mid-run and the caller discovers it as a 401 they have to interpret.
//
// This provider owns that lifecycle: cache the token, refresh it before it dies,
// and never hand out one that is about to expire.
//
// ── THE PART THAT IS NOT LIKE OTHER REFRESH LOOPS ───────────────────────────
//
// A KnoxCall workload assertion is SINGLE-USE. The exchange spends the whole
// assertion — the server claims a hash of it before minting (WIF Phase 1.2), so
// presenting the same bytes twice is refused with "subject_token has already
// been exchanged". A refresh therefore cannot re-send the assertion it used
// last time; it needs a FRESH one from the platform every single time.
//
// That makes the obvious implementation — capture the assertion once, reuse it
// on refresh — not merely suboptimal but broken, and broken in a way that only
// shows up when the first refresh fires, i.e. minutes into production rather
// than in anyone's smoke test. So the provider takes a SOURCE it calls before
// every exchange, and refuses to send an assertion whose bytes it has already
// spent (`StaleAssertionError`). It fails loudly at the real cause rather than
// forwarding a doomed request and surfacing the server's replay refusal, which
// reads as "my credentials were rejected" and sends the reader hunting in the
// wrong place.
//
// ── THE TWO-TIER SCHEDULE ───────────────────────────────────────────────────
//
// ADVISORY (expiry − 120s): refresh opportunistically. If it fails, the token in
// hand is still valid, so the caller is served and the failure is a warning, not
// an exception. A transient blip near a refresh boundary must not take down a
// worker that has two minutes of perfectly good credential left.
//
// MANDATORY (expiry − 30s): refresh or throw. Below this line the token may die
// in flight — between the provider handing it over and the request reaching the
// server — and a 401 from an expired capability token is exactly the confusing
// failure this provider exists to prevent.
//
// The gap between the two tiers is the whole point: it buys 90 seconds in which
// a failing token source or a flaky network is survivable rather than fatal.

import { KnoxCallError } from "../error.js";
import { Redacted, redact } from "../redacted.js";
import { warnOnce } from "../warn.js";
import { MemoryTokenStore, type CachedToken, type TokenStore } from "./token-store.js";
import { exchangeToken, type ExchangeTokenOptions } from "../resources/token-exchange.js";
import { createHash } from "crypto";

/** Refresh opportunistically below this much remaining life; failure is survivable. */
export const ADVISORY_REFRESH_MS = 120_000;

/** Refresh or throw below this much remaining life; the token may die in flight. */
export const MANDATORY_REFRESH_MS = 30_000;

/**
 * Produces the workload's CURRENT OIDC assertion.
 *
 * Called before EVERY exchange, never cached by the provider. On GitHub Actions
 * this is a fetch of `ACTIONS_ID_TOKEN_REQUEST_URL`; on GCP or EKS a read of the
 * metadata service or the projected token file. Whatever it is, it must mint or
 * re-read — returning a value captured once at startup is the failure this
 * provider detects rather than tolerates.
 */
export type WorkloadAssertionSource = () => string | Promise<string>;

/**
 * The token source returned bytes that were already spent on a previous
 * exchange, so sending them could only have been refused.
 *
 * This is a caller-side configuration error, not a credential rejection, and it
 * says so: the message names the cause and what to do, because the alternative
 * is a replay refusal from the server that reads like "your CI identity is not
 * trusted".
 */
export class StaleAssertionError extends KnoxCallError {
  constructor(message: string) {
    super(message);
    this.name = "StaleAssertionError";
  }
}

export interface WorkloadCredentialProviderOptions extends ExchangeTokenOptions {
  /** Called before every exchange; must return a FRESH assertion each time. */
  assertion: WorkloadAssertionSource;
  /** RFC 8707 resource indicator — narrows the minted token to `tool` kind. */
  resource?: string;
  /** Defaults to `knoxcall:gateway`. */
  audience?: string;
  /** Defaults to a process-local {@link MemoryTokenStore}. */
  store?: TokenStore;
  /** Cache key, for callers holding several workload identities at once. */
  cacheKey?: string;
  /** Clock seam for tests. */
  now?: () => number;
}

/**
 * Caches a workload capability token and refreshes it on the two-tier schedule.
 *
 * Concurrency is the store's single-flight lock, so N simultaneous callers
 * produce ONE exchange — which matters more here than in an ordinary refresh
 * loop: each exchange spends an assertion, and a thundering herd would burn N
 * of them and have N−1 refused.
 */
export class WorkloadCredentialProvider {
  readonly #assertion: WorkloadAssertionSource;
  readonly #options: ExchangeTokenOptions;
  readonly #resource?: string;
  readonly #audience?: string;
  readonly #store: TokenStore;
  readonly #key: string;
  readonly #now: () => number;
  /** sha256 of every assertion this provider has spent. Never the assertion. */
  #spent = new Set<string>();

  constructor(opts: WorkloadCredentialProviderOptions) {
    this.#assertion = opts.assertion;
    // Every exchange option carried through verbatim. `sandbox` in particular:
    // dropping it would silently send a Test-mode workload's assertion to the
    // Live host, where it matches no binding — a confusing refusal produced by
    // the provider rather than by the caller's configuration.
    this.#options = {
      tenant: opts.tenant,
      sandbox: opts.sandbox,
      baseUrl: opts.baseUrl,
      fetch: opts.fetch,
      signal: opts.signal,
    };
    this.#resource = opts.resource;
    this.#audience = opts.audience;
    this.#store = opts.store ?? new MemoryTokenStore();
    // The default key separates Live from Test for the same tenant, so one
    // provider per data space cannot serve the other's token from cache.
    this.#key =
      opts.cacheKey ??
      `workload:${opts.baseUrl ?? opts.tenant ?? "default"}:${opts.sandbox ? "test" : "live"}`;
    this.#now = opts.now ?? Date.now;
  }

  /**
   * A capability token with more than {@link MANDATORY_REFRESH_MS} of life left.
   *
   * Returns `Redacted` so the token cannot reach a log through a stray template
   * or a structured-logger field — the same treatment every other credential in
   * this SDK gets.
   */
  async getAccessToken(): Promise<Redacted<string>> {
    const cached = await this.#store.get(this.#key);
    const remaining = cached ? cached.expiresAt - this.#now() : -1;

    if (cached && remaining > ADVISORY_REFRESH_MS) return cached.accessToken;

    if (cached && remaining > MANDATORY_REFRESH_MS) {
      // ADVISORY tier: try, but the token in hand is still good.
      try {
        return await this.#refresh();
      } catch (err) {
        // best-effort: the caller still has a valid credential, and failing here
        // would convert a survivable blip into an outage. The MANDATORY tier
        // below will raise it for real if the condition persists.
        warnOnce(
          "workload-advisory-refresh",
          `KnoxCall: advisory token refresh failed (${err instanceof Error ? err.message : String(err)}); ` +
            `continuing with the current token, which expires in ${Math.round(remaining / 1000)}s`,
        );
        return cached.accessToken;
      }
    }

    // MANDATORY tier, or nothing cached at all.
    return this.#refresh();
  }

  /** Exchange a fresh assertion, under the store's single-flight lock. */
  async #refresh(): Promise<Redacted<string>> {
    return this.#store.withLock(this.#key, async () => {
      // Re-read inside the lock: a peer may have refreshed while we waited, and
      // spending a second assertion for a token we already hold is pure waste.
      const current = await this.#store.get(this.#key);
      if (current && current.expiresAt - this.#now() > ADVISORY_REFRESH_MS) {
        return current.accessToken;
      }

      const assertion = await this.#assertion();
      if (typeof assertion !== "string" || assertion.length === 0) {
        throw new StaleAssertionError(
          "the workload assertion source returned nothing. It must return the workload's " +
            "current OIDC id_token on every call.",
        );
      }

      const fingerprint = createHash("sha256").update(assertion, "utf8").digest("hex");
      if (this.#spent.has(fingerprint)) {
        throw new StaleAssertionError(
          "the workload assertion source returned an assertion that has already been exchanged. " +
            "KnoxCall assertions are single-use, so each refresh needs a NEWLY minted one — " +
            "call the platform's token endpoint inside the source (for example re-fetch " +
            "ACTIONS_ID_TOKEN_REQUEST_URL, or re-read the projected service-account token file) " +
            "rather than capturing one value at startup.",
        );
      }

      const res = await exchangeToken(
        {
          subject_token: assertion,
          ...(this.#resource ? { resource: this.#resource } : {}),
          ...(this.#audience ? { audience: this.#audience } : {}),
        },
        this.#options,
      );

      // Recorded only after the exchange returns, so a network failure does not
      // burn a fingerprint the caller could legitimately retry with. The server
      // claims the assertion before it mints, so a SUCCESS is what makes those
      // bytes unusable.
      this.#spent.add(fingerprint);

      const lifetime = res.expires_in * 1000;
      const token: CachedToken = {
        accessToken: redact(res.access_token),
        expiresAt: this.#now() + lifetime,
        lifetime,
        scope: res.scope ? [res.scope] : [],
        tokenType: "Bearer",
      };
      await this.#store.set(this.#key, token);
      return token.accessToken;
    });
  }
}
