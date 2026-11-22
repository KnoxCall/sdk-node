// The DPoP server nonce (RFC 9449 §8) — PARITY §7.1, client Phase 4.3.
//
// KnoxCall answers EVERY request that carried a `DPoP` proof header with
// `DPoP-Nonce: <value>`: mints, refusals and successful calls alike, on
// `POST /oauth/token`, `/v1`, the tenant data plane, the self-hosted proxy and
// the AI gateway. The value is stateless, changes every minute, and the server
// accepts the current and the previous minute's — so a nonce is good for
// 60–120 s.
//
// The server's rule is VERIFY-IF-PRESENT: a proof carrying a `nonce` claim must
// carry one the server would issue now, and a proof carrying none is still
// accepted. So sending one is an optimisation and a readiness step, never a
// requirement, and a client that never learned a nonce keeps working.
//
// WHAT THIS MODULE IS. A per-origin memory of the last nonce seen, plus the
// predicate that recognises the server's "use a nonce" refusal. Both are
// deliberately tiny and have no I/O.
//
//  * Keyed by ORIGIN (scheme + host + port), because that is what the nonce is
//    scoped to: the management API and a tenant's data plane are different
//    origins and issue different values. Keyed on anything coarser and a
//    cross-origin nonce would be sent and refused; keyed on anything finer (a
//    path) and almost every request would start without one.
//  * Last-write-wins, no expiry. A nonce is not a secret and needs no storage
//    beyond the process. It does not need to be fresh either: the worst a stale
//    one costs is the single documented retry, and the server deliberately
//    refuses a stale nonce BEFORE claiming the proof's `jti`, so that retry is
//    not then refused for an unrelated reason.
//  * Per client instance, not module-global. One process may hold clients for
//    two tenants; keeping the map on the client means a test can observe it and
//    nothing leaks between instances.

/** The response header the server sends on every DPoP-carrying request. */
export const NONCE_HEADER = "dpop-nonce";

/** The RFC 9449 §8 error code: in the OAuth body on the authorization server,
 *  in `WWW-Authenticate` on a resource server. */
export const USE_DPOP_NONCE = "use_dpop_nonce";

/** `scheme://host[:port]` — the scope a nonce belongs to. `""` when the URL has
 *  no host, which simply means "do not remember this one". */
export function originOf(url: string): string {
  try {
    return new URL(url).origin.toLowerCase();
  } catch {
    return "";
  }
}

/** The last `DPoP-Nonce` seen per origin. See the header comment. */
export class DpopNonceStore {
  readonly #byOrigin = new Map<string, string>();

  /** Record the nonce on a response, if it carried one. Returns it.
   *
   *  `headers` keys must already be lower-cased — every call site in this SDK
   *  normalises them, and looking for one casing only is what makes this a map
   *  lookup rather than a scan. */
  remember(url: string, headers: Record<string, string> | undefined): string | undefined {
    const raw = headers?.[NONCE_HEADER];
    if (typeof raw !== "string") return undefined;
    const value = raw.trim();
    if (!value) return undefined;
    const origin = originOf(url);
    if (!origin) return undefined;
    this.#byOrigin.set(origin, value);
    return value;
  }

  /** The nonce to put in a proof for `url`, or `undefined` when this origin has
   *  not answered yet (which is fine — the server accepts a proof with no
   *  nonce claim). */
  get(url: string): string | undefined {
    const origin = originOf(url);
    return origin ? this.#byOrigin.get(origin) : undefined;
  }

  forget(url: string): void {
    const origin = originOf(url);
    if (origin) this.#byOrigin.delete(origin);
  }

  /** A copy, for tests and debugging. */
  snapshot(): Record<string, string> {
    return Object.fromEntries(this.#byOrigin);
  }
}

/**
 * Whether a refusal is the server asking for a (fresh) nonce.
 *
 * RFC 9449 splits the two surfaces and so does KnoxCall, which is why this
 * takes all three inputs rather than just a status:
 *
 *  * `POST /oauth/token` (authorization server, §8.1) answers **400** with the
 *    OAuth body `{"error": "use_dpop_nonce", …}`;
 *  * `/v1`, the tenant data plane, the self-hosted proxy and the AI gateway
 *    (resource server, §8.2) answer **401** with
 *    `WWW-Authenticate: DPoP error="use_dpop_nonce"`. On `/v1` the body's error
 *    type says it too, but the tenant data plane keeps its deliberately opaque
 *    `Unauthorized` body, SO THE HEADER IS THE ONLY SIGNAL THERE. Reading the
 *    body alone would make this work on /v1 and silently not on the data plane.
 */
export function isUseDpopNonce(args: {
  status?: number;
  code?: string;
  headers?: Record<string, string>;
}): boolean {
  if (args.status !== 400 && args.status !== 401) return false;
  if (args.code === USE_DPOP_NONCE) return true;
  const challenge = args.headers?.["www-authenticate"] ?? "";
  return challenge.toLowerCase().includes(USE_DPOP_NONCE);
}
