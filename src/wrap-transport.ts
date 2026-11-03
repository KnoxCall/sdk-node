// Wrap transport — the client-side machinery behind `knox.wrap.fetch()`
// (sdk-wrapping plan PR4, Node reference).
//
// A wrapped third-party SDK (Stripe first) keeps its own serialization, retries,
// idempotency keys and error types; only its HTTP transport is swapped for one
// that re-targets each request through KnoxCall's ephemeral proxy in transparent
// mode. The provider credential the SDK sets on its Authorization header is
// LIFTED out-of-band (never sent to the upstream as a raw header, never logged),
// or — in escrow mode — replaced by a named escrowed credential the server
// resolves and host-pins.
//
// Pure, transport-agnostic helpers live here so they are unit-testable without a
// client; the resource method in resources/wrap.ts wires them to ephemeral().

/** Where the provider credential comes from for a wrapped call. */
export type WrapCredential =
  /**
   * Escrow mode: reference an escrowed credential by name (see `wrap.escrow()`).
   * The raw key never leaves KnoxCall custody; the server injects it, host-pinned.
   */
  | { secret: string; scheme?: string };
// Transit mode is the DEFAULT (no credential option): the wrapper lifts the
// wrapped SDK's own Authorization header, so the SDK formats its own auth and we
// never have to guess a scheme. That is strictly more robust than an explicit
// raw-key option, so none is offered.

export interface RouteAroundRule {
  /** Exact upstream host this rule matches (lower-case DNS hostname). */
  host: string;
  /** Optional path prefix; when omitted the whole host is routed around. */
  pathPrefix?: string;
  /** Human reason, surfaced to the onRouteAround hook and docs. */
  reason: string;
}

export interface WrapFetchOptions {
  /** Provider credential source. Omit for transit mode (lift the SDK's own Authorization). */
  credential?: WrapCredential;
  /**
   * Additional route-around rules, merged with the built-in defaults. A matching
   * request is sent to the provider DIRECTLY (untouched), never through KnoxCall
   * — the client-side half of the PCI posture (plan §3) and the escape hatch for
   * un-proxyable calls (streaming, multipart, host-signed).
   */
  routeAround?: RouteAroundRule[];
  /** Disable the built-in default route-around rules (keep only `routeAround`). */
  disableDefaultRouteAround?: boolean;
  /** fetch used for route-around direct calls + as the ultimate transport. Defaults to globalThis.fetch. */
  directFetch?: typeof fetch;
  /** Observability hook: called when a request is routed directly to the provider. */
  onRouteAround?: (info: { url: string; host: string; reason: string }) => void;
  /**
   * Send via a PROMOTED durable route instead of the ephemeral proxy: the request
   * goes to the tenant data plane with `x-knoxcall-route: <slug>` and the route
   * injects the stored secret — no provider credential travels. Set this after
   * you promote an opportunity to switch a wrapped SDK over with a one-line change.
   */
  route?: string;
  /**
   * Opt in to AUTOMATIC switching: when an ephemeral response carries
   * `X-Knox-Promoted-Route`, subsequent calls to that host are sent via the named
   * route (per this wrapper instance). Off by default — switching is a deliberate
   * config change (a promoted route couples availability to KnoxCall once the key
   * is deleted). Loudly surfaced via `onPromoted`.
   */
  autoSwitch?: boolean;
  /** Observability hook: called when a response advertises a promoted route for a host. */
  onPromoted?: (info: { host: string; slug: string }) => void;

  // ── route-aware (route-aware-interception-plan.md §2, PARITY §21) ──────────
  /**
   * `"auto"`: poll the intercept manifest and send each request through the
   * Route that covers its host + path (the Route injects the stored secret;
   * no provider credential travels), falling back to the ephemeral proxy for
   * hosts no Route covers. `"off"`: never consult the manifest — the ephemeral
   * proxy (or an explicit `route`) for everything, as before.
   * Default: `"off"` for `wrap.fetch()` (an explicit transport keeps its
   * behaviour), `"auto"` for `wrap.intercept()` (decision D3).
   */
  routes?: "auto" | "off";
  /**
   * When KnoxCall is unreachable for EPHEMERAL transit traffic: `"error"`
   * (default — decision D4, the SDK's connection error surfaces) or `"direct"`
   * (send the original request untouched via `directFetch`, firing
   * `onFallback`). Route mode and escrow never go direct: there is no
   * credential to go direct with.
   */
  unavailable?: "error" | "direct";
  /** Fires when a request is sent through KnoxCall, with the mode and the stable reason code. */
  onReroute?: (info: { host: string; url: string; mode: "route" | "ephemeral" | "intercepted"; slug?: string; reason: string }) => void;
  /** Fires when a manifest refresh changed the entries (added/removed). */
  onRefresh?: (info: { reason: string; version: string | null; added: unknown[]; removed: unknown[] }) => void;
  /** Fires when a manifest refresh failed (the last good manifest is kept). */
  onManifestError?: (err: unknown) => void;
  /** Fires once per (host, path prefix) when a Route covers the host but not this path, so the request went ephemeral. */
  onUnmatchedPath?: (info: { host: string; url: string }) => void;
  /** Fires when a route-mode request was refused by KnoxCall (a 401, or a 404 `route_not_found`) and the manifest was refreshed; `redecided` names the new mode, or null when unchanged. */
  onRefused?: (info: { host: string; url: string; slug: string; status: number; redecided: "route" | "ephemeral" | "direct" | null }) => void;
  /** Fires when `unavailable: "direct"` sent a request direct because KnoxCall was unreachable. */
  onFallback?: (info: { host: string; url: string; error: unknown }) => void;

  // ── uncovered-egress observations (PARITY §21.3) ─────────────────────────
  /**
   * Report uncovered egress: calls this transport sent DIRECT because the
   * host was `unlisted` (no Route covers it, nobody listed it) while they
   * carried a credential-bearing header. Host, first path segment, method and
   * the header NAME are counted in memory and posted to
   * `POST /v1/wrap/egress-observations` about once a minute — names, never
   * values; never the query string; never the body. ON by default for
   * `intercept()` and for `routes: "auto"`. `false`, or
   * `KNOXCALL_OBSERVE_UNCOVERED=off` in the environment (read when the
   * transport is built), turns it off; nothing is reported while
   * `KNOXCALL_INTERCEPT=off`. A 403 from the endpoint stops reporting for the
   * life of the handle (warned once).
   */
  observeUncovered?: boolean;
  /** Fires after each accepted observation report with the server's counts — never per observation. */
  onObservationFlush?: (info: { accepted: number; dropped: number }) => void;
}

// Built-in route-around defaults. Mirrors the SERVER's raw-PAN refusal
// (src/client-api/ephemeral-proxy.ts PAN_ENDPOINT_DENYLIST) so a wrapped SDK's
// raw-card call is sent straight to Stripe instead of hard-failing on the 403.
// Deliberately conservative and identical in spirit to the server list; the
// durable answer is tokenize-at-the-edge (plan §3), and a server-fetched list is
// the documented follow-up.
export const DEFAULT_ROUTE_AROUND: RouteAroundRule[] = [
  { host: "api.stripe.com", pathPrefix: "/v1/tokens", reason: "raw-card endpoint (PCI): sent direct to the provider" },
  { host: "api.stripe.com", pathPrefix: "/v1/sources", reason: "raw-card endpoint (PCI): sent direct to the provider" },
];

/** The normalized shape the shim works with, extracted from (input, init). */
export interface ParsedRequest {
  url: string;
  method: string;
  headers: Record<string, string>;   // lower-cased keys
  body?: BodyInit | null;
  /** Caller abort/timeout signal, preserved so a wrapped SDK's abort still works. */
  signal?: AbortSignal;
}

/** Extract url/method/headers/body/signal from a fetch (input, init) pair. */
export function parseFetchArgs(input: string | URL | Request, init?: RequestInit): ParsedRequest {
  let url: string;
  let method = init?.method;
  let signal = init?.signal ?? undefined;
  const headers: Record<string, string> = {};

  const collect = (h: HeadersInit | Record<string, string> | undefined) => {
    if (!h) return;
    if (typeof (h as Headers).forEach === "function" && !Array.isArray(h)) {
      (h as Headers).forEach((v, k) => { headers[k.toLowerCase()] = v; });
    } else if (Array.isArray(h)) {
      for (const [k, v] of h) headers[String(k).toLowerCase()] = String(v);
    } else {
      for (const [k, v] of Object.entries(h)) headers[k.toLowerCase()] = String(v);
    }
  };

  if (typeof input === "string") {
    url = input;
  } else if (input instanceof URL) {
    url = input.toString();
  } else {
    // Request object
    url = input.url;
    method = method ?? input.method;
    signal = signal ?? input.signal ?? undefined;
    collect(input.headers as unknown as HeadersInit);
  }
  collect(init?.headers);

  return {
    url,
    method: (method ?? "GET").toUpperCase(),
    headers,
    body: init?.body ?? null,
    signal,
  };
}

/** Strip a single trailing dot from an FQDN and lower-case it. */
function normalizeHost(host: string): string {
  return host.toLowerCase().replace(/\.$/, "");
}

/** First route-around rule matching this URL, or null. */
export function matchRouteAround(url: string, rules: RouteAroundRule[]): RouteAroundRule | null {
  let u: URL;
  try { u = new URL(url); } catch { return null; }
  // Trailing-dot FQDNs ("api.stripe.com.") resolve to the same host but would
  // dodge an exact-match rule — normalize both sides. The server's PAN denylist
  // (src/client-api/ephemeral-proxy.ts refusedPanEndpoint) normalizes the same
  // way so the client route-around and the server guarantee stay consistent.
  const host = normalizeHost(u.hostname);
  for (const r of rules) {
    if (host !== normalizeHost(r.host)) continue;
    if (r.pathPrefix && !u.pathname.startsWith(r.pathPrefix)) continue;
    return r;
  }
  return null;
}

export class WrapSandboxMismatchError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WrapSandboxMismatchError";
  }
}

/**
 * Both-must-agree (plan PR4): a Stripe key's Test/Live prefix must match the
 * KnoxCall client's `sandbox` flag, so a test key can never be wrapped by a live
 * client (or vice versa) — the class of Test/Live collision the sandbox
 * invariant exists to prevent, one level up. Publishable keys (`pk_`) are
 * rejected outright: they are not server credentials. Non-Stripe schemes we
 * cannot classify are left alone (return without throwing).
 *
 * `authorizationValue` is the full header value, e.g. "Bearer sk_live_…".
 */
export function assertKeyMatchesSandbox(authorizationValue: string | undefined, sandbox: boolean): void {
  if (!authorizationValue) return;
  // Trim BEFORE stripping the scheme: leading whitespace would otherwise stop
  // the anchored `^Bearer` from matching, leaving "Bearer sk_live_…" in `token`,
  // which the classifier can't parse — silently skipping the check.
  const token = authorizationValue.trim().replace(/^Bearer\s+/i, "").trim();
  if (/^pk_(test|live)_/.test(token)) {
    throw new WrapSandboxMismatchError(
      "A Stripe publishable key (pk_…) is not a server credential and cannot be wrapped. Use a secret (sk_…) or restricted (rk_…) key.",
    );
  }
  const m = /^(?:sk|rk)_(test|live)_/.exec(token);
  if (!m) return; // unknown / non-Stripe scheme — nothing to assert
  const keyIsTest = m[1] === "test";
  if (keyIsTest !== sandbox) {
    throw new WrapSandboxMismatchError(
      `Provider key is a ${keyIsTest ? "TEST" : "LIVE"} key but the KnoxCall client was constructed with sandbox=${sandbox}. ` +
        `Test keys require sandbox:true, live keys require sandbox:false — construct a matching client.`,
    );
  }
}

// Headers the shim must NOT forward to ephemeral()'s upstream: the provider
// Authorization is lifted out-of-band; host/content-length are recomputed.
const DROP_FORWARDED = new Set(["authorization", "host", "content-length"]);

/**
 * Validate caller-supplied route-around rules: a `host` that isn't a bare DNS
 * hostname (a scheme/port/path slipped in) can never match `new URL(...).hostname`
 * and would silently disable the rule — fail loud instead. Mirrors the escrow()
 * allowed-hosts contract.
 */
export function assertRouteAroundRules(rules: RouteAroundRule[]): void {
  for (const r of rules) {
    const h = String(r.host ?? "").trim();
    let parsed: string;
    try { parsed = new URL(`https://${h}`).hostname; } catch { parsed = ""; }
    if (!h || normalizeHost(parsed) !== normalizeHost(h)) {
      throw new WrapSandboxMismatchError(
        `Invalid routeAround host ${JSON.stringify(r.host)}: expected a bare DNS hostname (no scheme, port, or path).`,
      );
    }
  }
}

/** The upstream headers to forward (everything the SDK set except the dropped ones). */
export function forwardableHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    if (DROP_FORWARDED.has(k)) continue;
    out[k] = v;
  }
  return out;
}
