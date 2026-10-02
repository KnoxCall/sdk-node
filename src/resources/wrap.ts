// Wrap resource — mirrors src/client-api/wrap.ts (sdk-wrapping PR3/PR4) and
// carries the route-aware interception surface (route-aware-interception-plan.md
// PR2, PARITY §18 + §21).
//
// Three halves:
//   1. management — escrow, gateway tokens, the intercept manifest;
//   2. `fetch()` — the explicit transport a wrapped SDK is handed; ephemeral
//      (transparent) by default, route-aware with `routes: "auto"`;
//   3. `intercept()` — the process-wide interceptor (global fetch + node:http),
//      route-aware by DEFAULT (decision D3): a Route that covers a host takes
//      that host's traffic the moment it exists, a listed host with no Route
//      goes through the ephemeral proxy, everything else is untouched.
//
// The decision table itself is pure (../intercept-resolver.ts) and driven by
// the cross-language fixtures in sdk/fixtures; the manifest's lifecycle is
// ../intercept-manifest-store.ts. This file wires them to the client.

import { INTERCEPT_ORIGIN, NOT_MODIFIED, SDK_VERSION, type APIClient, type InternalCallOptions } from "../core.js";
import { type Envelope, unwrap } from "./shared.js";
import {
  type WrapFetchOptions,
  type RouteAroundRule,
  type WrapCredential,
  DEFAULT_ROUTE_AROUND,
  parseFetchArgs,
  assertKeyMatchesSandbox,
  assertRouteAroundRules,
  forwardableHeaders,
} from "../wrap-transport.js";
import {
  installEgressInterceptor,
  installHttpEgressInterceptor,
  nodeHttpModules,
  combineEgressInterceptors,
  runRouted,
  inRoutedContext,
  runSuppressed,
  type EgressInterceptor,
  type HttpModules,
  type PassThroughInfo,
} from "../egress-interceptor.js";
import {
  EgressObservationReporter,
  observationFor,
  observeUncoveredDisabledByEnv,
} from "../egress-observations.js";
import { InterceptManifestStore, type ManifestRefreshInfo } from "../intercept-manifest-store.js";
import { resolveIntercept, normaliseHost, type InterceptDecision, type InterceptReason } from "../intercept-resolver.js";
import { isRouteRefusal } from "../route-refusal.js";
import { APIConnectionError } from "../error.js";
import { warnOnce } from "../warn.js";

export type { WrapFetchOptions, WrapCredential, RouteAroundRule } from "../wrap-transport.js";
export { WrapSandboxMismatchError, DEFAULT_ROUTE_AROUND } from "../wrap-transport.js";
export type { EgressInterceptor } from "../egress-interceptor.js";
export type { InterceptDecision, InterceptReason, InterceptMode } from "../intercept-resolver.js";
export type { ManifestRefreshInfo } from "../intercept-manifest-store.js";
export type { ObservationFlushInfo } from "../egress-observations.js";

export interface EscrowWrapCredentialInput {
  /** Free-form provider label ('stripe', 'openai', …). Not a security boundary. */
  provider: string;
  /** Secret name the escrowed credential is stored + referenced under. */
  name: string;
  /** The raw provider credential. Sent once; never returned. */
  value: string;
  /**
   * The ONLY upstream hosts this credential may be injected toward — the
   * load-bearing anti-exfiltration pin. Bare DNS hostnames (no scheme/port/path).
   */
  hosts: string[];
}

export interface EscrowWrapCredentialResponse {
  secret_id: string;
  name: string;
  provider: string;
  allowed_hosts: string[];
  sandbox: boolean;
}

export interface GatewayUrlInput {
  /** The escrowed credential (name or id) to inject, from `escrow()`. */
  secret: string;
  /** Upstream host to pin. Optional when the credential allows exactly one. */
  host?: string;
  /** Optional token TTL in seconds. Omit for a non-expiring token. */
  ttlSeconds?: number;
  /** Optional human label for the token list. */
  label?: string;
  /**
   * Which base_url form to return. `"path"` (`…/wg/<token>/<host>`) is always
   * available; `"subdomain"` (`<label>.wrap.<domain>`) is only available when the
   * operator has enabled the wildcard-subdomain gateway (else the call 400s).
   * Omit to let the server choose (subdomain when enabled, else path). NOTE: the
   * subdomain form carries the token in the TLS SNI (plaintext on the wire) —
   * weaker token confidentiality than the path form; prefer a short `ttlSeconds`.
   */
  style?: "path" | "subdomain";
}

export interface GatewayUrlResponse {
  /** wrap-token id — pass to `revokeGatewayToken(id)` to revoke this token. */
  id: string;
  /** The wrap-token — a bearer credential embedded in base_url. Treat as secret. */
  token: string;
  /** Set this as your SDK's base URL; the SDK's own key becomes a placeholder. */
  base_url: string;
  /** Which base_url form was returned (`"path"` or `"subdomain"`). */
  base_url_style?: "path" | "subdomain";
  host: string;
  secret_id: string;
  sandbox: boolean;
  expires_at: string | null;
}

/** A gateway token's metadata (the token itself is never returned by list). */
export interface WrapGatewayToken {
  id: string;
  secret_id: string;
  host: string;
  label: string | null;
  created_at: string;
  expires_at: string | null;
  revoked_at: string | null;
  last_used_at: string | null;
}

/** One entry of the intercept manifest: an upstream host an intercept-enabled Route covers. */
export interface InterceptManifestRoute {
  /** Lower-case DNS hostname, no port, trailing dot stripped. */
  host: string;
  /** Path prefix the route serves under (`/` when its target has none). Forward the request path with this prefix removed. */
  base_path: string;
  /** Send as `x-knoxcall-route`. */
  slug: string;
  route_id: string;
  /** The environment requires a registered client — a bearer-only SDK call will be refused. */
  requires_clients: boolean;
  /** Upper-cased verbs when method restrictions are on; null otherwise. */
  allowed_methods: string[] | null;
  /** Another entry shares this (host, base_path); take the lexically lowest slug and warn. */
  ambiguous?: true;
  updated_at: string | null;
}

/** GET /v1/wrap/intercept-manifest — which hosts an intercept-enabled Route covers for one environment. */
export interface InterceptManifest {
  /** Content hash of `routes`; doubles as the ETag. */
  version: string;
  /** How long to hold this manifest before polling again. */
  ttl_seconds: number;
  environment: string;
  sandbox: boolean;
  /** Sorted by host, then longest `base_path` first, then slug. */
  routes: InterceptManifestRoute[];
}

export interface InterceptManifestOptions {
  /** Environment to resolve for. Omit for the tenant's default environment. */
  environment?: string;
  /**
   * The manifest `version` you already hold (not an ETag — the SDK sends it as
   * the server's weak tag, `If-None-Match: W/"<version>"`). When the server's
   * manifest still has that version it answers `304` and the call resolves to
   * `null`: keep what you hold. Omit for an unconditional fetch.
   */
  ifNoneMatch?: string;
}

/** The weak ETag the manifest endpoint sets for a `version` (`src/client-api/wrap.ts`). */
export function manifestEtag(version: string): string {
  return `W/"${version}"`;
}

/**
 * One uncovered-egress observation (PARITY §21.3): a credentialed call the
 * interceptor sent DIRECT because no Route covered its host and nobody listed
 * it. Names, never values — the credential header's NAME, never its value;
 * the first path segment, never the query string or the body.
 */
export interface EgressObservation {
  /** Normalised host: lower-case, no port, brackets and trailing dot stripped. */
  host: string;
  /** `/` or `/<first path segment>` — never the query string, never deeper. */
  first_segment: string;
  /** Upper-case HTTP method. */
  method: string;
  /** Lower-case NAME of the credential-bearing header. Never its value. */
  header_name: string;
  /** Calls aggregated into this observation (positive). */
  count: number;
  /** ISO-8601 UTC. */
  first_seen: string;
  /** ISO-8601 UTC. */
  last_seen: string;
}

/** POST /v1/wrap/egress-observations — what the server did with a report. */
export interface EgressObservationsReport {
  accepted: number;
  dropped: number;
  /** Dropped observations by reason. */
  reasons: Record<string, number>;
  /** Accepted observations whose content the server reduced, by reason (e.g. `first_segment_looks_like_credential`). */
  redacted?: Record<string, number>;
}

export interface ReportEgressObservationsOptions {
  /** `<language>/<version>` of the reporting SDK; defaults to this one's. */
  sdk?: string;
}

/** Per-host options for `intercept()` when `hosts` is given as a map. */
export interface HostOptions {
  /** Escrow mode for this host's ephemeral traffic (omit for transit: the SDK's own Authorization is lifted). */
  credential?: WrapCredential;
  /**
   * When KnoxCall is unreachable for this host's EPHEMERAL traffic: `"error"`
   * (default — the SDK's connection error surfaces; decision D4) or `"direct"`
   * (send the original request untouched via the original transport, and fire
   * `onFallback`). Only transit mode may go direct — the key is in the process
   * there. Escrow and route mode never can: there is no credential to go
   * direct with.
   */
  unavailable?: "error" | "direct";
}

export type InterceptHosts = string[] | Record<string, HostOptions>;

/** The function `wrap.fetch()` returns, plus the route-aware controls. */
export interface WrappedFetch {
  (input: string | URL | Request, init?: RequestInit): Promise<Response>;
  /** Resolves once the first manifest attempt settled (immediately with `routes: "off"`). Never rejects. */
  readonly ready: Promise<void>;
  /** Refresh the manifest now (no-op with `routes: "off"`). */
  refresh(): Promise<void>;
  /** The manifest this transport is deciding on, or null. */
  manifest(): InterceptManifest | null;
  /** Stop polling. The transport keeps working on its last manifest. */
  stop(): void;
}

/** Options for `intercept()` — the process-wide, route-aware interceptor. */
export interface InterceptOptions extends WrapFetchOptions {
  /**
   * Hosts to cover even when NO Route does (they go through the ephemeral
   * proxy): a list, or a map with per-host options. Hosts a Route covers are
   * added from the manifest automatically (`routes: "auto"`, the default), so
   * this may be empty. Never widened to "all egress" (decision D2).
   */
  hosts?: InterceptHosts;
  /**
   * Which egress stacks to patch. Defaults to BOTH:
   *   - `"fetch"` — the process's global `fetch`.
   *   - `"http"`  — node:http / node:https `.request`/`.get`, which catches
   *     axios, node-fetch, cross-fetch, got and most non-`fetch` SDKs with NO
   *     added dependency.
   * A captured `fetch`/`request` reference, or an SDK on its own undici
   * `Dispatcher`, is still not reached — use `wrap.fetch()`/`wrap.gatewayUrl()`.
   */
  stacks?: Array<"fetch" | "http">;
  /** Only reroute inside `wrap.routed()` — off by default (host-list + manifest scope). */
  requireContext?: boolean;
  /** @internal fetch install target; defaults to globalThis. Injected for tests. */
  target?: { fetch: (input: string | URL | Request, init?: RequestInit) => Promise<Response> };
  /** @internal http(s) modules to patch; defaults to node:http + node:https. Injected for tests. */
  httpModules?: HttpModules;
}

/** @deprecated Use {@link InterceptOptions}. Kept for `interceptEgress()`. */
export interface InterceptEgressOptions extends Omit<InterceptOptions, "hosts"> {
  /** Bare DNS hostnames whose outbound traffic is rerouted through KnoxCall. */
  hosts: string[];
}

/** What `intercept()` returns: the uninstall handle plus the route-aware controls. */
export interface InterceptHandle extends EgressInterceptor {
  /** Resolves once the first manifest attempt settled. Never rejects. */
  readonly ready: Promise<void>;
  /** Refresh the manifest now. */
  refresh(): Promise<void>;
  /** The manifest the interceptor is deciding on, or null. */
  manifest(): InterceptManifest | null;
}

/** `KNOXCALL_INTERCEPT=off` turns every interceptor and route-aware transport into pass-through, per request, no deploy. */
export function interceptKillSwitch(): boolean {
  const v = process.env.KNOXCALL_INTERCEPT;
  return typeof v === "string" && ["off", "0", "false"].includes(v.trim().toLowerCase());
}

function hostOfUrl(u: string | undefined): string | null {
  if (!u) return null;
  try {
    return normaliseHost(new URL(u).hostname) || null;
  } catch {
    return null;
  }
}

/** True when a body can be sent a second time (a refusal answered before upstream is safe to replay). */
function bodyIsReplayable(body: unknown): boolean {
  if (body == null) return true;
  if (typeof body === "string") return true;
  if (typeof ArrayBuffer !== "undefined" && (body instanceof ArrayBuffer || ArrayBuffer.isView(body))) return true;
  if (typeof URLSearchParams !== "undefined" && body instanceof URLSearchParams) return true;
  if (typeof Blob !== "undefined" && body instanceof Blob) return true;
  if (typeof FormData !== "undefined" && body instanceof FormData) return true;
  return false; // a ReadableStream, or anything we cannot vouch for
}

/** Everything a route-aware transport needs beyond the options: how to scope, where to send direct. */
interface TransportContext {
  hosts: ReadonlySet<string> | "all";
  hostOptions: ReadonlyMap<string, HostOptions>;
  requireContext: boolean;
  inContext: () => boolean;
  directFetch: typeof fetch;
  /** The form's default for uncovered-egress reporting (the option and env still apply). */
  observe: boolean;
}

export class WrapResource {
  constructor(private readonly client: APIClient) {}

  /** Escrow a provider credential (POST /v1/wrap/credentials). */
  async escrow(
    input: EscrowWrapCredentialInput,
    opts?: { idempotencyKey?: string },
  ): Promise<EscrowWrapCredentialResponse> {
    return unwrap(await this.client.request<Envelope<EscrowWrapCredentialResponse>>({
      method: "POST",
      path: "/v1/wrap/credentials",
      body: input,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  /**
   * Mint a base-URL gateway token for an escrowed credential and return the
   * `base_url` to point a wrapped SDK at. For SDKs that expose ONLY a base-URL
   * override and no `fetch`/transport hook (Resend, Mailgun, Airtable, …) — where
   * `fetch()` above cannot be used.
   *
   *   const { base_url } = await knox.wrap.gatewayUrl({ secret: "stripe-live", host: "api.stripe.com" });
   *   const resend = new Resend("placeholder_key", { baseUrl: base_url });
   *
   * Escrow-only: the SDK's own key is a placeholder; KnoxCall injects the escrowed
   * secret server-side, so the real key is never in your process. The token is a
   * bearer credential embedded in the URL — see the base-URL-gateway docs for the
   * logging/revocation trade-offs.
   */
  async gatewayUrl(
    input: GatewayUrlInput,
    opts?: { idempotencyKey?: string },
  ): Promise<GatewayUrlResponse> {
    const body: Record<string, unknown> = { secret: input.secret };
    if (input.host !== undefined) body.host = input.host;
    if (input.ttlSeconds !== undefined) body.ttl_seconds = input.ttlSeconds;
    if (input.label !== undefined) body.label = input.label;
    if (input.style !== undefined) body.style = input.style;
    return unwrap(await this.client.request<Envelope<GatewayUrlResponse>>({
      method: "POST",
      path: "/v1/wrap/tokens",
      body,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  /**
   * The intercept manifest (GET /v1/wrap/intercept-manifest): which upstream
   * hosts an intercept-enabled Route covers in this space, for one environment,
   * and the slug to send them under. This is what a route-aware interceptor
   * polls; `version` is the ETag. Scope: `routes:read`.
   *
   * Conditional form: pass `ifNoneMatch` (the `version` you hold) and the SDK
   * sends `If-None-Match: W/"<version>"`; a `304` resolves to `null` — keep
   * what you hold. Everything else (auth, the one re-auth on 401, retries,
   * a 200 with a newer manifest) is exactly the unconditional call.
   */
  async interceptManifest(opts: InterceptManifestOptions & { ifNoneMatch: string | undefined }): Promise<InterceptManifest | null>;
  async interceptManifest(opts?: InterceptManifestOptions): Promise<InterceptManifest>;
  async interceptManifest(opts: InterceptManifestOptions = {}): Promise<InterceptManifest | null> {
    const query = opts.environment !== undefined ? { environment: opts.environment } : undefined;
    if (opts.ifNoneMatch === undefined) {
      return unwrap(await this.client.request<Envelope<InterceptManifest>>({
        method: "GET",
        path: "/v1/wrap/intercept-manifest",
        query,
      }));
    }
    const res = await this.client.request<Envelope<InterceptManifest>>({
      method: "GET",
      path: "/v1/wrap/intercept-manifest",
      query,
      headers: { "If-None-Match": manifestEtag(opts.ifNoneMatch) },
      allowNotModified: true,
    });
    return res === NOT_MODIFIED ? null : unwrap(res);
  }

  /**
   * Report uncovered-egress observations (POST /v1/wrap/egress-observations;
   * PARITY §21.3) — the thin typed wrapper the interceptor's reporter uses,
   * exported so an integrator can report by hand. At most 200 observations
   * per call. The body carries names, never values: a credential header's
   * NAME, the host, the first path segment, the method and counts. Scope:
   * `routes:read`.
   */
  async reportEgressObservations(
    observations: EgressObservation[],
    opts: ReportEgressObservationsOptions = {},
  ): Promise<EgressObservationsReport> {
    return unwrap(await this.client.request<Envelope<EgressObservationsReport>>({
      method: "POST",
      path: "/v1/wrap/egress-observations",
      body: { sdk: opts.sdk ?? `node/${SDK_VERSION}`, observations },
    }));
  }

  /** List this space's gateway tokens (metadata only — the token is never returned). */
  async listGatewayTokens(): Promise<WrapGatewayToken[]> {
    const res = unwrap(await this.client.request<Envelope<{ tokens: WrapGatewayToken[] }>>({
      method: "GET",
      path: "/v1/wrap/tokens",
    }));
    return res.tokens;
  }

  /** Revoke a single gateway token by id (from `gatewayUrl()` or `listGatewayTokens()`). */
  async revokeGatewayToken(id: string): Promise<{ id: string; revoked: boolean }> {
    return unwrap(await this.client.request<Envelope<{ id: string; revoked: boolean }>>({
      method: "DELETE",
      path: `/v1/wrap/tokens/${encodeURIComponent(id)}`,
    }));
  }

  /**
   * A `fetch`-compatible function that routes a wrapped SDK's requests through
   * KnoxCall. Hand it to any SDK that accepts a `fetch`/`baseURL`-style transport:
   *
   *   // OpenAI, Anthropic, Octokit, … (any fetch-accepting SDK):
   *   const openai = new OpenAI({ fetch: knox.wrap.fetch() });
   *
   *   // Stripe takes an httpClient, not a fetch — feed ours to its own factory:
   *   const stripe = new Stripe(key, { httpClient: Stripe.createFetchHttpClient(knox.wrap.fetch()) });
   *
   * Default (`routes: "off"`): every request goes through the ephemeral proxy in
   * transparent mode. Transit mode lifts the wrapped SDK's own `Authorization`
   * header out-of-band (never a raw header, never logged); escrow mode
   * (`{ credential: { secret } }`) keeps the raw key in KnoxCall custody.
   *
   * Route-aware (`routes: "auto"`): the transport polls the intercept manifest
   * and sends a request through the Route that covers its host + path — the
   * Route injects the stored secret, so NO provider credential travels — falling
   * back to the ephemeral proxy for anything no Route covers. Creating,
   * enabling or disabling a Route takes effect on the next poll (`ttl_seconds`)
   * or the next refusal, with no code change. `await wrapped.ready` to avoid
   * the first calls going ephemeral before the manifest has loaded.
   *
   * Requests matching a route-around rule (raw-card endpoints by default) are
   * sent to the provider DIRECTLY, untouched. `KNOXCALL_INTERCEPT=off` makes
   * every request direct.
   */
  fetch(opts: WrapFetchOptions = {}): WrappedFetch {
    const directFetch = opts.directFetch ?? globalThis.fetch;
    const { send, store, reporter } = this.#makeTransport(opts, {
      hosts: "all",
      hostOptions: new Map(),
      requireContext: false,
      inContext: () => true,
      directFetch,
      // An explicit transport treats every host as listed, so `unlisted` never
      // occurs here by construction; the reporter is still built with
      // routes: "auto" so the contract (and the opt-out) reads the same.
      observe: (opts.routes ?? "off") === "auto",
    });
    const fn = ((input: string | URL | Request, init?: RequestInit) => send(input, init)) as WrappedFetch;
    Object.defineProperties(fn, {
      ready: { value: store ? store.ready : Promise.resolve(), enumerable: false },
      refresh: { value: async () => { if (store) await store.refresh("manual", { force: true }); }, enumerable: false },
      manifest: { value: () => store?.get() ?? null, enumerable: false },
      stop: { value: () => { store?.stop(); void reporter?.stop(); }, enumerable: false },
    });
    return fn;
  }

  /**
   * Reroute outbound egress for the hosts a Route covers — and for `hosts`
   * you list — through KnoxCall, with NO per-SDK wiring. Patches the process's
   * global `fetch` AND node:http / node:https `.request`/`.get` (both by
   * default — scope with `stacks`). Returns a handle; call `.uninstall()` to
   * restore the originals.
   *
   *   const knox = new KnoxCall({ apiKey });
   *   const stop = knox.wrap.intercept({ hosts: ["api.openai.com"] });
   *   await stop.ready;                        // first manifest loaded
   *   const hubspot = new Client({ accessToken: "placeholder" }); // untouched SDK
   *   await hubspot.crm.contacts.basicApi.getPage();   // via the Route that covers api.hubapi.com
   *   stop.uninstall();
   *
   * Decision per request (route-aware-interception-plan.md §2.2): kill switch →
   * direct; KnoxCall's own hosts → direct; route-around rule → direct; a Route
   * in the manifest covers host + path → ROUTE mode (the Route injects the
   * secret); host in `hosts` → EPHEMERAL proxy; otherwise → untouched.
   *
   * This is a CONVENIENCE, not a security boundary — it patches process globals
   * (covers the `fetch` + `http`/`https` stacks but not a captured reference or
   * a custom undici Dispatcher, composes badly with APM agents, and is not a
   * boundary against hostile in-process code). ROUTE mode is the custody path:
   * the key never enters the process. Transit is not. See
   * docs/internal/sdk-wrapping/egress-interceptor.md.
   */
  intercept(opts: InterceptOptions = {}): InterceptHandle {
    const { hosts: rawHosts, stacks, requireContext, target, httpModules, ...wrapOpts } = opts;
    const hostSet = new Set<string>();
    const hostOptions = new Map<string, HostOptions>();
    if (Array.isArray(rawHosts)) {
      for (const h of rawHosts) hostSet.add(normaliseHost(h));
    } else if (rawHosts && typeof rawHosts === "object") {
      for (const [h, o] of Object.entries(rawHosts)) {
        hostSet.add(normaliseHost(h));
        hostOptions.set(normaliseHost(h), o ?? {});
      }
    }
    hostSet.delete("");
    const routesMode = wrapOpts.routes ?? "auto";
    if (hostSet.size === 0 && routesMode === "off") {
      throw new TypeError("intercept requires `hosts` when `routes` is \"off\" — there would be nothing to intercept.");
    }

    const enabled = new Set<"fetch" | "http">(stacks && stacks.length ? stacks : ["fetch", "http"]);
    const tgt = target ?? (globalThis as unknown as { fetch: typeof fetch });
    const originalFetch = tgt.fetch;

    // One transport serves both stacks; its direct path is pinned to the
    // ORIGINAL global fetch (never the patched one).
    const { send, store, observe, reporter } = this.#makeTransport(
      { ...wrapOpts, routes: routesMode, directFetch: originalFetch as typeof fetch },
      {
        hosts: hostSet,
        hostOptions,
        requireContext: requireContext === true,
        inContext: () => inRoutedContext(),
        directFetch: originalFetch as typeof fetch,
        observe: true,
      },
    );

    const ownHosts = () => this.#ownHosts();
    // Listed hosts, plus whatever the manifest covers right now, minus our own
    // hosts (anti-recursion: the manifest poll itself must never be caught).
    const matchHost = (host: string): boolean => {
      if (ownHosts().has(host)) return false;
      if (hostSet.has(host)) return true;
      const m = store?.get();
      return !!m && m.routes.some((e) => normaliseHost(e.host) === host);
    };
    const reroute = (input: string | URL | Request, init?: RequestInit) => send(input, init);
    const onReroute = wrapOpts.onReroute;
    const notify = onReroute ? (info: { host: string; url: string }) => onReroute({ ...info, mode: "intercepted", reason: "matched" }) : undefined;
    const enabledFn = () => !interceptKillSwitch();

    const handles: EgressInterceptor[] = [];
    try {
      if (enabled.has("fetch")) {
        handles.push(installEgressInterceptor({ hosts: [...hostSet], matchHost, enabled: enabledFn, reroute, target: tgt, requireContext, onReroute: notify, onPassThrough: observe }));
      }
      if (enabled.has("http")) {
        handles.push(
          installHttpEgressInterceptor({
            hosts: [...hostSet],
            matchHost,
            enabled: enabledFn,
            reroute,
            modules: httpModules ?? nodeHttpModules(),
            requireContext,
            onReroute: notify,
            onPassThrough: observe,
          }),
        );
      }
    } catch (e) {
      // Never leave a half-installed interceptor patched onto the process — if
      // the second stack refuses (e.g. a stale install), roll back the first.
      for (const h of handles) h.uninstall();
      store?.stop();
      void reporter?.stop();
      throw e;
    }

    const combined = combineEgressInterceptors(handles);
    return {
      get installed() {
        return combined.installed;
      },
      uninstall() {
        combined.uninstall();
        store?.stop();
        // The final flush is fire-and-forget: uninstall stays synchronous and
        // the report can never fail into the caller.
        void reporter?.stop();
      },
      ready: store ? store.ready : Promise.resolve(),
      refresh: async () => { if (store) await store.refresh("manual", { force: true }); },
      manifest: () => store?.get() ?? null,
    };
  }

  /**
   * @deprecated Use {@link intercept} — the same interceptor, route-aware by
   * default. This alias keeps the original static-host, ephemeral-only
   * behaviour (`routes: "off"`).
   */
  interceptEgress(opts: InterceptEgressOptions): EgressInterceptor {
    return this.intercept({ ...opts, routes: "off" });
  }

  /**
   * Run `fn` in a "routed" async scope. When an interceptor was installed with
   * `requireContext: true`, only egress performed inside `routed()` (and its
   * awaited descendants) is rerouted — you mark the CALL SITE, not the SDK.
   */
  routed<T>(fn: () => T): T {
    return runRouted(fn);
  }

  // ── the route-aware transport ────────────────────────────────────────────

  /** The client's own hosts — never intercepted, whatever a manifest or list says. */
  #ownHosts(): Set<string> {
    const s = new Set<string>();
    const a = hostOfUrl(this.client.baseUrl);
    const b = hostOfUrl(this.client.proxyBaseUrl);
    if (a) s.add(a);
    if (b) s.add(b);
    return s;
  }

  #makeTransport(
    opts: WrapFetchOptions,
    ctx: TransportContext,
  ): {
    send: (input: string | URL | Request, init?: RequestInit) => Promise<Response>;
    store: InterceptManifestStore | null;
    /** The uncovered-egress observer a seam hands its pass-throughs to (a no-op when reporting is off). */
    observe: (info: PassThroughInfo) => void;
    reporter: EgressObservationReporter | null;
  } {
    const client = this.client;
    // Escrow-vs-transit is decided by the credential shape; a malformed
    // `{ credential: {} }` (or `{ secret: "" }`) must NOT silently fall through
    // to transit mode and leak the SDK's raw key — fail loud.
    const checkCredential = (c: WrapCredential | undefined, where: string) => {
      if (c === undefined) return;
      const secret = (c as { secret?: unknown }).secret;
      if (typeof secret !== "string" || secret === "") {
        throw new TypeError(`${where} credential must be { secret: <non-empty string> } for escrow mode; omit \`credential\` entirely for transit mode.`);
      }
    };
    checkCredential(opts.credential, "wrap");
    for (const [h, o] of ctx.hostOptions) checkCredential(o.credential, `intercept host ${h}`);
    if (opts.routeAround) assertRouteAroundRules(opts.routeAround);
    const rules: RouteAroundRule[] = [
      ...(opts.disableDefaultRouteAround ? [] : DEFAULT_ROUTE_AROUND),
      ...(opts.routeAround ?? []),
    ];
    // `autoSwitch` alone keeps its pre-manifest meaning (remember a hint per
    // host); only `routes: "auto"` consults the manifest.
    const routesMode: "auto" | "off" = opts.routes ?? "off";

    // Legacy per-instance auto-switch memory (host → promoted slug), kept for
    // callers on `autoSwitch: true` from before the manifest existed. Consulted
    // only when the manifest has no entry for the host.
    const autoSwitched = new Map<string, string>();
    const unmatchedWarned = new Set<string>();

    const store: InterceptManifestStore | null =
      routesMode === "auto"
        ? new InterceptManifestStore({
            fetchManifest: ({ ifNoneMatch }) =>
              this.interceptManifest({
                ...(client.environment ? { environment: client.environment } : {}),
                ifNoneMatch,
              }),
            onRefresh: (info: ManifestRefreshInfo) => {
              for (const e of info.added) {
                if (e.requires_clients) {
                  warnOnce(
                    `KNOXCALL_INTERCEPT_REQUIRES_CLIENTS:${e.slug}`,
                    `KnoxCall route "${e.slug}" (${e.host}${e.base_path}) requires a registered client; a bearer-only SDK call will be refused (403). ` +
                      `Register this process as a client of the route, or leave the route out of interception.`,
                  );
                }
                if (e.ambiguous) {
                  warnOnce(
                    `KNOXCALL_INTERCEPT_AMBIGUOUS:${e.host}${e.base_path}`,
                    `KnoxCall: more than one intercept-enabled route covers ${e.host}${e.base_path}; the lexically lowest slug is used. Disable the others.`,
                  );
                }
              }
              opts.onRefresh?.(info);
            },
            onError: opts.onManifestError,
          })
        : null;
    store?.start();

    const decide = (url: string, method: string): InterceptDecision =>
      resolveIntercept({
        url,
        method,
        hosts: ctx.hosts,
        manifest: store?.get() ?? null,
        ownHosts: this.#ownHosts(),
        routeAround: rules,
        killSwitch: interceptKillSwitch(),
        requireContext: ctx.requireContext,
        inContext: ctx.inContext(),
      });

    // Uncovered-egress observations (PARITY §21.3). ON by default (founder
    // decision 2026-09-26); `observeUncovered: false` or the environment turns
    // it off. The report rides the SDK's own credential through request()
    // inside the suppressed scope, so it is never itself intercepted.
    const reporter: EgressObservationReporter | null =
      ctx.observe && opts.observeUncovered !== false && !observeUncoveredDisabledByEnv()
        ? new EgressObservationReporter({
            report: (observations) => this.reportEgressObservations(observations),
            onFlush: opts.onObservationFlush,
            runSuppressed,
          })
        : null;

    // A seam hands every request it passed through untouched here. Only a
    // DIRECT + `unlisted` decision with a credential-bearing header is
    // recorded — `own_host`, `route_around`, `kill_switch`, `outside_context`
    // and `unparseable` never are. Runs after the decision, before the direct
    // send, and can never throw into the application's request.
    const observe = (info: PassThroughInfo): void => {
      if (!reporter) return;
      try {
        const d = decide(info.url, info.method);
        if (d.mode !== "direct" || d.reason !== "unlisted") return;
        const obs = observationFor(info.url, info.method, info.headers());
        if (obs) reporter.record(obs);
      } catch {
        // best-effort: telemetry must never reach the application's request.
      }
    };

    const sendRoute = async (
      slug: string,
      path: string,
      req: ReturnType<typeof parseFetchArgs>,
      body: BodyInit | undefined,
    ): Promise<Response> => {
      const callOpts: InternalCallOptions = {
        method: req.method,
        path,
        headers: forwardableHeaders(req.headers),
        body,
        // Every route-mode reroute is marked (PARITY §21.2) — the manifest
        // decision and the legacy explicit `route:` form alike: both are a
        // third-party SDK's call this pipeline redirected, which is what the
        // API Log's "SDK intercept" origin means.
        [INTERCEPT_ORIGIN]: true,
      };
      if (req.signal) callOpts.signal = req.signal;
      return client.call(slug, callOpts);
    };

    const sendEphemeral = async (
      req: ReturnType<typeof parseFetchArgs>,
      body: BodyInit | undefined,
      host: string,
      input: string | URL | Request,
      init: RequestInit | undefined,
    ): Promise<Response> => {
      const hostOpts = ctx.hostOptions.get(host);
      const credential = hostOpts?.credential ?? opts.credential;
      const ephemeralOpts: Parameters<APIClient["ephemeral"]>[1] = {
        method: req.method,
        body,
        headers: forwardableHeaders(req.headers),
        mode: "transparent",
      };
      if (req.signal) ephemeralOpts.signal = req.signal; // preserve caller abort/timeout

      if (credential) {
        // Escrow mode — the raw key never travels.
        ephemeralOpts.upstreamAuthSecret = credential.secret;
        if (credential.scheme !== undefined) ephemeralOpts.upstreamAuthScheme = credential.scheme;
      } else {
        // Transit mode — lift the SDK's own Authorization header out-of-band.
        const auth = req.headers["authorization"];
        assertKeyMatchesSandbox(auth, client.sandbox);
        if (auth !== undefined) ephemeralOpts.upstreamAuthorization = auth;
      }

      let res: Response;
      try {
        res = await client.ephemeral(req.url, ephemeralOpts);
      } catch (err) {
        // D4: fail closed by default. `unavailable: "direct"` is honoured only
        // for TRANSIT traffic — the key is in the process there. Escrow has
        // nothing to go direct with.
        const policy = hostOpts?.unavailable ?? opts.unavailable ?? "error";
        if (err instanceof APIConnectionError && policy === "direct" && !credential) {
          opts.onFallback?.({ host, url: req.url, error: err });
          return ctx.directFetch(input as RequestInfo, init);
        }
        throw err;
      }

      // Promoted-route hint (PR6): a Route now covers this host. With a
      // manifest, the hint is a signal to refresh it — the manifest is the
      // truth. Without one (legacy `autoSwitch`), remember the slug directly.
      const slug = res.headers.get("x-knox-promoted-route");
      if (slug && host) {
        opts.onPromoted?.({ host, slug });
        if (store) void store.refresh("promoted_hint");
        else if (opts.autoSwitch) autoSwitched.set(host, slug);
      }
      return res;
    };

    const send = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      const req = parseFetchArgs(input, init);
      let decision = decide(req.url, req.method);

      if (decision.mode === "direct") {
        if (decision.reason === "route_around") {
          opts.onRouteAround?.({ url: req.url, host: decision.host, reason: decision.routeAroundReason ?? "" });
        } else if (decision.reason === "unlisted") {
          observe({ url: req.url, method: req.method, headers: () => req.headers });
        }
        // The ORIGINAL (input, init) is forwarded untouched — body/stream intact.
        return ctx.directFetch(input as RequestInfo, init);
      }

      // A Request object carries its body on the stream, not init.body — recover
      // it (cloned, so the original isn't consumed) rather than forward an empty
      // body. Only when init.body wasn't supplied.
      let body = req.body ?? undefined;
      if (body == null && input instanceof Request && input.body != null) {
        body = await input.clone().arrayBuffer();
      }

      // Explicit `route:` (legacy): every non-direct request goes via that slug
      // with the full path, exactly as before the manifest existed.
      const legacySlug = opts.route ?? (decision.mode === "ephemeral" ? autoSwitched.get(decision.host) : undefined);
      if (legacySlug) {
        const u = new URL(req.url);
        opts.onReroute?.({ host: decision.host, url: req.url, mode: "route", slug: legacySlug, reason: "explicit_route" });
        return sendRoute(legacySlug, u.pathname + u.search, req, body);
      }

      if (decision.mode === "route") {
        opts.onReroute?.({ host: decision.host, url: req.url, mode: "route", slug: decision.slug, reason: decision.reason });
        let res = await sendRoute(decision.slug!, decision.path!, req, body);
        if (store && (await isRouteRefusal(res))) {
          // Stale manifest or refused credential (a KnoxCall-origin 401), or a
          // route the manifest still names that no longer resolves (a
          // KnoxCall-origin 404 route_not_found) — one refresh tells them apart
          // (PARITY §21). Re-decide; resend only if the answer changed and the
          // body can be sent twice. Never loop.
          // Forced: a refusal is direct evidence the copy is stale; single-flight
          // still collapses a burst into one call.
          await store.refresh("route_refused", { force: true });
          const again = decide(req.url, req.method);
          const changed = again.mode !== "route" || again.slug !== decision.slug || again.path !== decision.path;
          opts.onRefused?.({ host: decision.host, url: req.url, slug: decision.slug!, status: res.status, redecided: changed ? again.mode : null });
          if (changed && bodyIsReplayable(body)) {
            decision = again;
            if (again.mode === "route") {
              res = await sendRoute(again.slug!, again.path!, req, body);
            } else if (again.mode === "ephemeral") {
              res = await sendEphemeral(req, body, again.host, input, init);
            } else {
              res = await ctx.directFetch(input as RequestInfo, init);
            }
          }
        }
        return res;
      }

      // Ephemeral.
      if (decision.reason === "no_base_path_match") {
        const key = `${decision.host} ${new URL(req.url).pathname.split("/").slice(0, 2).join("/")}`;
        if (!unmatchedWarned.has(key)) {
          unmatchedWarned.add(key);
          opts.onUnmatchedPath?.({ host: decision.host, url: req.url });
        }
      }
      opts.onReroute?.({ host: decision.host, url: req.url, mode: "ephemeral", reason: decision.reason });
      return sendEphemeral(req, body, decision.host, input, init);
    };

    return { send, store, observe, reporter };
  }
}
