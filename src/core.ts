// APIClient — the request pipeline.
//
// Step-by-step from user code to wire and back:
//   1. Build URL + canonical request shape
//   2. Resolve auth (token cache → refresh if stale via single-flight lock)
//   3. Inject Authorization (Bearer or DPoP)
//   4. Sign DPoP proof for this request (when DPoP keypair present)
//   5. Standard headers (API-Version, User-Agent, Idempotency-Key)
//   6. HTTPS send
//   7. Classify response, retry on transient errors with exponential backoff
//   8. Map error status to typed errors
//   9. Parse JSON
//  10. Return typed result

import { AccessToken, ClientCredentials, autoDetectBootstrap, type Bootstrap } from "./auth/bootstrap.js";
import { readProfile, resolveCredentialsPath, resolveProfile } from "./auth/credentials-file.js";
import { DpopKeyPair } from "./auth/dpop.js";
import { MemoryTokenStore, type TokenStore, type CachedToken } from "./auth/token-store.js";
import { fetchToken, refreshTokenGrant } from "./auth/oauth.js";
import {
  errorFromResponse,
  APIConnectionError,
  APIConnectionTimeoutError,
  APIUserAbortError,
  KnoxCallError,
  RateLimitError,
  ServerError,
  BootstrapError,
} from "./error.js";
import { ulid } from "./ulid.js";
import { warnOnce, isInsecureRemoteUrl } from "./warn.js";
import { verifyWebhookSignature } from "./resources/webhooks.js";
import { TelemetryBuffer, type TelemetryHooks } from "./telemetry.js";

export interface KnoxCallOptions {
  /** Tenant slug. Falls back to the ``KNOXCALL_TENANT`` env var. */
  tenant?: string;
  /**
   * Default environment for data-plane calls. Falls back to the
   * ``KNOXCALL_ENVIRONMENT`` env var; per-call and bound-route values win.
   */
  environment?: string;
  scope?: string[];
  baseUrl?: string;
  /** Override the proxy base URL for ``call()``. Defaults to ``https://{tenant}.knoxcall.com`` on cloud, or ``baseUrl`` for local dev. */
  proxyBaseUrl?: string;
  /**
   * Sandbox / test mode. When true, defaults baseUrl to
   * ``https://sandbox.knoxcall.com`` and proxyBaseUrl to
   * ``https://sandbox-{tenant}.knoxcall.com`` — the Stripe-style
   * isolated test environment. Requires a ``tk_test_`` API key.
   * Ignored when an explicit ``baseUrl`` is provided.
   */
  sandbox?: boolean;
  bootstrap?: Bootstrap;
  /** Flat form of {@link ClientCredentials} — pass together with ``clientSecret``. */
  clientId?: string;
  clientSecret?: string;
  /** Flat form of {@link AccessToken} — a pre-acquired ``kc_…`` token or legacy ``tk_…``/``AKE…`` key. */
  accessToken?: string;
  /** Same behavior as ``accessToken`` — two spellings, one credential. */
  apiKey?: string;
  tokenStore?: TokenStore;
  dpop?: "auto" | "always" | "never";
  retry?: { maxAttempts?: number; baseDelayMs?: number; maxDelayMs?: number };
  timeout?: { total?: number };
  apiVersion?: string;
  userAgent?: string;
  fetchImpl?: typeof fetch;
  telemetry?: TelemetryHooks;
  /** Custom JSON.stringify replacer for request bodies (Date already serializes via toJSON). */
  jsonReplacer?: (key: string, value: unknown) => unknown;
}

// The dated API version this SDK was built against. Sent as `KnoxCall-Version`
// on every request so the SDK stays pinned to a known API shape even after the
// server ships a newer default (see the server's src/client-api/versioning.ts).
// Must be a version the server's registry knows, or requests are rejected 400.
const DEFAULT_API_VERSION = "2026-08-05";
export const SDK_VERSION = "1.1.0";
const REFRESH_AHEAD_MS = 5 * 60 * 1000;
// Honor a server Retry-After up to this long; beyond it, fail fast so callers
// can apply their own scheduling instead of blocking a worker.
const RETRY_AFTER_CAP_MS = 30_000;
// A cached token inside the refresh-ahead window is still usable this long
// before real expiry; used as a fallback when the token endpoint is down.
const STALE_TOKEN_MIN_REMAINING_MS = 10_000;

// 409 is deliberately NOT retryable — a real conflict does not resolve by replaying.
const RETRYABLE_STATUSES = new Set([408, 429, 500, 502, 503, 504]);

/**
 * The value `request()` resolves to for a `304 Not Modified` when the caller
 * opted in with `allowNotModified` (a conditional GET carrying `If-None-Match`).
 * Internal: the one consumer is `wrap.interceptManifest({ ifNoneMatch })`,
 * which maps it to `null`. Without the opt-in a 304 keeps its old behaviour
 * (an empty body parsed as `null`), so nothing else changes.
 */
export const NOT_MODIFIED: unique symbol = Symbol("knoxcall.not_modified");

interface ManagementRequestOptions {
  method: string;
  path: string;
  query?: Record<string, string | number | boolean | undefined>;
  body?: unknown;
  headers?: Record<string, string>;
  signal?: AbortSignal;
  idempotencyKey?: string;
  /**
   * Treat a `304 Not Modified` as success with no body and resolve to
   * `NOT_MODIFIED`, instead of parsing the empty body. Auth, the one
   * transparent re-auth on 401 and the retry policy are unchanged — the
   * caller's headers (the `If-None-Match`) ride on every attempt.
   */
  allowNotModified?: boolean;
}

// Codes that mean the TCP/TLS connection was never established — Node's
// dns/net layers and undici surface these on the error (or its cause chain).
const CONNECT_ERROR_CODES = new Set([
  "ECONNREFUSED",
  "ENOTFOUND",
  "EAI_AGAIN",
  "EHOSTUNREACH",
  "ENETUNREACH",
  "UND_ERR_CONNECT_TIMEOUT",
]);

function isConnectStageError(err: unknown): boolean {
  for (let cur = err; cur && typeof cur === "object"; cur = (cur as { cause?: unknown }).cause) {
    const code = (cur as { code?: unknown }).code;
    if (typeof code === "string" && CONNECT_ERROR_CODES.has(code)) return true;
  }
  return false;
}

/** Case-insensitive presence check on a plain headers record. */
function hasHeader(headers: Record<string, string>, name: string): boolean {
  const lower = name.toLowerCase();
  return Object.keys(headers).some((k) => k.toLowerCase() === lower);
}

/** Case-insensitive set — removes any existing casing variant first. */
function setHeader(headers: Record<string, string>, name: string, value: string): void {
  const lower = name.toLowerCase();
  for (const k of Object.keys(headers)) {
    if (k.toLowerCase() === lower) delete headers[k];
  }
  headers[name] = value;
}
function deleteHeader(headers: Record<string, string>, name: string): void {
  const lower = name.toLowerCase();
  for (const k of Object.keys(headers)) {
    if (k.toLowerCase() === lower) delete headers[k];
  }
}

// Auth-bearing headers the proxy data plane consumes to identify the caller.
// The SDK's own credential is the SOLE authority on the data plane, so any
// caller-supplied copy of these is stripped from call()/ephemeral() headers
// before the SDK sets its own — otherwise an integrator forwarding untrusted
// end-user headers could inject an alternate proxy identity
// (x-knoxcall-agent-*) or, on the legacy-key path, a Bearer Authorization the
// proxy would honor over the SDK's own x-knoxcall-key.
const PROXY_AUTH_HEADERS = [
  "authorization",
  "dpop",
  "x-knoxcall-key",
  "x-knoxcall-agent-id",
  "x-knoxcall-agent-token",
];

// Markers the SDK owns on the data plane (PARITY §21.2). Not auth — the server
// treats them as informational — but a caller-supplied copy is stripped the
// same way, so an app cannot relabel its own calls as interceptor traffic
// through the SDK's header map. The interceptors set the marker through
// INTERCEPT_ORIGIN below, never through `headers`.
const SDK_MARKER_HEADERS = ["x-knoxcall-origin"];

/**
 * Internal seam for the route-aware interceptors (resources/wrap.ts): a
 * symbol-keyed `call()` option that makes the request carry
 * `x-knoxcall-origin: sdk-intercept`, so the API Log can show which Route
 * calls the SDK rerouted from a third-party SDK and which were direct.
 * Symbol-keyed on purpose — it is not part of `CallOptions`' documented
 * surface and nothing in `headers` can set it. Not re-exported from index.ts.
 */
export const INTERCEPT_ORIGIN = Symbol("knoxcall.interceptOrigin");

export function defaultBaseUrl(sandbox = false): string {
  if (process.env.KNOXCALL_BASE_URL) return process.env.KNOXCALL_BASE_URL;
  return sandbox ? "https://sandbox.knoxcall.com" : "https://api.knoxcall.com";
}

/**
 * Derive the data-plane base URL (and its subdomain shape) from the tenant
 * and management base URL. The KNOXCALL_PROXY_BASE_URL env override always
 * wins. Used at construction and again when the `knoxcall login` credentials
 * file seeds tenant/baseUrl.
 */
// A tenant slug becomes a data-plane hostname (https://<slug>.knoxcall.com), so
// it must be a bare DNS label. A slug adopted from a token response, /v1/account,
// or the credentials file that isn't (e.g. "evil.com#") would otherwise
// misdirect the tenant's bearer token to an attacker-controlled host.
const TENANT_SLUG_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
function assertTenantSlug(tenant: string): string {
  if (!TENANT_SLUG_RE.test(tenant)) {
    throw new BootstrapError(
      `invalid tenant slug ${JSON.stringify(tenant)} — expected a DNS label; ` +
        "refusing to derive a data-plane host from it",
    );
  }
  return tenant;
}

/**
 * Where the data plane lives under a proxy base (PARITY §5).
 *
 * On a KnoxCall CLOUD tenant host the proxy is served ONLY under `/api`
 * (`https://{slug}.knoxcall.com/api/<upstream path>`: server.ts strips the
 * prefix, and every other path on that host is the dashboard). `call()`
 * therefore places the upstream path under `/api` whenever the base names
 * such a host and carries no path of its own — the derived plain/sandbox
 * shapes and an explicit override alike, any port. Every other base is used
 * verbatim: self-hosted mounts the proxy at `/`, and a base that already
 * carries a path IS the entry point (the agent bundle spells the same base
 * as `…knoxcall.com/api`). Until 2026-09-25 nothing added the prefix, so the
 * documented `path: "/users"` answered the dashboard HTML on every tenant
 * host; the live smokes hid it by hard-coding `path: "/api/get"`.
 */
const NON_TENANT_LABELS = new Set(["api", "sandbox", "api-staging", "sandbox-staging", "www", "staging", "admin"]);
const CLOUD_TENANT_HOST_RE = /^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\.knoxcall\.com$/;

export function dataPlanePathPrefix(proxyBaseUrl: string): "" | "/api" {
  let url: URL;
  try {
    url = new URL(proxyBaseUrl);
  } catch {
    return "";
  }
  if (url.pathname !== "" && url.pathname !== "/") return "";
  const m = CLOUD_TENANT_HOST_RE.exec(url.hostname.toLowerCase());
  if (!m || NON_TENANT_LABELS.has(m[1])) return "";
  return "/api";
}

function deriveProxyBaseUrl(
  tenant: string | undefined,
  baseUrl: string,
): { proxy?: string; shape?: "plain" | "sandbox" } {
  const env = process.env.KNOXCALL_PROXY_BASE_URL;
  if (env) return { proxy: env.replace(/\/+$/, "") };
  if (baseUrl.includes("sandbox.knoxcall.com") || baseUrl.includes("sandbox-staging.knoxcall.com")) {
    return { proxy: tenant ? `https://sandbox-${assertTenantSlug(tenant)}.knoxcall.com` : undefined, shape: "sandbox" };
  }
  if (baseUrl.includes("api.knoxcall.com") || baseUrl.includes("api-staging.knoxcall.com")) {
    return { proxy: tenant ? `https://${assertTenantSlug(tenant)}.knoxcall.com` : undefined, shape: "plain" };
  }
  return { proxy: baseUrl }; // self-hosted: proxy runs on the same host, no tenant needed
}

/**
 * Fold the flat constructor options into a Bootstrap, enforcing mutual
 * exclusion. Returns undefined when nothing explicit was passed, preserving
 * the lazy env/platform auto-detection path.
 */
/**
 * Stable token-cache key component for clients constructed without a tenant.
 * Uses the credential's identity so shared stores still deduplicate; falls
 * back to a per-instance nonce for lazy auto-detect. FNV-1a suffices — this
 * is a cache key, not a security boundary (and node:crypto would break the
 * browser entrypoint).
 */
function credentialIdentity(bootstrap: Bootstrap | undefined): string {
  if (!bootstrap) return `anon:${ulid()}`;
  if (bootstrap.type === "client_credentials") return `cid:${bootstrap.clientId}`;
  if (bootstrap.type === "stored_credentials") {
    return `file:${resolveCredentialsPath(bootstrap.path)}:${resolveProfile(bootstrap.profile)}`;
  }
  if (bootstrap.type === "access_token") {
    let hash = 0x811c9dc5;
    for (let i = 0; i < bootstrap.accessToken.length; i++) {
      hash ^= bootstrap.accessToken.charCodeAt(i);
      hash = Math.imul(hash, 0x01000193) >>> 0;
    }
    return `tok:${hash.toString(16)}`;
  }
  return `anon:${ulid()}`;
}

function resolveFlatCredentials(opts: KnoxCallOptions): Bootstrap | undefined {
  const flat = (
    [
      ["clientId", opts.clientId],
      ["clientSecret", opts.clientSecret],
      ["accessToken", opts.accessToken],
      ["apiKey", opts.apiKey],
    ] as const
  )
    .filter(([, v]) => v !== undefined)
    .map(([n]) => n);
  if (opts.bootstrap !== undefined && flat.length > 0) {
    throw new BootstrapError(`bootstrap cannot be combined with ${flat.join(", ")}`);
  }
  if (opts.accessToken !== undefined && opts.apiKey !== undefined) {
    throw new BootstrapError(
      "pass either accessToken or apiKey, not both (they are two spellings of the same credential)",
    );
  }
  const token = opts.accessToken ?? opts.apiKey;
  if (token !== undefined && (opts.clientId !== undefined || opts.clientSecret !== undefined)) {
    throw new BootstrapError("a token credential cannot be combined with clientId/clientSecret");
  }
  if ((opts.clientId === undefined) !== (opts.clientSecret === undefined)) {
    throw new BootstrapError("clientId and clientSecret must be provided together");
  }

  if (opts.bootstrap !== undefined) return opts.bootstrap;
  if (token !== undefined) return new AccessToken({ accessToken: token });
  if (opts.clientId !== undefined && opts.clientSecret !== undefined) {
    return new ClientCredentials({ clientId: opts.clientId, clientSecret: opts.clientSecret });
  }
  return undefined;
}

/** Per-call options for data-plane requests through a route — see {@link APIClient.call}. */
export interface CallOptions {
  method?: string;
  path?: string;
  body?: unknown;
  headers?: Record<string, string>;
  environment?: string;
  query?: Record<string, string | number | undefined>;
  timeout?: number;
  signal?: AbortSignal;
}

/** `CallOptions` plus the interceptors' internal origin marker (see INTERCEPT_ORIGIN). */
export interface InternalCallOptions extends CallOptions {
  [INTERCEPT_ORIGIN]?: true;
}

/** Defaults bound once by {@link APIClient.route} and applied to every call on the handle. */
export interface BoundRouteDefaults {
  environment?: string;
  headers?: Record<string, string>;
  timeout?: number;
}

export class APIClient {
  tenant?: string; // mutable: adopted from the token response when not configured
  readonly environment?: string;
  /** Resolved Test-vs-Live mode. Read by the wrap transport's both-must-agree check. */
  readonly sandbox: boolean;
  baseUrl: string; // mutable: seeded from the `knoxcall login` credentials file when not explicit
  proxyBaseUrl?: string; // resolved lazily when the tenant must be discovered
  readonly apiVersion: string;
  readonly userAgent: string;
  readonly scope: string[];
  readonly #fetch: typeof fetch;
  readonly #store: TokenStore;
  readonly #cacheKey: string;
  readonly #retry: Required<NonNullable<KnoxCallOptions["retry"]>>;
  readonly #timeoutMs: number;
  readonly #dpopMode: "auto" | "always" | "never";
  readonly #telemetry?: TelemetryHooks;
  readonly #telemetryBuffer = new TelemetryBuffer();
  readonly #jsonReplacer?: (key: string, value: unknown) => unknown;
  #bootstrap?: Bootstrap;
  #dpop?: DpopKeyPair;
  #proxyShape?: "plain" | "sandbox"; // subdomain shape to derive once the tenant is known
  #proxyDiscovery?: Promise<string>; // single-flight for concurrent first calls
  // Explicit tenant/base_url (constructor, env, or sandbox: true) always beat
  // values seeded from the `knoxcall login` credentials file.
  readonly #baseUrlExplicit: boolean;
  readonly #proxyExplicit: boolean;

  constructor(opts: KnoxCallOptions = {}) {
    // Tenant is optional: when absent it is discovered from the first token
    // response (or /v1/account for pre-acquired tokens). Only the data-plane
    // hostname needs it client-side; management calls resolve the tenant
    // server-side from the credential.
    const tenant = opts.tenant ?? process.env.KNOXCALL_TENANT ?? undefined;
    const bootstrap = resolveFlatCredentials(opts);
    // TypeScript narrows this, but plain-JS callers can pass anything.
    if (opts.dpop !== undefined && !["auto", "always", "never"].includes(opts.dpop)) {
      throw new KnoxCallError(`dpop must be "auto", "always", or "never" (got ${JSON.stringify(opts.dpop)})`);
    }
    this.tenant = tenant;
    this.environment = opts.environment ?? process.env.KNOXCALL_ENVIRONMENT;
    const sandbox = opts.sandbox === true;
    this.sandbox = sandbox;
    this.baseUrl = (opts.baseUrl ?? defaultBaseUrl(sandbox)).replace(/\/+$/, "");
    this.#baseUrlExplicit =
      opts.baseUrl !== undefined || Boolean(process.env.KNOXCALL_BASE_URL) || sandbox;
    this.#proxyExplicit = opts.proxyBaseUrl !== undefined;
    if (!process.env.KNOXCALL_PROXY_BASE_URL && opts.proxyBaseUrl) {
      this.proxyBaseUrl = opts.proxyBaseUrl.replace(/\/+$/, "");
    } else {
      const derived = deriveProxyBaseUrl(tenant, this.baseUrl);
      this.proxyBaseUrl = derived.proxy;
      this.#proxyShape = derived.shape;
    }
    if (bootstrap?.type === "stored_credentials") this.#seedFromStoredCredentials(bootstrap);
    // Plaintext http:// to a non-loopback host sends credentials and tokens in
    // the clear — warn (don't block: http://localhost is the normal dev case).
    if (isInsecureRemoteUrl(this.baseUrl)) {
      warnOnce(
        "KNOXCALL_INSECURE_BASE_URL",
        `KnoxCall base URL ${this.baseUrl} uses plaintext http:// to a non-loopback host — ` +
          `credentials and access tokens will be sent unencrypted. Use https:// (plain http:// is only safe for localhost).`,
      );
    }
    if (isInsecureRemoteUrl(this.proxyBaseUrl)) {
      warnOnce(
        "KNOXCALL_INSECURE_PROXY_URL",
        `KnoxCall proxy base URL ${this.proxyBaseUrl} uses plaintext http:// to a non-loopback host — ` +
          `proxied requests and the SDK credential will be sent unencrypted. Use https:// (plain http:// is only safe for localhost).`,
      );
    }
    this.apiVersion = opts.apiVersion ?? DEFAULT_API_VERSION;
    this.userAgent = opts.userAgent ?? `knoxcall-sdk-node/${SDK_VERSION}`;
    this.scope = opts.scope ?? [];
    this.#fetch = opts.fetchImpl ?? globalThis.fetch;
    this.#store = opts.tokenStore ?? new MemoryTokenStore();
    this.#cacheKey = `${this.tenant ?? credentialIdentity(bootstrap)}:${this.scope.sort().join(" ")}`;
    this.#retry = {
      maxAttempts: opts.retry?.maxAttempts ?? 3,
      baseDelayMs: opts.retry?.baseDelayMs ?? 100,
      maxDelayMs: opts.retry?.maxDelayMs ?? 5000,
    };
    this.#timeoutMs = opts.timeout?.total ?? 30000;
    this.#dpopMode = opts.dpop ?? "auto";
    this.#telemetry = opts.telemetry;
    this.#jsonReplacer = opts.jsonReplacer;
    this.#bootstrap = bootstrap;
    if (this.#dpopMode === "always") {
      this.#dpop = DpopKeyPair.generate();
    }
  }

  /** Public: explicitly trigger token acquisition. Optional — first API call does this anyway. */
  async authenticate(): Promise<void> {
    await this.#getOrRefreshToken();
  }

  /** Public: revoke our cached token + clear bootstrap. Subsequent calls will re-detect. */
  async signOut(): Promise<void> {
    await this.#store.delete(this.#cacheKey);
  }

  async #resolveBootstrap(): Promise<Bootstrap> {
    if (this.#bootstrap) return this.#bootstrap;
    const detected = await autoDetectBootstrap();
    if (detected.type === "stored_credentials") this.#seedFromStoredCredentials(detected);
    this.#bootstrap = detected;
    return this.#bootstrap;
  }

  /**
   * Seed tenant/baseUrl from the `knoxcall login` credentials file when the
   * caller did not set them explicitly (explicit constructor/env values
   * always win). Malformed/missing file → no-op (the chain already vetted
   * presence).
   */
  #seedFromStoredCredentials(stored: { path?: string; profile?: string }): void {
    const record = readProfile(resolveCredentialsPath(stored.path), resolveProfile(stored.profile));
    if (!record) return;
    if (!this.tenant && typeof record.tenant === "string" && record.tenant) {
      this.tenant = record.tenant;
    }
    if (!this.#baseUrlExplicit && typeof record.base_url === "string" && record.base_url) {
      this.baseUrl = record.base_url.replace(/\/+$/, "");
    }
    if (!this.#proxyExplicit) {
      // Re-derive the data plane from the (possibly updated) tenant and
      // baseUrl; the KNOXCALL_PROXY_BASE_URL env override still wins inside
      // deriveProxyBaseUrl.
      const derived = deriveProxyBaseUrl(this.tenant, this.baseUrl);
      this.proxyBaseUrl = derived.proxy;
      this.#proxyShape = derived.shape;
    }
  }

  static #refreshAhead(cached: CachedToken): number {
    // For short-lived tokens a fixed 5-minute window would mean "always
    // expired", forcing a token fetch per request; never use more than
    // half the token's lifetime as the refresh-ahead window.
    if (cached.lifetime) return Math.min(REFRESH_AHEAD_MS, cached.lifetime / 2);
    return REFRESH_AHEAD_MS;
  }

  async #fetchToken(bootstrap: Bootstrap): Promise<CachedToken> {
    try {
      return await fetchToken({
        tokenEndpoint: `${this.baseUrl}/oauth/token`,
        bootstrap,
        scope: this.scope,
        dpop: this.#dpop,
        fetchImpl: this.#fetch,
      });
    } catch (e) {
      // In "auto" mode, upgrade to DPoP when the OAuth client record
      // requires it instead of failing every token request.
      if (
        this.#dpopMode === "auto" &&
        !this.#dpop &&
        e instanceof KnoxCallError &&
        e.code === "invalid_dpop_proof"
      ) {
        this.#dpop = DpopKeyPair.generate();
        return await fetchToken({
          tokenEndpoint: `${this.baseUrl}/oauth/token`,
          bootstrap,
          scope: this.scope,
          dpop: this.#dpop,
          fetchImpl: this.#fetch,
        });
      }
      throw e;
    }
  }

  /** Learn the tenant from a token response when constructed without one. */
  #adoptTenant(cached: CachedToken): CachedToken {
    if (!this.tenant && cached.tenant) this.tenant = cached.tenant;
    return cached;
  }

  /**
   * Resolve the data-plane base URL, discovering the tenant if needed.
   *
   * Tenant discovery: the token response carries the slug; pre-acquired
   * tokens (and older servers) fall back to one GET /v1/account. Concurrent
   * first calls share a single discovery via #proxyDiscovery.
   */
  async #ensureProxyBaseUrl(): Promise<string> {
    if (this.proxyBaseUrl) return this.proxyBaseUrl;
    this.#proxyDiscovery ??= this.#discoverProxyBaseUrl().finally(() => {
      this.#proxyDiscovery = undefined;
    });
    return this.#proxyDiscovery;
  }

  async #discoverProxyBaseUrl(): Promise<string> {
    if (!this.tenant) await this.#getOrRefreshToken(); // may adopt from the response
    if (!this.tenant) {
      const account = await this.request<{ data?: { slug?: string } }>({
        method: "GET",
        path: "/v1/account",
      });
      const slug = account?.data?.slug;
      if (!slug) {
        throw new BootstrapError(
          "could not discover the tenant from the credential — pass tenant " +
            "or set the KNOXCALL_TENANT environment variable",
        );
      }
      this.tenant = slug;
    }
    this.proxyBaseUrl =
      this.#proxyShape === "sandbox"
        ? `https://sandbox-${assertTenantSlug(this.tenant)}.knoxcall.com`
        : `https://${assertTenantSlug(this.tenant)}.knoxcall.com`;
    return this.proxyBaseUrl;
  }

  async #getOrRefreshToken(): Promise<CachedToken> {
    const cached = await this.#store.get(this.#cacheKey);
    if (cached && cached.expiresAt - Date.now() > APIClient.#refreshAhead(cached)) {
      return this.#adoptTenant(cached);
    }
    try {
      return await this.#store.withLock(this.#cacheKey, async () => {
        const again = await this.#store.get(this.#cacheKey);
        if (again && again.expiresAt - Date.now() > APIClient.#refreshAhead(again)) return again;

        const bootstrap = await this.#resolveBootstrap();

        // Try refresh-token grant first if we have one
        if (again?.refreshToken && bootstrap.type === "client_credentials") {
          try {
            const refreshed = await refreshTokenGrant({
              tokenEndpoint: `${this.baseUrl}/oauth/token`,
              clientId: bootstrap.clientId,
              clientSecret: bootstrap.clientSecret,
              refreshToken: again.refreshToken,
              dpop: this.#dpop,
              fetchImpl: this.#fetch,
            });
            await this.#store.set(this.#cacheKey, refreshed);
            return refreshed;
          } catch {
            // Fall through to full bootstrap
          }
        }

        const fresh = await this.#fetchToken(bootstrap);
        await this.#store.set(this.#cacheKey, fresh);
        return fresh;
      }).then((t) => this.#adoptTenant(t));
    } catch (e) {
      // Token endpoint unreachable or erroring during the refresh-ahead
      // window: a cached token that hasn't actually expired is still
      // good — use it rather than failing the caller's request.
      const stale = await this.#store.get(this.#cacheKey);
      if (stale && stale.expiresAt - Date.now() > STALE_TOKEN_MIN_REMAINING_MS) return this.#adoptTenant(stale);
      throw e;
    }
  }

  /**
   * Attach Authorization (and a fresh DPoP proof when bound). SDK auth always
   * wins over caller headers.
   *
   * ``legacyKeyAsHeader`` is set on data-plane call() requests: the proxy's
   * OAuth detection matches the ``kc_`` token prefix only, so a legacy
   * ``tk_``/``AKE`` credential must travel as ``x-knoxcall-key`` (Bearer
   * would fall through to the legacy path and 401).
   */
  #authHeaders(
    headers: Record<string, string>,
    cached: CachedToken,
    method: string,
    url: string,
    legacyKeyAsHeader = false,
  ): void {
    const token = cached.accessToken.expose();
    if (legacyKeyAsHeader && cached.tokenType === "Bearer" && !token.startsWith("kc_")) {
      setHeader(headers, "x-knoxcall-key", token);
      return;
    }
    setHeader(headers, "Authorization", `${cached.tokenType} ${token}`);
    if (cached.tokenType === "DPoP" && this.#dpop) {
      const proofUrl = url.split("#")[0].split("?")[0];
      setHeader(
        headers,
        "DPoP",
        this.#dpop.sign({
          method: method.toUpperCase(),
          url: proofUrl,
          accessToken: cached.accessToken.expose(),
        }),
      );
    }
  }

  /**
   * Serialize a request body, defaulting Content-Type to JSON when the
   * caller hasn't set one. Strings and Buffers pass through untouched
   * (pre-serialized payloads); anything else is JSON-encoded with the
   * client's ``jsonReplacer`` hook (Date already serializes via toJSON).
   */
  #encodeBody(
    body: unknown,
    headers: Record<string, string>,
    // The wrap/transparent path passes false so it never synthesizes a
    // Content-Type the wrapped SDK did not set — the forward must be byte- AND
    // header-verbatim. Every other caller keeps the JSON default.
    defaultJsonContentType = true,
  ): BodyInit | undefined {
    if (body === undefined || body === null) return undefined;
    // Native BodyInit values (already-encoded bytes, form bodies, streams) pass
    // through verbatim — never JSON-stringified, and they carry their own
    // Content-Type semantics, so we don't force application/json on them.
    if (
      typeof body === "string" ||
      body instanceof Uint8Array ||
      body instanceof ArrayBuffer ||
      (typeof DataView !== "undefined" && body instanceof DataView) ||
      (typeof Blob !== "undefined" && body instanceof Blob) ||
      (typeof FormData !== "undefined" && body instanceof FormData) ||
      (typeof URLSearchParams !== "undefined" && body instanceof URLSearchParams) ||
      (typeof ReadableStream !== "undefined" && body instanceof ReadableStream)
    ) {
      // Only a plain string gets the optional JSON default (it's the only one of
      // these that is ambiguous); the rest set their own Content-Type.
      if (typeof body === "string" && defaultJsonContentType && !hasHeader(headers, "Content-Type")) {
        headers["Content-Type"] = "application/json";
      }
      return body as unknown as BodyInit;
    }
    // Plain object / array → JSON.
    if (defaultJsonContentType && !hasHeader(headers, "Content-Type")) {
      headers["Content-Type"] = "application/json";
    }
    return JSON.stringify(body, this.#jsonReplacer);
  }

  async request<T>(opts: ManagementRequestOptions & { allowNotModified: true }): Promise<T | typeof NOT_MODIFIED>;
  async request<T>(opts: ManagementRequestOptions): Promise<T>;
  async request<T>(opts: ManagementRequestOptions): Promise<T | typeof NOT_MODIFIED> {
    const isMutating = !["GET", "HEAD"].includes(opts.method.toUpperCase());
    const idempotencyKey = opts.idempotencyKey ?? (isMutating ? ulid() : undefined);

    let attempt = 0;
    let lastError: unknown;
    let reauthDone = false;

    while (attempt < this.#retry.maxAttempts) {
      attempt++;
      try {
        return await this.#attempt<T>({ ...opts, idempotencyKey, attempt });
      } catch (err) {
        lastError = err;
        // One transparent re-auth: #attempt purged the cached token on 401,
        // so the immediate retry runs with freshly minted creds.
        if (
          err instanceof KnoxCallError &&
          err.status === 401 &&
          !reauthDone &&
          attempt < this.#retry.maxAttempts
        ) {
          reauthDone = true;
          continue;
        }
        if (!this.#shouldRetry(err, attempt)) throw err;
        const delayMs = this.#retryDelay(err, attempt);
        this.#telemetry?.onRetry?.({
          method: opts.method,
          url: `${this.baseUrl}${opts.path}`,
          attempt,
          idempotencyKey,
          tenantId: this.tenant,
          status: err instanceof KnoxCallError ? err.status : undefined,
          delayMs,
          reason: err instanceof Error ? err.message : String(err),
        });
        await this.#sleep(delayMs);
      }
    }
    throw lastError;
  }

  #shouldRetry(err: unknown, attempt: number): boolean {
    if (attempt >= this.#retry.maxAttempts) return false;
    if (err instanceof APIUserAbortError) return false;
    if (err instanceof APIConnectionError) return true;
    if (err instanceof KnoxCallError && err.status && RETRYABLE_STATUSES.has(err.status)) return true;
    return false;
  }

  #retryDelay(err: unknown, attempt: number): number {
    // A 429's Retry-After, and a 503's (`dependency_unavailable` — the server
    // says how long the dependency needs). Both capped: beyond the cap the
    // caller's own scheduling beats a blocked worker.
    if ((err instanceof RateLimitError || err instanceof ServerError) && err.retryAfter) {
      return Math.min(err.retryAfter * 1000, RETRY_AFTER_CAP_MS);
    }
    return this.#backoffDelay(attempt);
  }

  #backoffDelay(attempt: number): number {
    // Half-jitter: random within [exp/2, exp] so a retry never fires
    // immediately but herds still spread out.
    const exp = this.#retry.baseDelayMs * Math.pow(2, attempt - 1);
    return Math.min(this.#retry.maxDelayMs, exp * (0.5 + Math.random() / 2));
  }

  #sleep(ms: number): Promise<void> {
    return new Promise((r) => setTimeout(r, ms));
  }

  async #attempt<T>(opts: ManagementRequestOptions & { attempt: number }): Promise<T | typeof NOT_MODIFIED> {
    const cached = await this.#getOrRefreshToken();

    let url = `${this.baseUrl}${opts.path.startsWith("/") ? "" : "/"}${opts.path}`;
    if (opts.query) {
      const params = new URLSearchParams();
      for (const [k, v] of Object.entries(opts.query)) {
        if (v !== undefined) params.set(k, String(v));
      }
      const qs = params.toString();
      if (qs) url += `?${qs}`;
    }

    const headers: Record<string, string> = { ...opts.headers };
    if (!hasHeader(headers, "Accept")) headers.Accept = "application/json";
    if (!hasHeader(headers, "User-Agent")) headers["User-Agent"] = this.userAgent;
    if (!hasHeader(headers, "KnoxCall-Version")) headers["KnoxCall-Version"] = this.apiVersion;

    this.#authHeaders(headers, cached, opts.method, url);

    if (opts.idempotencyKey) {
      headers["X-Idempotency-Key"] = opts.idempotencyKey;
    }

    // Stripe-style next-request telemetry — ride on this request's headers.
    const drained = this.#telemetryBuffer.drain();
    if (drained) headers["X-KnoxCall-Telemetry"] = drained;

    this.#telemetry?.onRequest?.({
      method: opts.method,
      url,
      attempt: opts.attempt,
      idempotencyKey: opts.idempotencyKey,
      tenantId: this.tenant,
    });

    const startedAt = Date.now();

    const body = this.#encodeBody(opts.body, headers);

    // Combine user signal + our timeout.
    const ourController = new AbortController();
    const timer = setTimeout(() => ourController.abort(), this.#timeoutMs);
    const combinedSignal = opts.signal
      ? anySignal(opts.signal, ourController.signal)
      : ourController.signal;

    let res: Response;
    try {
      res = await this.#fetch(url, { method: opts.method, headers, body, signal: combinedSignal });
    } catch (e) {
      if (opts.signal?.aborted) {
        throw new APIUserAbortError();
      }
      if ((e as { name?: string })?.name === "AbortError") {
        throw new APIConnectionTimeoutError();
      }
      throw new APIConnectionError(`network error: ${(e as Error)?.message ?? String(e)}`);
    } finally {
      clearTimeout(timer);
    }

    const respHeaders: Record<string, string> = {};
    res.headers.forEach((v, k) => {
      respHeaders[k.toLowerCase()] = v;
    });

    const text = await res.text();
    let parsed: unknown = null;
    if (text) {
      try {
        parsed = JSON.parse(text);
      } catch {
        parsed = text;
      }
    }

    const durationMs = Date.now() - startedAt;
    this.#telemetryBuffer.record({
      method: opts.method,
      path: opts.path,
      status: res.status,
      durationMs,
    });
    this.#telemetry?.onResponse?.({
      method: opts.method,
      url,
      attempt: opts.attempt,
      idempotencyKey: opts.idempotencyKey,
      tenantId: this.tenant,
      status: res.status,
      durationMs,
      requestId: respHeaders["x-request-id"],
    });

    if (res.status === 401) {
      // Token rejected — refresh once and let outer retry loop handle it.
      await this.#store.delete(this.#cacheKey);
      throw errorFromResponse(res.status, parsed, respHeaders);
    }
    if (res.status >= 400) {
      throw errorFromResponse(res.status, parsed, respHeaders);
    }
    if (res.status === 304 && opts.allowNotModified) {
      // A conditional GET the server answered "unchanged": success, no body.
      return NOT_MODIFIED;
    }
    return parsed as T;
  }

  #proxyTransportRetryable(err: unknown, method: string, attempt: number): boolean {
    if (attempt >= this.#retry.maxAttempts) return false;
    // The connection was never established, so the request was never
    // sent — always safe to retry, even for mutating methods.
    if (isConnectStageError(err)) return true;
    // Anything later (local timeout, idle-keepalive reset, …) may have
    // reached the upstream; only replay methods that are safe to repeat.
    return method === "GET" || method === "HEAD";
  }

  /**
   * Shared data-plane sender for call()/ephemeral().
   *
   * Proxied responses are returned raw (the upstream's status belongs to
   * the caller), but transport failures are mapped to KnoxCallError
   * subclasses and retried when safe, and a 401 triggers one token
   * purge + re-mint so a revoked token can't wedge a long-lived client.
   */
  async #proxySend(opts: {
    method: string;
    url: string;
    headers?: Record<string, string>;
    sdkHeaders: Record<string, string>;
    query?: Record<string, string | number | undefined>;
    body?: unknown;
    timeout?: number;
    signal?: AbortSignal;
    legacyKeyAsHeader?: boolean;
    /** false on the wrap/transparent path so no Content-Type is synthesized. */
    defaultJsonContentType?: boolean;
  }): Promise<Response> {
    const method = opts.method.toUpperCase();
    let url = opts.url;
    if (opts.query) {
      const params = new URLSearchParams();
      for (const [k, v] of Object.entries(opts.query)) {
        if (v !== undefined) params.set(k, String(v));
      }
      const qs = params.toString();
      if (qs) url += `?${qs}`;
    }

    let reauthDone = false;
    let attempt = 0;
    while (true) {
      attempt++;
      const cached = await this.#getOrRefreshToken();

      const headers: Record<string, string> = { ...opts.headers };
      // The SDK credential is the sole data-plane auth authority: drop any
      // caller-supplied proxy-auth headers before we set our own, so SDK auth
      // always wins (agent identity / legacy-key path included).
      for (const h of PROXY_AUTH_HEADERS) deleteHeader(headers, h);
      for (const h of SDK_MARKER_HEADERS) deleteHeader(headers, h);
      if (!hasHeader(headers, "User-Agent")) headers["User-Agent"] = this.userAgent;
      // Explicit arguments (route, environment, …) always win over the caller's headers.
      for (const [k, v] of Object.entries(opts.sdkHeaders)) setHeader(headers, k, v);
      this.#authHeaders(headers, cached, method, url, opts.legacyKeyAsHeader === true);

      const body = this.#encodeBody(opts.body, headers, opts.defaultJsonContentType);

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), opts.timeout ?? this.#timeoutMs);
      const signal = opts.signal ? anySignal(opts.signal, controller.signal) : controller.signal;

      let res: Response;
      try {
        res = await this.#fetch(url, { method, headers, body, signal });
      } catch (e) {
        if (opts.signal?.aborted) throw new APIUserAbortError();
        if (this.#proxyTransportRetryable(e, method, attempt)) {
          await this.#sleep(this.#backoffDelay(attempt));
          continue;
        }
        if ((e as { name?: string })?.name === "AbortError") throw new APIConnectionTimeoutError();
        throw new APIConnectionError(`network error: ${(e as Error)?.message ?? String(e)}`);
      } finally {
        clearTimeout(timer);
      }

      // A 401 triggers one token purge + re-mint — but ONLY when it is
      // KnoxCall-originated. On the wrap/ephemeral path a 401 from the UPSTREAM
      // provider (e.g. Stripe auth failure) is a genuine forward, marked by
      // X-Knox-Destination-Status; purging the KnoxCall token for it would be
      // wrong (and would replay the request). The server sets that header only
      // on a real upstream forward (see ephemeral-proxy.ts).
      // An upstream that answered is not a KnoxCall refusal, whichever header
      // names it: the ephemeral proxy says `X-Knox-Destination-Status`, the
      // route data plane's response block says `X-Knox-Upstream-Status`.
      const gatewayOriginated =
        !res.headers.get("x-knox-destination-status") && !res.headers.get("x-knox-upstream-status");
      if (res.status === 401 && !reauthDone && gatewayOriginated) {
        await this.#store.delete(this.#cacheKey);
        reauthDone = true;
        continue;
      }
      return res;
    }
  }

  /**
   * Make a proxied request through a KnoxCall route.
   *
   * Pass the route **UUID** (preferred) or name in ``route``.
   * Returns the raw ``Response`` so callers have full access to status, headers, and body.
   *
   * Connection-level failures throw ``APIConnectionError`` /
   * ``APIConnectionTimeoutError``; safe-to-repeat failures are retried
   * with backoff, and a rejected token is re-minted once automatically.
   * ``timeout`` overrides the client-level total timeout (ms) for this call.
   * ``path`` is the UPSTREAM path: on a cloud tenant host the SDK places it
   * under the data plane's ``/api`` entry point itself (PARITY §5).
   */
  async call(route: string, opts?: CallOptions): Promise<Response> {
    const sdkHeaders: Record<string, string> = { "x-knoxcall-route": route };
    const environment = opts?.environment ?? this.environment;
    if (environment) sdkHeaders["x-knoxcall-environment"] = environment;
    // The interceptors' reroute marker (PARITY §21.2). A direct call() sends
    // nothing — absence IS "direct" on the server.
    if ((opts as InternalCallOptions | undefined)?.[INTERCEPT_ORIGIN] === true) {
      sdkHeaders["x-knoxcall-origin"] = "sdk-intercept";
    }

    const proxyBase = await this.#ensureProxyBaseUrl();
    const path = opts?.path ?? "/";
    return this.#proxySend({
      method: opts?.method ?? "GET",
      // `path` is the UPSTREAM path; the entry point is the SDK's to add (PARITY §5).
      url: `${proxyBase}${dataPlanePathPrefix(proxyBase)}${path.startsWith("/") ? "" : "/"}${path}`,
      headers: opts?.headers,
      sdkHeaders,
      query: opts?.query,
      body: opts?.body,
      timeout: opts?.timeout,
      signal: opts?.signal,
      legacyKeyAsHeader: true,
    });
  }

  /**
   * Bind a route (and optional call defaults) once, then make plain
   * HTTP-verb calls against it:
   *
   *   const printnode = client.route("3f1e2c9a-...", { environment: "production" });
   *   const computers = await (await printnode.get("/computers")).json();
   *   await printnode.post("/printjobs", { body: payload });
   */
  route(route: string, defaults?: BoundRouteDefaults): BoundRoute {
    return new BoundRoute(this, route, defaults);
  }

  /**
   * Make a one-shot proxied request via the Ephemeral Proxy.
   * Resolves ``{{ token: "..." }}`` expressions on the wire before sending to upstream.
   *
   * ``timeoutMs`` bounds the server-side upstream call; ``timeout``
   * overrides the local total timeout (ms) for this request (set it higher
   * than ``timeoutMs`` or the local timeout fires first).
   */
  async ephemeral(
    upstreamUrl: string,
    opts?: {
      method?: string;
      body?: unknown;
      headers?: Record<string, string>;
      encrypted?: string;
      timeoutMs?: number;
      timeout?: number;
      signal?: AbortSignal;
      /**
       * `"transparent"` forwards the request bytes and Content-Type verbatim
       * and disables `{{ token }}` templating server-side — the mode a wrapped
       * third-party SDK uses so its own serialization (e.g. Stripe's
       * form-urlencoded) survives. Omit for the default JSON + template path.
       */
      mode?: "transparent";
      /**
       * Value mapped to the UPSTREAM Authorization header server-side (the
       * provider's own credential). It never reaches the upstream as a raw
       * header and is never logged or stored. The SDK's own KnoxCall auth is
       * unaffected — this is the third-party credential, delivered out-of-band.
       * Mutually exclusive with `upstreamAuthSecret`.
       */
      upstreamAuthorization?: string;
      /**
       * NAME of an escrowed wrap credential (see `wrap.escrow()`). The server
       * resolves + decrypts it and injects it as the upstream Authorization
       * header, but only for a host in the credential's `allowed_hosts`. The
       * raw key never travels. Mutually exclusive with `upstreamAuthorization`.
       */
      upstreamAuthSecret?: string;
      /** Auth scheme for `upstreamAuthSecret` (default `Bearer`; `none` = raw value). */
      upstreamAuthScheme?: string;
    },
  ): Promise<Response> {
    const sdkHeaders: Record<string, string> = { "X-Knox-Proxy-URL": upstreamUrl };
    if (opts?.encrypted) sdkHeaders["X-Knox-Encrypted"] = opts.encrypted;
    if (opts?.timeoutMs !== undefined) sdkHeaders["X-Knox-Timeout-Ms"] = String(opts.timeoutMs);
    if (opts?.mode === "transparent") sdkHeaders["X-Knox-Proxy-Mode"] = "transparent";
    if (opts?.upstreamAuthorization !== undefined) {
      sdkHeaders["X-Knox-Upstream-Authorization"] = opts.upstreamAuthorization;
    }
    if (opts?.upstreamAuthSecret !== undefined) {
      sdkHeaders["X-Knox-Upstream-Auth-Secret"] = opts.upstreamAuthSecret;
    }
    if (opts?.upstreamAuthScheme !== undefined) {
      sdkHeaders["X-Knox-Upstream-Auth-Scheme"] = opts.upstreamAuthScheme;
    }

    return this.#proxySend({
      method: opts?.method ?? "GET",
      url: `${this.baseUrl}/v1/proxy`,
      headers: opts?.headers,
      sdkHeaders,
      body: opts?.body,
      timeout: opts?.timeout,
      signal: opts?.signal,
      // Transparent mode forwards bytes + Content-Type verbatim; never let the
      // encoder synthesize application/json for a body the SDK left untyped.
      defaultJsonContentType: opts?.mode === "transparent" ? false : undefined,
    });
  }

  /** Verify an incoming KnoxCall webhook signature (HMAC-SHA256, constant-time). */
  verifySignature(input: {
    rawBody: string | Buffer;
    signature: string;
    secret: string;
    toleranceSeconds?: number;
    timestamp?: number;
  }): boolean {
    return verifyWebhookSignature(input);
  }
}

/**
 * A route with bound call defaults — see ``APIClient.route()``.
 *
 * Holds only the client reference, route id, and defaults (never a token or
 * any pipeline state), so retries and 401 re-mint behave exactly as on
 * ``call()``. Per-call values win over bound defaults; headers merge per-key
 * with per-call winning.
 */
export class BoundRoute {
  readonly #client: APIClient;
  readonly #route: string;
  readonly #environment?: string;
  readonly #headers: Record<string, string>;
  readonly #timeout?: number;

  constructor(client: APIClient, route: string, defaults?: BoundRouteDefaults) {
    this.#client = client;
    this.#route = route;
    this.#environment = defaults?.environment;
    this.#headers = { ...defaults?.headers };
    this.#timeout = defaults?.timeout;
  }

  request(method: string, path = "/", opts?: Omit<CallOptions, "method" | "path">): Promise<Response> {
    const headers = { ...this.#headers };
    for (const [k, v] of Object.entries(opts?.headers ?? {})) setHeader(headers, k, v);
    return this.#client.call(this.#route, {
      ...opts,
      method,
      path,
      headers: Object.keys(headers).length > 0 ? headers : undefined,
      environment: opts?.environment ?? this.#environment,
      timeout: opts?.timeout ?? this.#timeout,
    });
  }

  get(path = "/", opts?: Omit<CallOptions, "method" | "path">): Promise<Response> {
    return this.request("GET", path, opts);
  }

  post(path = "/", opts?: Omit<CallOptions, "method" | "path">): Promise<Response> {
    return this.request("POST", path, opts);
  }

  put(path = "/", opts?: Omit<CallOptions, "method" | "path">): Promise<Response> {
    return this.request("PUT", path, opts);
  }

  patch(path = "/", opts?: Omit<CallOptions, "method" | "path">): Promise<Response> {
    return this.request("PATCH", path, opts);
  }

  delete(path = "/", opts?: Omit<CallOptions, "method" | "path">): Promise<Response> {
    return this.request("DELETE", path, opts);
  }
}

/** Compose multiple AbortSignals — first one to abort wins. */
function anySignal(...signals: AbortSignal[]): AbortSignal {
  const controller = new AbortController();
  for (const s of signals) {
    if (s.aborted) {
      controller.abort();
      return controller.signal;
    }
    s.addEventListener("abort", () => controller.abort(), { once: true });
  }
  return controller.signal;
}
