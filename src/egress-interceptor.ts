// EXPERIMENTAL — transparent egress interceptor (sdk-wrapping, layer-2).
//
// The most transparent way to route a wrapped SDK through KnoxCall: instead of
// handing each SDK a custom `fetch`/`baseURL`, patch the process's global `fetch`
// ONCE so outbound requests to named hosts are re-targeted through KnoxCall — no
// per-SDK wiring. This is the in-process, ABOVE-TLS interception point: the
// request is still plaintext here (so credential injection works) and KnoxCall
// re-originates its own clean TLS, which is why SigV4/host-signed requests
// survive (the reroute forwards them faithfully in transparent mode).
//
// ┌─ READ THIS ─────────────────────────────────────────────────────────────┐
// │ This is a CONVENIENCE layer, NOT a security boundary.                    │
// │  • It is process-GLOBAL: it patches globalThis.fetch AND node:http /     │
// │    node:https .request/.get, affecting every library in the process — it │
// │    cannot be scoped per-tenant the way a per-client `wrap.fetch()` can.   │
// │    Scope it by host-list (and optionally by AsyncLocalStorage context    │
// │    via `requireContext` + `routed()`).                                   │
// │  • Two egress stacks are covered by default (`stacks: ['fetch','http']`):│
// │    global `fetch`, and node's `http`/`https` .request/.get — the latter  │
// │    catches axios, node-fetch, cross-fetch, got and most non-fetch SDKs   │
// │    with NO added dependency. A captured `fetch`/`request` REFERENCE, or  │
// │    an SDK on its own undici `Dispatcher`, is still not reached — use      │
// │    `wrap.fetch()` / `wrap.gatewayUrl()` (or the OPTIONAL undici-dispatcher│
// │    stack, which stays zero-dep by dynamic-importing `undici`).           │
// │  • It is not a boundary against hostile in-process code, which can       │
// │    restore the originals and egress directly. For real custody use       │
// │    escrow (`wrap.escrow` / `wrap.gatewayUrl`) where the key never enters │
// │    the process.                                                          │
// │  • It composes badly with APM agents (dd-trace/OTel) that patch the same │
// │    globals — last patcher wins; install order matters.                   │
// └──────────────────────────────────────────────────────────────────────────┘

import { AsyncLocalStorage } from "node:async_hooks";
import { createRequire } from "node:module";
import { Readable, Writable } from "node:stream";
import { urlToHttpOptions } from "node:url";
import { parseFetchArgs } from "./wrap-transport.js";

type FetchFn = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

// Marks the async scopes in which `requireContext` interceptors are active.
const routedStore = new AsyncLocalStorage<true>();

/** Run `fn` in a "routed" scope so a `requireContext` interceptor reroutes the
 *  egress it (and its awaited descendants) performs. Marks the CALL SITE, not the
 *  SDK — no SDK cooperation needed. */
export function runRouted<T>(fn: () => T): T {
  return routedStore.run(true, fn);
}

/** Whether the current async context is inside `runRouted`. */
export function inRoutedContext(): boolean {
  return routedStore.getStore() === true;
}

// Cross-realm-stable marker so a double install is detectable even if two copies
// of this module are loaded.
const INSTALLED = Symbol.for("knoxcall.egressInterceptor.installed");

export interface EgressInterceptorTarget {
  fetch: FetchFn;
}

/**
 * A request a seam passed through UNTOUCHED — what the uncovered-egress
 * observer (PARITY §21.3) reads. Headers are computed on demand so a request
 * the observer discards on url/method alone costs nothing more.
 */
export interface PassThroughInfo {
  url: string;
  method: string;
  /** Lower-cased header names → values. */
  headers: () => Record<string, string>;
}

function notifyPassThrough(hook: (info: PassThroughInfo) => void, info: PassThroughInfo): void {
  try {
    hook(info);
  } catch {
    // best-effort: an observer must never reach the application's request.
  }
}

function methodOf(input: string | URL | Request, init?: RequestInit): string {
  const fromRequest = typeof input === "object" && input !== null && !(input instanceof URL) ? (input as Request).method : undefined;
  return String(init?.method ?? fromRequest ?? "GET").toUpperCase();
}

function fetchPassThroughInfo(input: string | URL | Request, init?: RequestInit): PassThroughInfo {
  return { url: urlOf(input), method: methodOf(input, init), headers: () => parseFetchArgs(input, init).headers };
}

function lowerKeys(h: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(h)) out[k.toLowerCase()] = v;
  return out;
}

export interface InstallEgressInterceptorArgs {
  /** Bare DNS hostnames whose outbound requests are rerouted through `reroute`. */
  hosts: string[];
  /** The rerouting transport — normally a `wrap.fetch(...)` closure. */
  reroute: FetchFn;
  /** Where to install (defaults to globalThis). Injected for tests. */
  target?: EgressInterceptorTarget;
  /** Only reroute inside `runRouted()` — off by default (host-list alone scopes). */
  requireContext?: boolean;
  /** Fires when a request is rerouted (observability). */
  onReroute?: (info: { host: string; url: string }) => void;
  /**
   * Dynamic host predicate, consulted in addition to `hosts` — the route-aware
   * form feeds the manifest's hosts through it, so a Route created after
   * install is intercepted without a re-install. `hosts` may be empty when
   * this is given.
   */
  matchHost?: (host: string) => boolean;
  /** Consulted per request; false passes the request through untouched (the kill switch). */
  enabled?: () => boolean;
  /**
   * Fires for every request this seam passes through UNTOUCHED whose URL
   * parsed — the uncovered-egress observer decides from here whether it
   * carries a credential worth noting (PARITY §21.3). Never for a request made
   * inside `runSuppressed()`. Errors are swallowed.
   */
  onPassThrough?: (info: PassThroughInfo) => void;
}

export interface EgressInterceptor {
  /** True until `uninstall()` runs. */
  readonly installed: boolean;
  /** Restore the previous fetch. Safe to call more than once; never clobbers a
   *  fetch that was patched ON TOP of this one (e.g. a later APM agent). */
  uninstall(): void;
}

function normalizeHost(h: string): string {
  return String(h).trim().toLowerCase().replace(/\.$/, "");
}

function urlOf(input: string | URL | Request): string {
  if (typeof input === "string") return input;
  if (input instanceof URL) return input.toString();
  return input.url;
}

/**
 * Install a global-fetch interceptor. Returns a handle to uninstall it. Throws
 * if there is no `fetch` to patch, if `hosts` is empty, or if a KnoxCall
 * interceptor is already installed on the target (install one at a time).
 */
export function installEgressInterceptor(args: InstallEgressInterceptorArgs): EgressInterceptor {
  const target = (args.target ?? (globalThis as unknown as EgressInterceptorTarget));
  const originalFetch = target.fetch;
  if (typeof originalFetch !== "function") {
    throw new TypeError(
      "installEgressInterceptor requires a global fetch (Node 18+) — none found on the target.",
    );
  }
  if ((originalFetch as unknown as Record<symbol, unknown>)[INSTALLED]) {
    throw new Error(
      "A KnoxCall egress interceptor is already installed; uninstall it before installing another.",
    );
  }
  if (!Array.isArray(args.hosts) || (args.hosts.length === 0 && typeof args.matchHost !== "function")) {
    throw new TypeError("installEgressInterceptor requires a non-empty `hosts` array of DNS hostnames (or a `matchHost` predicate).");
  }
  const hostSet = new Set(args.hosts.map(normalizeHost).filter((h) => h.length > 0));
  const matches = (host: string): boolean => hostSet.has(host) || (args.matchHost?.(host) ?? false);

  const patched: FetchFn = (input, init) => {
    // Anti-recursion: egress performed BY the reroute, or by the SDK's own
    // observation report, bypasses the seam (see runSuppressed).
    if (httpSuppress.getStore()) return originalFetch(input, init);
    let host = "";
    try {
      host = normalizeHost(new URL(urlOf(input)).hostname);
    } catch {
      /* unparseable input → not ours, pass through untouched */
    }
    const shouldReroute =
      host.length > 0 &&
      (args.enabled?.() ?? true) &&
      matches(host) &&
      (!args.requireContext || inRoutedContext());
    if (!shouldReroute) {
      // Observed AFTER the decision, BEFORE the direct send — and never on the
      // request's own path: the hook cannot throw into it or delay it.
      if (host.length > 0 && args.onPassThrough) notifyPassThrough(args.onPassThrough, fetchPassThroughInfo(input, init));
      return originalFetch(input, init);
    }
    args.onReroute?.({ host, url: urlOf(input) });
    return httpSuppress.run(true, () => args.reroute(input, init));
  };
  (patched as unknown as Record<symbol, unknown>)[INSTALLED] = true;
  target.fetch = patched;

  let installed = true;
  return {
    get installed() {
      return installed;
    },
    uninstall() {
      if (!installed) return;
      installed = false;
      // Only restore if WE are still the active fetch. If something patched on top
      // of us (an APM agent installed later), leave its fetch in place — clobbering
      // it would silently disable the other tool.
      if (target.fetch === patched) target.fetch = originalFetch;
    },
  };
}

// ── node:http / node:https stack ─────────────────────────────────────────────
//
// The dependency-free coverage for non-`fetch` HTTP clients. axios, node-fetch,
// cross-fetch and got all bottom out at `http(s).request`; patching the module's
// `.request`/`.get` catches them with no new dependency. A matched request is
// re-targeted through the SAME reroute closure the fetch stack uses (transit /
// escrow / route-around / promoted-route hints all apply) by translating the
// http.ClientRequest options → a fetch-style call → an IncomingMessage-shaped
// response.
//
// Anti-recursion: egress the reroute performs itself — KnoxCall's own client
// calls (when the global fetch is a polyfill backed by http.request), and
// route-around DIRECT calls to the same matched host — must bypass the
// interceptor. `httpSuppress` marks the reroute's async scope; a patched
// request inside it falls straight through to the original.
const httpSuppress = new AsyncLocalStorage<true>();

/**
 * Run `fn` in the SDK's OWN suppressed scope: egress it (and its awaited
 * descendants) performs bypasses every seam this module installs. The reroute
 * runs its hops here; the uncovered-egress reporter runs its flush here, so
 * the report is never itself intercepted or observed.
 */
export function runSuppressed<T>(fn: () => T): T {
  return httpSuppress.run(true, fn);
}

/** Whether the current async context is inside `runSuppressed`. */
export function inSuppressedContext(): boolean {
  return httpSuppress.getStore() === true;
}

// Cross-realm marker so a double install is detectable on a shared module.
const HTTP_INSTALLED = Symbol.for("knoxcall.egressInterceptor.http.installed");

// A node:http-like module object — the mutable `module.exports` of node:http /
// node:https (or a fake, for tests). We patch `.request` and `.get` on it.
export interface HttpModuleLike {
  request: (...args: unknown[]) => unknown;
  get: (...args: unknown[]) => unknown;
}

export interface HttpModules {
  http?: HttpModuleLike;
  https?: HttpModuleLike;
}

export interface InstallHttpEgressInterceptorArgs {
  /** Bare DNS hostnames whose outbound http(s) requests are rerouted. */
  hosts: string[];
  /** The rerouting transport — normally a `wrap.fetch(...)` closure. */
  reroute: FetchFn;
  /** Modules to patch. Defaults to the real node:http + node:https. Injected for tests. */
  modules?: HttpModules;
  /** Only reroute inside `runRouted()` — off by default (host-list alone scopes). */
  requireContext?: boolean;
  /** Fires when a request is rerouted (observability). */
  onReroute?: (info: { host: string; url: string }) => void;
  /** Dynamic host predicate, in addition to `hosts` (see the fetch stack). */
  matchHost?: (host: string) => boolean;
  /** Consulted per request; false passes the request through untouched (the kill switch). */
  enabled?: () => boolean;
  /** As the fetch stack: every request passed through untouched, for the uncovered-egress observer. */
  onPassThrough?: (info: PassThroughInfo) => void;
}

// Hop-by-hop / connection-management headers that must not ride a fetch: the
// upstream Content-Length/Transfer-Encoding are recomputed, Host is derived
// from the URL, and Connection/Keep-Alive are meaningless across a re-origin.
// (`fetch` would drop these forbidden names anyway; we strip them so the
// forwarded set is clean and the byte-length is never stale.)
const HTTP_HOP_BY_HOP = new Set([
  "host",
  "connection",
  "content-length",
  "transfer-encoding",
  "keep-alive",
  "upgrade",
  "proxy-connection",
]);

function ensureColon(protocol: string): string {
  return protocol.endsWith(":") ? protocol : `${protocol}:`;
}

function normalizeHttpHeaders(raw: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (!raw || typeof raw !== "object") return out;
  for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
    if (v === undefined || v === null) continue;
    if (HTTP_HOP_BY_HOP.has(k.toLowerCase())) continue;
    out[k] = Array.isArray(v) ? v.map(String).join(", ") : String(v);
  }
  return out;
}

interface ResolvedHttpTarget {
  url: string;
  host: string;
  method: string;
  headers: Record<string, string>;
  callback?: (res: unknown) => void;
}

/**
 * Reproduce node's `http.request(input, options, cb)` argument normalization
 * (a string/URL first arg becomes options via urlToHttpOptions, then a second
 * options object is merged over it; a function in either slot is the callback),
 * and derive the target URL + bare host for matching.
 */
function resolveHttpTarget(defaultProtocol: string, callArgs: unknown[]): ResolvedHttpTarget {
  let input = callArgs[0];
  let options = callArgs[1];
  let cb = callArgs[2];
  let base: Record<string, unknown> = {};

  if (typeof input === "string") {
    base = urlToHttpOptions(new URL(input)) as unknown as Record<string, unknown>;
  } else if (input instanceof URL) {
    base = urlToHttpOptions(input) as unknown as Record<string, unknown>;
  } else {
    // First arg is the options object (or undefined): request(options[, cb]).
    cb = options;
    options = input;
    base = {};
  }

  let opts: Record<string, unknown>;
  if (typeof options === "function") {
    cb = options;
    opts = { ...base };
  } else {
    opts = Object.assign({ ...base }, options && typeof options === "object" ? (options as Record<string, unknown>) : {});
  }

  const protocol = ensureColon(String(opts.protocol || defaultProtocol));
  const hostname = opts.hostname
    ? String(opts.hostname)
    : opts.host
      ? String(opts.host).replace(/:\d+$/, "")
      : "localhost";
  const path = opts.path != null ? String(opts.path) : "/";
  let port = opts.port != null && opts.port !== "" ? String(opts.port) : "";
  if (!port && !opts.hostname && opts.host) {
    const m = /:(\d+)$/.exec(String(opts.host));
    if (m) port = m[1];
  }
  const auth = opts.auth ? `${String(opts.auth)}@` : "";
  const hostForUrl = hostname.includes(":") && !hostname.startsWith("[") ? `[${hostname}]` : hostname;
  const url = `${protocol}//${auth}${hostForUrl}${port ? `:${port}` : ""}${path.startsWith("/") ? "" : "/"}${path}`;

  const parsed = new URL(url); // throws on garbage → caller treats as "not ours"
  return {
    url,
    host: normalizeHost(parsed.hostname),
    method: String(opts.method || "GET").toUpperCase(),
    headers: normalizeHttpHeaders(opts.headers),
    callback: typeof cb === "function" ? (cb as (res: unknown) => void) : undefined,
  };
}

/**
 * A stand-in for `http.ClientRequest` whose body is buffered from
 * `.write()`/`.end()` and sent via the fetch-style `reroute`; the resolved
 * `Response` is surfaced as an `http.IncomingMessage`-shaped Readable on the
 * `'response'` event. Implements the ClientRequest surface the common clients
 * touch (header accessors, `setTimeout`, `abort`/`destroy`).
 */
class FetchBackedClientRequest extends Writable {
  private readonly _target: ResolvedHttpTarget;
  private readonly _reroute: FetchFn;
  private readonly _headers: Record<string, string>;
  private readonly _chunks: Buffer[] = [];
  private readonly _controller = new AbortController();
  private _timeout?: ReturnType<typeof setTimeout>;
  private _sent = false;
  private _settled = false;

  constructor(target: ResolvedHttpTarget, reroute: FetchFn) {
    super();
    this._target = target;
    this._reroute = reroute;
    this._headers = { ...target.headers };
    if (target.callback) this.once("response", target.callback);
  }

  // ── ClientRequest header surface ──
  setHeader(name: string, value: number | string | readonly string[]): this {
    this._headers[name] = Array.isArray(value) ? value.map(String).join(", ") : String(value);
    return this;
  }
  getHeader(name: string): string | undefined {
    const hit = Object.keys(this._headers).find((k) => k.toLowerCase() === name.toLowerCase());
    return hit ? this._headers[hit] : undefined;
  }
  removeHeader(name: string): void {
    for (const k of Object.keys(this._headers)) if (k.toLowerCase() === name.toLowerCase()) delete this._headers[k];
  }
  hasHeader(name: string): boolean {
    return this.getHeader(name) !== undefined;
  }
  getHeaders(): Record<string, string> {
    return { ...this._headers };
  }
  getHeaderNames(): string[] {
    return Object.keys(this._headers).map((k) => k.toLowerCase());
  }
  getRawHeaderNames(): string[] {
    return Object.keys(this._headers);
  }
  // No-op parity: headers flush when the reroute fires; socket knobs don't apply
  // to a re-originated request.
  flushHeaders(): void {}
  setNoDelay(): this {
    return this;
  }
  setSocketKeepAlive(): this {
    return this;
  }

  setTimeout(ms: number, cb?: () => void): this {
    if (this._timeout) clearTimeout(this._timeout);
    this._timeout = setTimeout(() => {
      this.emit("timeout");
      if (cb) cb();
    }, ms);
    // Never let our shim's timer keep the event loop alive.
    (this._timeout as { unref?: () => void }).unref?.();
    return this;
  }

  abort(): void {
    this.destroy();
    this.emit("abort");
  }

  _write(chunk: unknown, enc: BufferEncoding, cb: (err?: Error | null) => void): void {
    try {
      this._chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as string, enc));
      cb();
    } catch (e) {
      cb(e as Error);
    }
  }

  _final(cb: (err?: Error | null) => void): void {
    this._send();
    cb();
  }

  _destroy(err: Error | null, cb: (err?: Error | null) => void): void {
    if (this._timeout) clearTimeout(this._timeout);
    this._settled = true;
    // best-effort: aborting an already-settled/aborted controller is a no-op.
    try {
      this._controller.abort();
    } catch {
      /* best-effort: safe to lose — the fetch is already done or gone */
    }
    cb(err);
  }

  private _send(): void {
    if (this._sent) return;
    this._sent = true;
    const method = this._target.method;
    const init: RequestInit = { method, headers: this._headers, signal: this._controller.signal };
    if (this._chunks.length && method !== "GET" && method !== "HEAD") {
      init.body = Buffer.concat(this._chunks);
    }
    // Run the reroute (and every http(s) egress it triggers) inside the
    // suppression scope so it can never re-enter this interceptor.
    httpSuppress
      .run(true, () => this._reroute(this._target.url, init))
      .then((res) => {
        if (this._settled || this.destroyed) return;
        this._settled = true;
        if (this._timeout) clearTimeout(this._timeout);
        this.emit("response", responseToIncomingMessage(res));
      })
      .catch((err) => {
        if (this._settled || this.destroyed) return;
        this._settled = true;
        if (this._timeout) clearTimeout(this._timeout);
        this.emit("error", err instanceof Error ? err : new Error(String(err)));
      });
  }
}

/** Translate a fetch `Response` into an `http.IncomingMessage`-shaped Readable. */
function responseToIncomingMessage(res: Response): Readable {
  const im = new Readable({ read() {} }) as Readable & Record<string, unknown>;
  im.statusCode = res.status;
  im.statusMessage = res.statusText || "";
  const headers: Record<string, string> = {};
  const rawHeaders: string[] = [];
  res.headers.forEach((v, k) => {
    headers[k] = v;
    rawHeaders.push(k, v);
  });
  im.headers = headers;
  im.rawHeaders = rawHeaders;
  im.httpVersion = "1.1";
  im.httpVersionMajor = 1;
  im.httpVersionMinor = 1;
  im.complete = false;

  void (async () => {
    try {
      const body = res.body as ReadableStream<Uint8Array> | null | undefined;
      if (body && typeof body.getReader === "function") {
        const reader = body.getReader();
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          if (value && value.byteLength) im.push(Buffer.from(value));
        }
      } else {
        const ab = await res.arrayBuffer();
        if (ab.byteLength) im.push(Buffer.from(ab));
      }
      im.complete = true;
      im.push(null);
    } catch (e) {
      im.destroy(e instanceof Error ? e : new Error(String(e)));
    }
  })();

  return im;
}

function makePatchedHttp(
  defaultProtocol: string,
  original: (...args: unknown[]) => unknown,
  autoEnd: boolean,
  hostSet: Set<string>,
  args: InstallHttpEgressInterceptorArgs,
): (...callArgs: unknown[]) => unknown {
  return function patched(this: unknown, ...callArgs: unknown[]): unknown {
    // Anti-recursion: egress performed BY the reroute bypasses the interceptor
    // (KnoxCall's own client calls via a fetch polyfill; route-around direct
    // calls to the same matched host).
    if (httpSuppress.getStore()) return original.apply(this, callArgs);

    let target: ResolvedHttpTarget | null = null;
    try {
      target = resolveHttpTarget(defaultProtocol, callArgs);
    } catch {
      target = null; // unparseable → not ours, pass through untouched
    }
    const shouldReroute =
      target != null &&
      (args.enabled?.() ?? true) &&
      (hostSet.has(target.host) || (args.matchHost?.(target.host) ?? false)) &&
      (!args.requireContext || inRoutedContext());
    if (!shouldReroute || !target) {
      if (target && args.onPassThrough) {
        const t = target;
        notifyPassThrough(args.onPassThrough, { url: t.url, method: t.method, headers: () => lowerKeys(t.headers) });
      }
      return original.apply(this, callArgs);
    }

    args.onReroute?.({ host: target.host, url: target.url });
    const req = new FetchBackedClientRequest(target, args.reroute);
    if (autoEnd) req.end(); // http.get = request + end
    return req;
  };
}

/** The real node:http / node:https modules as MUTABLE `module.exports` objects. */
export function nodeHttpModules(): HttpModules {
  const require_ = createRequire(import.meta.url);
  return {
    http: require_("node:http") as unknown as HttpModuleLike,
    https: require_("node:https") as unknown as HttpModuleLike,
  };
}

/**
 * Patch `.request` and `.get` on node:http / node:https (or injected fakes) so
 * outbound requests to `hosts` reroute through `reroute`. Returns a handle to
 * uninstall. Throws if `hosts` is empty or a KnoxCall http interceptor is
 * already installed on the target modules.
 */
export function installHttpEgressInterceptor(args: InstallHttpEgressInterceptorArgs): EgressInterceptor {
  if (!Array.isArray(args.hosts) || (args.hosts.length === 0 && typeof args.matchHost !== "function")) {
    throw new TypeError("installHttpEgressInterceptor requires a non-empty `hosts` array of DNS hostnames (or a `matchHost` predicate).");
  }
  const modules = args.modules ?? nodeHttpModules();
  const hostSet = new Set(args.hosts.map(normalizeHost).filter((h) => h.length > 0));

  const targets: Array<[HttpModuleLike | undefined, string]> = [
    [modules.http, "http:"],
    [modules.https, "https:"],
  ];

  // Refuse a double install (install one at a time, mirror the fetch stack).
  for (const [mod] of targets) {
    if (mod && (mod.request as unknown as Record<symbol, unknown>)?.[HTTP_INSTALLED]) {
      throw new Error(
        "A KnoxCall http egress interceptor is already installed; uninstall it before installing another.",
      );
    }
  }

  interface Entry {
    module: HttpModuleLike;
    originalRequest: (...a: unknown[]) => unknown;
    originalGet?: (...a: unknown[]) => unknown;
    patchedRequest: (...a: unknown[]) => unknown;
    patchedGet: (...a: unknown[]) => unknown;
  }
  const entries: Entry[] = [];

  for (const [mod, protocol] of targets) {
    if (!mod || typeof mod.request !== "function") continue;
    // Capture the originals by reference (no bind) so uninstall restores the
    // exact function that was there, and `this` still flows to the callee.
    const originalRequest = mod.request as (...a: unknown[]) => unknown;
    const hasGet = typeof mod.get === "function";
    const originalGet = hasGet ? (mod.get as (...a: unknown[]) => unknown) : undefined;

    const patchedRequest = makePatchedHttp(protocol, originalRequest, false, hostSet, args);
    const patchedGet = makePatchedHttp(protocol, originalGet ?? originalRequest, true, hostSet, args);
    (patchedRequest as unknown as Record<symbol, unknown>)[HTTP_INSTALLED] = true;
    (patchedGet as unknown as Record<symbol, unknown>)[HTTP_INSTALLED] = true;

    mod.request = patchedRequest as HttpModuleLike["request"];
    if (hasGet) mod.get = patchedGet as HttpModuleLike["get"];
    entries.push({ module: mod, originalRequest, originalGet, patchedRequest, patchedGet });
  }

  let installed = true;
  return {
    get installed() {
      return installed;
    },
    uninstall() {
      if (!installed) return;
      installed = false;
      for (const e of entries) {
        // Anti-clobber: only restore where WE are still the active function.
        if (e.module.request === e.patchedRequest) {
          e.module.request = e.originalRequest as HttpModuleLike["request"];
        }
        if (e.originalGet && e.module.get === e.patchedGet) {
          e.module.get = e.originalGet as HttpModuleLike["get"];
        }
      }
    },
  };
}

/** Combine several interceptor handles into one; `uninstall()` cascades to all. */
export function combineEgressInterceptors(handles: EgressInterceptor[]): EgressInterceptor {
  return {
    get installed() {
      return handles.some((h) => h.installed);
    },
    uninstall() {
      for (const h of handles) h.uninstall();
    },
  };
}
