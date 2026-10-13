// Route-aware transport + interceptor (route-aware-interception-plan.md PR2).
//
// Capture is at the SDK's HTTP boundary (the injected fetchImpl for KnoxCall
// traffic; a fake global-fetch target for the interceptor), never by mocking
// the wrapper. The manifest is served by the same stub the proxy calls hit, so
// every test drives the real store, the real resolver and the real senders.
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { KnoxCall, APIConnectionError, manifestEtag } from "../src/index.js";
import type { InterceptManifestRoute } from "../src/index.js";
import { _resetWarnedForTests } from "../src/warn.js";

interface Seen {
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: string;
}

function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });
}

function entry(over: Partial<InterceptManifestRoute> & { host: string; slug: string }): InterceptManifestRoute {
  return { base_path: "/", route_id: `id-${over.slug}`, requires_clients: false, allowed_methods: null, updated_at: null, ...over };
}

const HUBSPOT = entry({ host: "api.hubapi.com", base_path: "/crm/v3", slug: "hubspot-crm" });
const HUBSPOT_ROOT = entry({ host: "api.hubapi.com", base_path: "/", slug: "hubspot" });

interface StubOptions {
  /** The manifest entries to serve; `"forbidden"` answers 403; a function is called per manifest fetch. */
  manifest?: InterceptManifestRoute[] | "forbidden" | (() => InterceptManifestRoute[]);
  /** Per-call override for the manifest endpoint (n is 1-based); `undefined` falls through to the normal answer. */
  manifestOverride?: (seen: Seen, n: number) => Response | undefined;
  /** Per-call responder for data-plane traffic (route + ephemeral). Default: 200 {ok:true}. */
  dataPlane?: (seen: Seen, n: number) => Response | Error;
}

/**
 * A KnoxCall client whose fetchImpl records every call and serves the manifest
 * + data plane. The manifest endpoint behaves as the server does
 * (src/client-api/wrap.ts): `ETag: W/"<version>"` on every answer, and a `304`
 * with no body when `If-None-Match` carries that tag.
 */
function makeClient(seen: Seen[], opts: StubOptions = {}) {
  let manifestCallsN = 0;
  let dataPlaneCalls = 0;
  const fetchImpl: typeof fetch = async (input, init) => {
    const url = typeof input === "string" ? input : (input as Request).url;
    const headers: Record<string, string> = {};
    if (init?.headers) for (const [k, v] of Object.entries(init.headers as Record<string, string>)) headers[k.toLowerCase()] = v;
    const rec: Seen = { url, method: init?.method ?? "GET", headers, body: typeof init?.body === "string" ? init.body : undefined };
    seen.push(rec);
    if (url.startsWith("https://api.test/v1/wrap/intercept-manifest")) {
      manifestCallsN++;
      const override = opts.manifestOverride?.(rec, manifestCallsN);
      if (override) return override;
      if (opts.manifest === "forbidden") {
        return json(403, { error: { type: "forbidden", message: "insufficient scope", request_id: "r" } });
      }
      const routes = typeof opts.manifest === "function" ? opts.manifest() : (opts.manifest ?? []);
      const version = `sha256:${routes.map((r) => r.slug).join(",") || "empty"}`;
      const etag = manifestEtag(version);
      if (headers["if-none-match"]?.split(",").map((t) => t.trim()).includes(etag)) {
        return new Response(null, { status: 304, headers: { ETag: etag } });
      }
      return json(200, { data: { version, ttl_seconds: 60, environment: "production", sandbox: false, routes }, meta: { request_id: `m${manifestCallsN}` } }, { ETag: etag });
    }
    dataPlaneCalls++;
    const r = opts.dataPlane?.(rec, dataPlaneCalls);
    if (r instanceof Error) throw r;
    return r ?? json(200, { ok: true });
  };
  return new KnoxCall({
    tenant: "acme", baseUrl: "https://api.test", proxyBaseUrl: "https://acme.test",
    apiKey: "kc_live_x", sandbox: false, fetchImpl,
  });
}

const manifestCalls = (seen: Seen[]) => seen.filter((s) => s.url.startsWith("https://api.test/v1/wrap/intercept-manifest"));
const proxyCalls = (seen: Seen[]) => seen.filter((s) => s.url === "https://api.test/v1/proxy");
const routeCalls = (seen: Seen[]) => seen.filter((s) => s.url.startsWith("https://acme.test/"));

beforeEach(() => {
  _resetWarnedForTests();
  delete process.env.KNOXCALL_INTERCEPT;
});
afterEach(() => {
  delete process.env.KNOXCALL_INTERCEPT;
});

describe("wrap.fetch — routes: 'off' (default) never consults the manifest", () => {
  it("sends every request ephemeral and makes no manifest call", async () => {
    const seen: Seen[] = [];
    const wrapped = makeClient(seen, { manifest: [HUBSPOT] }).wrap.fetch();
    await wrapped.ready;
    await wrapped("https://api.hubapi.com/crm/v3/objects", { headers: { authorization: "Bearer tok" } });
    expect(manifestCalls(seen)).toHaveLength(0);
    expect(proxyCalls(seen)).toHaveLength(1);
    // The reroute marker is a ROUTE-mode fact (PARITY §21.2); an ephemeral hop
    // is a different log and carries nothing.
    expect(proxyCalls(seen)[0].headers["x-knoxcall-origin"]).toBeUndefined();
    expect(wrapped.manifest()).toBeNull();
  });
});

describe("wrap.fetch — routes: 'auto'", () => {
  it("a host + path a Route covers goes through the Route with the path rebased and no provider credential", async () => {
    const seen: Seen[] = [];
    const onReroute = vi.fn();
    const wrapped = makeClient(seen, { manifest: [HUBSPOT, HUBSPOT_ROOT] }).wrap.fetch({ routes: "auto", onReroute });
    await wrapped.ready;
    expect(wrapped.manifest()?.routes).toHaveLength(2);

    await wrapped("https://api.hubapi.com/crm/v3/objects/contacts?limit=1", {
      method: "POST", headers: { authorization: "Bearer hubspot-token", "content-type": "application/json" }, body: '{"a":1}',
    });
    const r = routeCalls(seen)[0];
    expect(r.url).toBe("https://acme.test/objects/contacts?limit=1");
    expect(r.method).toBe("POST");
    expect(r.headers["x-knoxcall-route"]).toBe("hubspot-crm");
    // The reroute marker the API Log renders as "SDK intercept" (PARITY §21.2).
    expect(r.headers["x-knoxcall-origin"]).toBe("sdk-intercept");
    expect(r.headers["authorization"]).toBe("Bearer kc_live_x"); // KnoxCall's own credential
    expect(r.headers["x-knox-upstream-authorization"]).toBeUndefined(); // the Route injects the secret
    expect(r.headers["x-knox-proxy-url"]).toBeUndefined();
    expect(r.body).toBe('{"a":1}');
    expect(proxyCalls(seen)).toHaveLength(0);
    expect(onReroute).toHaveBeenCalledWith(expect.objectContaining({ mode: "route", slug: "hubspot-crm", reason: "manifest", host: "api.hubapi.com" }));
  });

  it("a path outside the deeper base falls to the root Route; a host no Route covers goes ephemeral", async () => {
    const seen: Seen[] = [];
    const wrapped = makeClient(seen, { manifest: [HUBSPOT, HUBSPOT_ROOT] }).wrap.fetch({ routes: "auto" });
    await wrapped.ready;
    await wrapped("https://api.hubapi.com/oauth/v1/token", { method: "POST", headers: { authorization: "Bearer t" }, body: "" });
    expect(routeCalls(seen)[0].url).toBe("https://acme.test/oauth/v1/token");
    expect(routeCalls(seen)[0].headers["x-knoxcall-route"]).toBe("hubspot");

    await wrapped("https://api.resend.com/emails", { method: "POST", headers: { authorization: "Bearer re_x" }, body: "{}" });
    const p = proxyCalls(seen)[0];
    expect(p.headers["x-knox-proxy-url"]).toBe("https://api.resend.com/emails");
    expect(p.headers["x-knox-upstream-authorization"]).toBe("Bearer re_x");
  });

  it("the client's own hosts are never routed, and KNOXCALL_INTERCEPT=off makes everything direct", async () => {
    const seen: Seen[] = [];
    const direct = vi.fn(async () => new Response("DIRECT"));
    const wrapped = makeClient(seen, { manifest: [HUBSPOT_ROOT] }).wrap.fetch({ routes: "auto", directFetch: direct as unknown as typeof fetch });
    await wrapped.ready;

    await wrapped("https://api.test/v1/routes");
    expect(direct).toHaveBeenCalledTimes(1);
    expect(routeCalls(seen)).toHaveLength(0);
    expect(proxyCalls(seen)).toHaveLength(0);

    process.env.KNOXCALL_INTERCEPT = "off";
    const res = await wrapped("https://api.hubapi.com/crm/v3/objects");
    expect(await res.text()).toBe("DIRECT");
    expect(routeCalls(seen)).toHaveLength(0);
  });

  it("a KnoxCall-origin 401 in route mode refreshes the manifest once and re-decides — resending ephemeral when the Route is gone", async () => {
    const seen: Seen[] = [];
    const onRefused = vi.fn();
    let routes: InterceptManifestRoute[] = [HUBSPOT_ROOT];
    const client = makeClient(seen, {
      manifest: () => routes,
      dataPlane: (rec) => (rec.url.startsWith("https://acme.test/") ? json(401, { error: "Unauthorized" }) : undefined) as Response,
    });
    const wrapped = client.wrap.fetch({ routes: "auto", onRefused });
    await wrapped.ready;
    expect(manifestCalls(seen)).toHaveLength(1);

    routes = []; // the Route was disabled between the poll and this request
    const res = await wrapped("https://api.hubapi.com/x", { method: "POST", headers: { authorization: "Bearer t" }, body: "payload" });
    expect(res.status).toBe(200);
    // call() spends its one re-mint (2 route attempts), then ONE manifest refresh, then the ephemeral resend.
    expect(routeCalls(seen)).toHaveLength(2);
    expect(manifestCalls(seen)).toHaveLength(2);
    expect(proxyCalls(seen)).toHaveLength(1);
    expect(proxyCalls(seen)[0].body).toBe("payload");
    expect(onRefused).toHaveBeenCalledWith(expect.objectContaining({ slug: "hubspot", status: 401, redecided: "ephemeral" }));
    expect(wrapped.manifest()?.routes).toEqual([]);
  });

  it("a KnoxCall-origin 401 whose refresh changes nothing is returned as-is — never a loop", async () => {
    const seen: Seen[] = [];
    const onRefused = vi.fn();
    const client = makeClient(seen, {
      manifest: [HUBSPOT_ROOT],
      dataPlane: (rec) => (rec.url.startsWith("https://acme.test/") ? json(401, { error: "Unauthorized" }) : undefined) as Response,
    });
    const wrapped = client.wrap.fetch({ routes: "auto", onRefused });
    await wrapped.ready;
    const res = await wrapped("https://api.hubapi.com/x", { method: "POST", headers: { authorization: "Bearer t" }, body: "payload" });
    expect(res.status).toBe(401);
    expect(routeCalls(seen)).toHaveLength(2); // call()'s own re-mint, nothing more
    expect(manifestCalls(seen)).toHaveLength(2);
    expect(proxyCalls(seen)).toHaveLength(0);
    expect(onRefused).toHaveBeenCalledWith(expect.objectContaining({ redecided: null }));
  });

  it("an UPSTREAM 401 through the Route is not a refusal: no refresh, returned as-is", async () => {
    const seen: Seen[] = [];
    const client = makeClient(seen, {
      manifest: [HUBSPOT_ROOT],
      dataPlane: (rec) => (rec.url.startsWith("https://acme.test/") ? json(401, { err: "bad provider token" }, { "X-Knox-Upstream-Status": "401" }) : undefined) as Response,
    });
    const wrapped = client.wrap.fetch({ routes: "auto" });
    await wrapped.ready;
    const res = await wrapped("https://api.hubapi.com/x", { headers: { authorization: "Bearer t" } });
    expect(res.status).toBe(401);
    expect(routeCalls(seen)).toHaveLength(1);
    expect(manifestCalls(seen)).toHaveLength(1);
  });

  // Founder decision 2026-09-26: an AUTHENTICATED key gets a real 404 for a
  // route that does not resolve. A stale manifest naming a Route that was
  // deleted since the poll is exactly that, so the 404 route_not_found
  // envelope is a refresh trigger too (PARITY §21.1). No re-mint is spent on
  // it — that is call()'s 401-only rule — so the Route is called ONCE.
  it("a KnoxCall-origin 404 route_not_found in route mode refreshes once and re-decides — resending ephemeral when the Route is gone", async () => {
    const seen: Seen[] = [];
    const onRefused = vi.fn();
    let routes: InterceptManifestRoute[] = [HUBSPOT_ROOT];
    const notFound = () =>
      json(
        404,
        { error: { type: "route_not_found", message: "Route 'hubspot' not found.", request_id: "req_x" } },
        { "X-Knox-Origin": "knoxcall", "X-Knox-Error": "route_not_found", "X-Knox-Plane": "route" },
      );
    const client = makeClient(seen, {
      manifest: () => routes,
      dataPlane: (rec) => (rec.url.startsWith("https://acme.test/") ? notFound() : undefined) as Response,
    });
    const wrapped = client.wrap.fetch({ routes: "auto", onRefused });
    await wrapped.ready;

    routes = []; // the Route was deleted between the poll and this request
    const res = await wrapped("https://api.hubapi.com/x", { method: "POST", headers: { authorization: "Bearer t" }, body: "payload" });
    expect(res.status).toBe(200);
    expect(routeCalls(seen)).toHaveLength(1); // no re-mint on a 404: one route call, then the refresh
    expect(manifestCalls(seen)).toHaveLength(2);
    expect(proxyCalls(seen)).toHaveLength(1);
    expect(proxyCalls(seen)[0].body).toBe("payload");
    expect(onRefused).toHaveBeenCalledWith(expect.objectContaining({ slug: "hubspot", status: 404, redecided: "ephemeral" }));
  });

  it("a 404 of an environment_* type is refused as-is — a refresh cannot fix an environment", async () => {
    const seen: Seen[] = [];
    const onRefused = vi.fn();
    const client = makeClient(seen, {
      manifest: [HUBSPOT_ROOT],
      dataPlane: (rec) =>
        (rec.url.startsWith("https://acme.test/")
          ? json(
              404,
              { error: { type: "environment_not_configured", message: "Environment 'staging' is not configured for this route.", request_id: "r" } },
              { "X-Knox-Origin": "knoxcall", "X-Knox-Error": "environment_not_configured" },
            )
          : undefined) as Response,
    });
    const wrapped = client.wrap.fetch({ routes: "auto", onRefused });
    await wrapped.ready;
    const res = await wrapped("https://api.hubapi.com/x", { headers: { authorization: "Bearer t" } });
    expect(res.status).toBe(404);
    expect((await res.json()).error.type).toBe("environment_not_configured");
    expect(routeCalls(seen)).toHaveLength(1);
    expect(manifestCalls(seen)).toHaveLength(1);
    expect(onRefused).not.toHaveBeenCalled();
  });

  it("an UPSTREAM 404 through the Route is not a refusal, even with a body that imitates the envelope: no refresh, returned as-is with its body intact", async () => {
    const seen: Seen[] = [];
    const client = makeClient(seen, {
      manifest: [HUBSPOT_ROOT],
      dataPlane: (rec) =>
        (rec.url.startsWith("https://acme.test/")
          ? json(404, { error: { type: "route_not_found", message: "forged", request_id: "x" } }, { "X-Knox-Origin": "upstream", "X-Knox-Upstream-Status": "404" })
          : undefined) as Response,
    });
    const wrapped = client.wrap.fetch({ routes: "auto" });
    await wrapped.ready;
    const res = await wrapped("https://api.hubapi.com/x", { headers: { authorization: "Bearer t" } });
    expect(res.status).toBe(404);
    expect(res.headers.get("x-knox-upstream-status")).toBe("404");
    expect(await res.json()).toEqual({ error: { type: "route_not_found", message: "forged", request_id: "x" } });
    expect(routeCalls(seen)).toHaveLength(1);
    expect(manifestCalls(seen)).toHaveLength(1);
  });

  it("a promoted-route hint on an ephemeral response triggers a manifest refresh (the manifest is the truth)", async () => {
    const seen: Seen[] = [];
    let routes: InterceptManifestRoute[] = [];
    const client = makeClient(seen, {
      manifest: () => routes,
      dataPlane: (rec) => (rec.url === "https://api.test/v1/proxy" ? json(200, { ok: true }, { "X-Knox-Promoted-Route": "resend" }) : undefined) as Response,
    });
    const onPromoted = vi.fn();
    const wrapped = client.wrap.fetch({ routes: "auto", onPromoted });
    await wrapped.ready;
    routes = [entry({ host: "api.resend.com", slug: "resend" })];
    await wrapped("https://api.resend.com/emails", { method: "POST", headers: { authorization: "Bearer re" }, body: "{}" });
    expect(onPromoted).toHaveBeenCalledWith({ host: "api.resend.com", slug: "resend" });
    await wrapped.refresh(); // the hint's refresh is rate-limited; force one for determinism
    expect(wrapped.manifest()?.routes.map((r) => r.slug)).toEqual(["resend"]);
    await wrapped("https://api.resend.com/emails", { method: "POST", headers: { authorization: "Bearer re" }, body: "{}" });
    expect(routeCalls(seen).at(-1)?.headers["x-knoxcall-route"]).toBe("resend");
  });

  it("when the manifest endpoint refuses the credential, listed hosts stay ephemeral and one warning fires", async () => {
    const seen: Seen[] = [];
    const warn = vi.spyOn(process, "emitWarning").mockImplementation(() => undefined);
    const wrapped = makeClient(seen, { manifest: "forbidden" }).wrap.fetch({ routes: "auto" });
    await wrapped.ready;
    expect(wrapped.manifest()).toBeNull();
    await wrapped("https://api.hubapi.com/x", { headers: { authorization: "Bearer t" } });
    expect(proxyCalls(seen)).toHaveLength(1);
    expect(warn).toHaveBeenCalledTimes(1);
    expect(String(warn.mock.calls[0][0])).toContain("routes:read");
    warn.mockRestore();
  });

  it("D4: KnoxCall unreachable is an error by default; `unavailable: 'direct'` sends transit traffic direct and fires onFallback", async () => {
    const seen: Seen[] = [];
    const direct = vi.fn(async () => new Response("DIRECT"));
    const onFallback = vi.fn();
    const client = makeClient(seen, {
      manifest: [],
      dataPlane: () => new TypeError("fetch failed: ECONNREFUSED"),
    });
    const strict = client.wrap.fetch({ routes: "auto", directFetch: direct as unknown as typeof fetch });
    await strict.ready;
    await expect(strict("https://api.resend.com/emails", { headers: { authorization: "Bearer re" } })).rejects.toBeInstanceOf(APIConnectionError);
    expect(direct).not.toHaveBeenCalled();

    const lenient = client.wrap.fetch({ routes: "auto", unavailable: "direct", directFetch: direct as unknown as typeof fetch, onFallback });
    await lenient.ready;
    const res = await lenient("https://api.resend.com/emails", { headers: { authorization: "Bearer re" } });
    expect(await res.text()).toBe("DIRECT");
    expect(onFallback).toHaveBeenCalledWith(expect.objectContaining({ host: "api.resend.com" }));

    // Escrow has nothing to go direct with: still an error.
    const escrow = client.wrap.fetch({ routes: "auto", unavailable: "direct", credential: { secret: "resend-key" }, directFetch: direct as unknown as typeof fetch });
    await escrow.ready;
    await expect(escrow("https://api.resend.com/emails")).rejects.toBeInstanceOf(APIConnectionError);
    expect(direct).toHaveBeenCalledTimes(1);
  });

  it("onUnmatchedPath fires once per (host, prefix) when a Route covers the host but not the path", async () => {
    const seen: Seen[] = [];
    const onUnmatchedPath = vi.fn();
    const client = makeClient(seen, { manifest: [HUBSPOT] });
    const wrapped = client.wrap.fetch({ routes: "auto", onUnmatchedPath });
    await wrapped.ready;
    await wrapped("https://api.hubapi.com/oauth/v1/token", { headers: { authorization: "Bearer t" } });
    await wrapped("https://api.hubapi.com/oauth/v1/refresh", { headers: { authorization: "Bearer t" } });
    await wrapped("https://api.hubapi.com/settings/v3/users", { headers: { authorization: "Bearer t" } });
    expect(proxyCalls(seen)).toHaveLength(3);
    expect(onUnmatchedPath).toHaveBeenCalledTimes(2);
  });
});

describe("wrap.intercept — route-aware by default", () => {
  function makeTarget() {
    const original = vi.fn(async () => new Response("ORIGINAL"));
    return { target: { fetch: original as unknown as typeof fetch }, original };
  }

  it("a manifest host is rerouted through its Route; a listed host without one goes ephemeral; the rest is untouched", async () => {
    const seen: Seen[] = [];
    const client = makeClient(seen, { manifest: [HUBSPOT, HUBSPOT_ROOT] });
    const { target, original } = makeTarget();
    const handle = client.wrap.intercept({ hosts: ["api.resend.com"], stacks: ["fetch"], target });
    await handle.ready;
    expect(handle.manifest()?.routes).toHaveLength(2);

    await target.fetch("https://api.hubapi.com/crm/v3/objects", { headers: { authorization: "Bearer t" } });
    expect(routeCalls(seen)[0].url).toBe("https://acme.test/objects");
    expect(routeCalls(seen)[0].headers["x-knoxcall-route"]).toBe("hubspot-crm");

    await target.fetch("https://api.resend.com/emails", { method: "POST", headers: { authorization: "Bearer re" }, body: "{}" });
    expect(proxyCalls(seen)).toHaveLength(1);

    const r = await target.fetch("https://api.openai.com/v1/models");
    expect(await r.text()).toBe("ORIGINAL");
    expect(original).toHaveBeenCalledTimes(1);

    handle.uninstall();
    expect(handle.installed).toBe(false);
    expect(target.fetch).toBe(original);
    expect(handle.manifest()).toBeNull(); // the store is dropped with the patch
  });

  it("needs no `hosts` at all when the manifest is the scope", async () => {
    const seen: Seen[] = [];
    const client = makeClient(seen, { manifest: [HUBSPOT_ROOT] });
    const { target } = makeTarget();
    const handle = client.wrap.intercept({ stacks: ["fetch"], target });
    await handle.ready;
    await target.fetch("https://api.hubapi.com/anything");
    expect(routeCalls(seen)).toHaveLength(1);
    handle.uninstall();
  });

  it("the client's own hosts are never intercepted, even when listed and even with a manifest naming them", async () => {
    const seen: Seen[] = [];
    const client = makeClient(seen, { manifest: [entry({ host: "api.test", slug: "self" })] });
    const { target, original } = makeTarget();
    const handle = client.wrap.intercept({ hosts: ["api.test", "acme.test"], stacks: ["fetch"], target });
    await handle.ready;
    await target.fetch("https://api.test/v1/routes");
    await target.fetch("https://acme.test/x");
    expect(original).toHaveBeenCalledTimes(2);
    expect(routeCalls(seen)).toHaveLength(0);
    expect(proxyCalls(seen)).toHaveLength(0);
    handle.uninstall();
  });

  it("hosts as a map carries per-host escrow: that host's ephemeral traffic references the secret", async () => {
    const seen: Seen[] = [];
    const client = makeClient(seen, { manifest: [] });
    const { target } = makeTarget();
    const handle = client.wrap.intercept({ hosts: { "api.resend.com": { credential: { secret: "resend-key" } }, "api.mailgun.net": {} }, stacks: ["fetch"], target });
    await handle.ready;
    await target.fetch("https://api.resend.com/emails", { method: "POST", body: "{}" });
    await target.fetch("https://api.mailgun.net/v3/x", { method: "POST", headers: { authorization: "Basic abc" }, body: "" });
    const [resend, mailgun] = proxyCalls(seen);
    expect(resend.headers["x-knox-upstream-auth-secret"]).toBe("resend-key");
    expect(resend.headers["x-knox-upstream-authorization"]).toBeUndefined();
    expect(mailgun.headers["x-knox-upstream-authorization"]).toBe("Basic abc");
    handle.uninstall();
  });

  it("KNOXCALL_INTERCEPT=off passes every request through the original transport", async () => {
    const seen: Seen[] = [];
    const client = makeClient(seen, { manifest: [HUBSPOT_ROOT] });
    const { target, original } = makeTarget();
    const handle = client.wrap.intercept({ hosts: ["api.resend.com"], stacks: ["fetch"], target });
    await handle.ready;
    process.env.KNOXCALL_INTERCEPT = "off";
    await target.fetch("https://api.hubapi.com/x");
    await target.fetch("https://api.resend.com/x");
    expect(original).toHaveBeenCalledTimes(2);
    expect(routeCalls(seen)).toHaveLength(0);
    expect(proxyCalls(seen)).toHaveLength(0);
    handle.uninstall();
  });

  it("refresh() picks up a Route created after install — no re-install", async () => {
    const seen: Seen[] = [];
    let routes: InterceptManifestRoute[] = [];
    const client = makeClient(seen, { manifest: () => routes });
    const { target, original } = makeTarget();
    const handle = client.wrap.intercept({ stacks: ["fetch"], target });
    await handle.ready;
    await target.fetch("https://api.hubapi.com/x");
    expect(original).toHaveBeenCalledTimes(1); // unlisted, no route → untouched
    routes = [HUBSPOT_ROOT];
    await handle.refresh();
    await target.fetch("https://api.hubapi.com/x");
    expect(routeCalls(seen)).toHaveLength(1);
    handle.uninstall();
  });

  it("routes: 'off' without hosts is refused — there would be nothing to intercept", () => {
    const client = makeClient([], {});
    expect(() => client.wrap.intercept({ routes: "off", stacks: ["fetch"], target: makeTarget().target })).toThrow(TypeError);
  });

  it("interceptEgress() is the static, ephemeral-only alias: no manifest call, listed host ephemeral", async () => {
    const seen: Seen[] = [];
    const client = makeClient(seen, { manifest: [HUBSPOT_ROOT] });
    const { target, original } = makeTarget();
    const handle = client.wrap.interceptEgress({ hosts: ["api.resend.com"], stacks: ["fetch"], target });
    await target.fetch("https://api.resend.com/emails", { headers: { authorization: "Bearer re" } });
    await target.fetch("https://api.hubapi.com/x");
    expect(manifestCalls(seen)).toHaveLength(0);
    expect(proxyCalls(seen)).toHaveLength(1);
    expect(original).toHaveBeenCalledTimes(1);
    handle.uninstall();
  });
});

// The conditional poll on the wire (PARITY §21.1 "Conditional poll"). The
// store-level walk of sdk/fixtures/intercept-store-conditional.json lives in
// intercept-manifest-store.test.ts; here the same contract is proven at the
// SDK's HTTP boundary — which header leaves, in which form, and what a 304
// becomes — through the real interceptManifest and the real store.
describe("wrap.interceptManifest — conditional poll (If-None-Match)", () => {
  const HERE = dirname(fileURLToPath(import.meta.url));
  const fixture = JSON.parse(readFileSync(join(HERE, "..", "..", "fixtures", "intercept-store-conditional.json"), "utf8")) as {
    steps: { expect: { fetch_if_none_match: string | null; wire_if_none_match: string | null } }[];
  };

  it("the wire form of every fixture step's held version is the server's weak ETag, W/\"<version>\"", () => {
    for (const step of fixture.steps) {
      if (step.expect.fetch_if_none_match === null) {
        expect(step.expect.wire_if_none_match).toBeNull();
        continue;
      }
      expect(manifestEtag(step.expect.fetch_if_none_match)).toBe(step.expect.wire_if_none_match);
    }
  });

  it("sends If-None-Match as W/\"<version>\" and resolves null on 304; the unconditional call sends no header; a stale tag gets the manifest", async () => {
    const seen: Seen[] = [];
    const client = makeClient(seen, { manifest: [HUBSPOT] });
    const first = await client.wrap.interceptManifest();
    expect(first.routes.map((r) => r.slug)).toEqual(["hubspot-crm"]);
    expect(manifestCalls(seen)[0].headers["if-none-match"]).toBeUndefined();

    const unchanged = await client.wrap.interceptManifest({ ifNoneMatch: first.version });
    expect(manifestCalls(seen)[1].headers["if-none-match"]).toBe(`W/"${first.version}"`);
    expect(unchanged).toBeNull();

    const stale = await client.wrap.interceptManifest({ ifNoneMatch: "sha256:stale" });
    expect(manifestCalls(seen)[2].headers["if-none-match"]).toBe('W/"sha256:stale"');
    expect(stale?.version).toBe(first.version);

    // `ifNoneMatch: undefined` is the unconditional call, not a header with no value.
    const explicit = await client.wrap.interceptManifest({ ifNoneMatch: undefined });
    expect(manifestCalls(seen)[3].headers["if-none-match"]).toBeUndefined();
    expect(explicit?.version).toBe(first.version);
  });

  it("a 401 on the conditional poll still gets the one transparent re-auth, and the retry carries If-None-Match", async () => {
    const seen: Seen[] = [];
    const client = makeClient(seen, {
      manifest: [HUBSPOT],
      manifestOverride: (_rec, n) => (n === 2 ? json(401, { error: { type: "authentication_error", message: "expired", request_id: "r" } }) : undefined),
    });
    const first = await client.wrap.interceptManifest();
    const res = await client.wrap.interceptManifest({ ifNoneMatch: first.version });
    expect(manifestCalls(seen)).toHaveLength(3); // unconditional, the 401, the re-authed retry
    expect(manifestCalls(seen).slice(1).map((c) => c.headers["if-none-match"])).toEqual([`W/"${first.version}"`, `W/"${first.version}"`]);
    expect(res).toBeNull();
  });

  it("the route-aware transport polls conditionally: every refresh after the first carries the held version, a 304 keeps the manifest and fires no onRefresh, a change replaces it and the next poll carries the new version", async () => {
    const seen: Seen[] = [];
    let routes = [HUBSPOT];
    const onRefresh = vi.fn();
    const wrapped = makeClient(seen, { manifest: () => routes }).wrap.fetch({ routes: "auto", onRefresh });
    await wrapped.ready;
    const v1 = wrapped.manifest()!.version;
    expect(manifestCalls(seen)[0].headers["if-none-match"]).toBeUndefined();
    expect(onRefresh).toHaveBeenCalledTimes(1);

    await wrapped.refresh(); // forced, as a refusal-driven refresh is
    expect(manifestCalls(seen)).toHaveLength(2);
    expect(manifestCalls(seen)[1].headers["if-none-match"]).toBe(`W/"${v1}"`);
    expect(wrapped.manifest()?.version).toBe(v1);
    expect(wrapped.manifest()?.routes).toEqual([HUBSPOT]);
    expect(onRefresh).toHaveBeenCalledTimes(1);

    routes = [HUBSPOT_ROOT];
    await wrapped.refresh();
    expect(manifestCalls(seen)[2].headers["if-none-match"]).toBe(`W/"${v1}"`);
    const v2 = wrapped.manifest()!.version;
    expect(v2).not.toBe(v1);
    expect(onRefresh).toHaveBeenCalledTimes(2);
    expect(onRefresh.mock.calls[1][0]).toEqual(expect.objectContaining({ version: v2, added: [HUBSPOT_ROOT], removed: [HUBSPOT] }));

    await wrapped.refresh();
    expect(manifestCalls(seen)[3].headers["if-none-match"]).toBe(`W/"${v2}"`);
    expect(wrapped.manifest()?.version).toBe(v2);
    expect(onRefresh).toHaveBeenCalledTimes(2);

    // The decision still reads the held manifest after a 304: the covered host routes.
    await wrapped("https://api.hubapi.com/oauth/v1/token", { method: "POST", headers: { authorization: "Bearer t" }, body: "" });
    expect(routeCalls(seen)[0].headers["x-knoxcall-route"]).toBe("hubspot");
    wrapped.stop();
  });
});
