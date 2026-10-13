// Uncovered-egress observations (PARITY §21.3) — the Node REFERENCE.
//
// Three layers, each captured at a real boundary, never by mocking the thing
// under test:
//   1. the classifier, driven by the CROSS-LANGUAGE fixture
//      sdk/fixtures/egress-observation.json (python/go/php/ruby walk the same
//      file);
//   2. the reporter (aggregation, bounds, timer, single-flight, 403 / failure
//      posture) against an injected report function;
//   3. the seams: `wrap.intercept()` over a fake global fetch and a fake
//      node:http module, with the SDK's own fetchImpl recording what LEAVES
//      the process — so the wire body is asserted byte-for-byte to carry the
//      credential header's NAME and never its VALUE, and never the query.
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  KnoxCall,
  EgressObservationReporter,
  credentialHeaderName,
  isCredentialHeaderName,
  observationFirstSegment,
  observationFor,
  firstSegmentLooksLikeCredential,
  CREDENTIAL_HEADER_ALLOWLIST,
  CREDENTIAL_HEADER_SUFFIXES,
} from "../src/index.js";
import type { EgressObservation, EgressObservationsReport, InterceptManifestRoute } from "../src/index.js";
import { normaliseHost } from "../src/intercept-resolver.js";
import { _resetWarnedForTests } from "../src/warn.js";
import { SDK_VERSION } from "../src/core.js";
import type { HttpModuleLike } from "../src/egress-interceptor.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURE_PATH = join(HERE, "..", "..", "fixtures", "egress-observation.json");

interface Fixture {
  credential_headers: { allowlist: string[]; suffixes: string[] };
  header_cases: Array<{ name: string; counts: boolean }>;
  pick_cases: Array<{ headers: string[]; expect: string | null }>;
  first_segment_cases: Array<{ url: string; expect: string }>;
  segment_redaction_cases: Array<{ segment: string; redacted: boolean }>;
  host_cases: Array<{ url: string; expect: string }>;
  cases: Array<{
    name: string;
    url: string;
    method: string;
    headers: Record<string, string>;
    expect: { host: string; first_segment: string; method: string; header_name: string } | null;
  }>;
}
const fixture: Fixture = JSON.parse(readFileSync(FIXTURE_PATH, "utf8"));

const OBS_URL = "https://api.test/v1/wrap/egress-observations";

beforeEach(() => {
  _resetWarnedForTests();
  delete process.env.KNOXCALL_INTERCEPT;
  delete process.env.KNOXCALL_OBSERVE_UNCOVERED;
});
afterEach(() => {
  delete process.env.KNOXCALL_INTERCEPT;
  delete process.env.KNOXCALL_OBSERVE_UNCOVERED;
  vi.useRealTimers();
  vi.restoreAllMocks();
});

// ── 1. the classifier: shared fixtures ───────────────────────────────────────

describe("egress observations — shared fixtures", () => {
  it("the fixture is non-trivial and the SDK's lists are the fixture's lists", () => {
    expect(fixture.header_cases.length).toBeGreaterThan(20);
    expect(fixture.cases.length).toBeGreaterThan(3);
    expect([...CREDENTIAL_HEADER_ALLOWLIST]).toEqual(fixture.credential_headers.allowlist);
    expect([...CREDENTIAL_HEADER_SUFFIXES]).toEqual(fixture.credential_headers.suffixes);
  });

  for (const c of fixture.header_cases) {
    it(`header ${JSON.stringify(c.name)} ${c.counts ? "counts" : "does not count"}`, () => {
      expect(isCredentialHeaderName(c.name)).toBe(c.counts);
    });
  }

  for (const c of fixture.pick_cases) {
    it(`pick among ${JSON.stringify(c.headers)} → ${JSON.stringify(c.expect)}`, () => {
      expect(credentialHeaderName(Object.fromEntries(c.headers.map((h) => [h, "value"])))).toBe(c.expect);
    });
  }

  for (const c of fixture.first_segment_cases) {
    it(`first segment of ${c.url} → ${c.expect}`, () => {
      expect(observationFirstSegment(c.url)).toBe(c.expect);
    });
  }

  for (const c of fixture.segment_redaction_cases) {
    it(`segment ${c.segment.slice(0, 40)} ${c.redacted ? "is reported as /" : "passes unchanged"}`, () => {
      expect(firstSegmentLooksLikeCredential(c.segment)).toBe(c.redacted);
    });
  }

  for (const c of fixture.host_cases) {
    it(`host of ${c.url} → ${c.expect}`, () => {
      expect(normaliseHost(new URL(c.url).hostname)).toBe(c.expect);
    });
  }

  for (const c of fixture.cases) {
    it(c.name, () => {
      const got = observationFor(c.url, c.method, c.headers);
      if (c.expect === null) {
        expect(got).toBeNull();
      } else {
        expect(got).toEqual({ host: c.expect.host, firstSegment: c.expect.first_segment, method: c.expect.method, headerName: c.expect.header_name });
        // Names, never values: no header VALUE from the case appears anywhere in what is recorded.
        for (const v of Object.values(c.headers)) {
          if (v.trim()) expect(JSON.stringify(got)).not.toContain(v);
        }
      }
    });
  }
});

// ── 2. the reporter ──────────────────────────────────────────────────────────

function obs(i: number | string, over: Partial<{ method: string; seg: string; header: string }> = {}) {
  return { host: `h${i}.example`, firstSegment: over.seg ?? "/v1", method: over.method ?? "GET", headerName: over.header ?? "authorization" };
}

function makeReporter(over: Partial<ConstructorParameters<typeof EgressObservationReporter>[0]> = {}) {
  const calls: EgressObservation[][] = [];
  const report = vi.fn(async (o: EgressObservation[]): Promise<EgressObservationsReport> => {
    calls.push(o);
    return { accepted: o.length, dropped: 0, reasons: {} };
  });
  const reporter = new EgressObservationReporter({ report, random: () => 0.5, ...over });
  return { reporter, report, calls };
}

describe("EgressObservationReporter", () => {
  it("aggregates by (host, first segment, method, header) with counts and first/last seen in ISO-8601 UTC", async () => {
    let t = 1_700_000_000_000;
    const { reporter, calls } = makeReporter({ now: () => t });
    reporter.record(obs(1));
    t += 1000;
    reporter.record(obs(1));
    t += 1000;
    reporter.record(obs(1));
    reporter.record(obs(1, { method: "POST" }));
    reporter.record(obs(1, { seg: "/v2" }));
    reporter.record(obs(1, { header: "x-api-key" }));
    expect(reporter.size).toBe(4);
    await reporter.flush();
    expect(calls).toHaveLength(1);
    const first = calls[0][0];
    expect(first).toEqual({
      host: "h1.example", first_segment: "/v1", method: "GET", header_name: "authorization", count: 3,
      first_seen: "2023-11-14T22:13:20.000Z", last_seen: "2023-11-14T22:13:22.000Z",
    });
    for (const o of calls[0]) {
      expect(new Date(o.first_seen).toISOString()).toBe(o.first_seen);
      expect(o.count).toBeGreaterThan(0);
    }
    expect(reporter.size).toBe(0);
  });

  it("flushes immediately when 200 distinct keys accumulate, and never more than 200 per request", async () => {
    const { reporter, calls } = makeReporter();
    for (let i = 0; i < 199; i++) reporter.record(obs(i));
    expect(calls).toHaveLength(0);
    reporter.record(obs(199));
    await vi.waitFor(() => expect(calls).toHaveLength(1));
    expect(calls[0]).toHaveLength(200);

    const big = makeReporter({ flushAtKeys: 10_000 });
    for (let i = 0; i < 450; i++) big.reporter.record(obs(i));
    await big.reporter.flush();
    expect(big.calls.map((c) => c.length)).toEqual([200, 200, 50]);
  });

  it("flushes on a jittered 60 s timer that does not keep the process alive", async () => {
    vi.useFakeTimers();
    const unref = vi.fn();
    const setTimeoutImpl = ((fn: () => void, ms: number) => {
      const t = setTimeout(fn, ms) as unknown as { unref?: () => void };
      t.unref = unref;
      return t;
    }) as unknown as typeof setTimeout;
    const { reporter, calls } = makeReporter({ setTimeoutImpl, random: () => 1 }); // +10% jitter → 66 s
    reporter.record(obs(1));
    expect(unref).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(65_999);
    expect(calls).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(1);
    expect(calls).toHaveLength(1);
    // Nothing pending → the timer is not re-armed until the next record.
    await vi.advanceTimersByTimeAsync(200_000);
    expect(calls).toHaveLength(1);
    reporter.record(obs(2));
    await vi.advanceTimersByTimeAsync(66_000);
    expect(calls).toHaveLength(2);
  });

  it("holds at most 1 000 distinct keys; beyond that new keys are dropped with one warning", () => {
    const warn = vi.spyOn(process, "emitWarning").mockImplementation(() => undefined);
    const { reporter } = makeReporter({ flushAtKeys: 10_000 });
    for (let i = 0; i < 1_005; i++) reporter.record(obs(i));
    expect(reporter.size).toBe(1_000);
    reporter.record(obs(3)); // an EXISTING key still counts
    expect(reporter.pending().find((o) => o.host === "h3.example")?.count).toBe(2);
    expect(warn).toHaveBeenCalledTimes(1);
    expect(String(warn.mock.calls[0][0])).toContain("1000");
  });

  it("a 403 stops reporting for the life of the reporter, warned once; later records are dropped at the door", async () => {
    const warn = vi.spyOn(process, "emitWarning").mockImplementation(() => undefined);
    const report = vi.fn(async () => {
      throw Object.assign(new Error("insufficient scope"), { status: 403 });
    });
    const reporter = new EgressObservationReporter({ report });
    reporter.record(obs(1));
    await reporter.flush();
    expect(reporter.forbidden).toBe(true);
    expect(warn).toHaveBeenCalledTimes(1);
    expect(String(warn.mock.calls[0][0])).toContain("routes:read");
    reporter.record(obs(2));
    expect(reporter.size).toBe(0);
    await reporter.flush();
    await reporter.stop();
    expect(report).toHaveBeenCalledTimes(1);
  });

  it("any other failure drops the batch with one warning, never retries it, and does not stop later flushes", async () => {
    const warn = vi.spyOn(process, "emitWarning").mockImplementation(() => undefined);
    let fail = true;
    const calls: EgressObservation[][] = [];
    const report = vi.fn(async (o: EgressObservation[]) => {
      if (fail) throw new TypeError("fetch failed: ECONNREFUSED");
      calls.push(o);
      return { accepted: o.length, dropped: 0, reasons: {} };
    });
    const reporter = new EgressObservationReporter({ report });
    reporter.record(obs(1));
    await reporter.flush();
    expect(report).toHaveBeenCalledTimes(1);
    expect(reporter.size).toBe(0); // dropped, not held for a retry
    expect(warn).toHaveBeenCalledTimes(1);
    expect(reporter.forbidden).toBe(false);
    fail = false;
    reporter.record(obs(2));
    await reporter.flush();
    expect(calls).toEqual([[expect.objectContaining({ host: "h2.example" })]]);
    reporter.record(obs(3));
    fail = true;
    await reporter.flush();
    expect(warn).toHaveBeenCalledTimes(1); // warned once per process, not per failure
  });

  it("onFlush reports the server's counts per accepted request; a throwing hook never breaks the reporter", async () => {
    const onFlush = vi.fn(() => {
      throw new Error("hook bug");
    });
    const report = vi.fn(async (o: EgressObservation[]) => ({ accepted: o.length - 1, dropped: 1, reasons: { unknown_host: 1 } }));
    const reporter = new EgressObservationReporter({ report, onFlush });
    reporter.record(obs(1));
    reporter.record(obs(2));
    await reporter.flush();
    expect(onFlush).toHaveBeenCalledWith({ accepted: 1, dropped: 1 });
    expect(reporter.size).toBe(0);
  });

  it("flush is single-flight and stop() flushes once more, after which records are ignored", async () => {
    let resolve!: (v: EgressObservationsReport) => void;
    const report = vi.fn(() => new Promise<EgressObservationsReport>((r) => (resolve = r)));
    const reporter = new EgressObservationReporter({ report });
    reporter.record(obs(1));
    const a = reporter.flush();
    const b = reporter.flush();
    expect(a).toBe(b);
    resolve({ accepted: 1, dropped: 0, reasons: {} });
    await a;
    expect(report).toHaveBeenCalledTimes(1);

    reporter.record(obs(2));
    const stopping = reporter.stop();
    resolve({ accepted: 1, dropped: 0, reasons: {} });
    await stopping;
    expect(report).toHaveBeenCalledTimes(2);
    expect(reporter.stopped).toBe(true);
    reporter.record(obs(3));
    expect(reporter.size).toBe(0);
  });
});

// ── 3. the seams ─────────────────────────────────────────────────────────────

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
const HUBSPOT_ROOT = entry({ host: "api.hubapi.com", slug: "hubspot" });

interface StubOptions {
  manifest?: InterceptManifestRoute[];
  /** Per-call responder for the observations endpoint. Default: 202 accepting everything. */
  observations?: (seen: Seen, n: number) => Response | Error | undefined;
}

/** The mock KnoxCall: records every call, serves the manifest, the data plane and the observations endpoint. */
function makeServer(seen: Seen[], opts: StubOptions = {}): typeof fetch {
  let obsCalls = 0;
  return async (input, init) => {
    const url = typeof input === "string" ? input : (input as Request).url;
    const headers: Record<string, string> = {};
    if (init?.headers) for (const [k, v] of Object.entries(init.headers as Record<string, string>)) headers[k.toLowerCase()] = v;
    const rec: Seen = { url, method: init?.method ?? "GET", headers, body: typeof init?.body === "string" ? init.body : undefined };
    seen.push(rec);
    if (url.startsWith("https://api.test/v1/wrap/intercept-manifest")) {
      const routes = opts.manifest ?? [];
      return json(200, { data: { version: `sha256:${routes.map((r) => r.slug).join(",") || "empty"}`, ttl_seconds: 60, environment: "production", sandbox: false, routes }, meta: { request_id: "m" } });
    }
    if (url === OBS_URL) {
      const r = opts.observations?.(rec, ++obsCalls);
      if (r instanceof Error) throw r;
      if (r) return r;
      const n = (JSON.parse(rec.body ?? "{}").observations as unknown[] | undefined)?.length ?? 0;
      return json(202, { data: { accepted: n, dropped: 0, reasons: {} }, meta: { request_id: "o" } });
    }
    return json(200, { ok: true });
  };
}

function makeClient(fetchImpl: typeof fetch, extra: Record<string, unknown> = {}) {
  return new KnoxCall({
    tenant: "acme", baseUrl: "https://api.test", proxyBaseUrl: "https://acme.test",
    apiKey: "kc_live_x", sandbox: false, fetchImpl, ...extra,
  });
}

const obsCalls = (seen: Seen[]) => seen.filter((s) => s.url === OBS_URL);
const bodyOf = (s: Seen) => JSON.parse(s.body ?? "{}") as { sdk: string; observations: EgressObservation[] };
const settle = () => new Promise<void>((r) => setImmediate(r));

function makeTarget() {
  const original = vi.fn(async () => new Response("ORIGINAL"));
  return { target: { fetch: original as unknown as typeof fetch }, original };
}

describe("wrap.intercept — uncovered-egress observations (fetch stack)", () => {
  it("a direct `unlisted` request carrying Authorization is recorded and flushed with exactly the contract fields — the value and the query never reach the wire", async () => {
    const seen: Seen[] = [];
    const client = makeClient(makeServer(seen, { manifest: [HUBSPOT_ROOT] }));
    const { target, original } = makeTarget();
    const onObservationFlush = vi.fn();
    const handle = client.wrap.intercept({ hosts: ["api.resend.com"], stacks: ["fetch"], target, onObservationFlush });
    await handle.ready;

    const res = await target.fetch("https://a.klaviyo.com/api/profiles/?x=1&token=leak-in-query", {
      method: "post",
      headers: { Authorization: "Klaviyo-API-Key pk_live_should_never_appear", "Content-Type": "application/json" },
      body: '{"email":"never-appears@example.com"}',
    });
    expect(await res.text()).toBe("ORIGINAL"); // the application's request is untouched
    expect(original).toHaveBeenCalledTimes(1);
    await target.fetch("https://a.klaviyo.com/api/profiles/?x=2", { method: "POST", headers: { authorization: "Klaviyo-API-Key pk_live_2" } });
    expect(obsCalls(seen)).toHaveLength(0); // nothing leaves the process on the request's own path

    handle.uninstall();
    await vi.waitFor(() => expect(obsCalls(seen)).toHaveLength(1));
    const call = obsCalls(seen)[0];
    expect(call.method).toBe("POST");
    expect(call.headers["authorization"]).toBe("Bearer kc_live_x"); // the SDK's OWN credential
    expect(call.headers["x-idempotency-key"]).toBeTruthy(); // the shared request() path
    const body = bodyOf(call);
    expect(body.sdk).toBe(`node/${SDK_VERSION}`); // the value itself is pinned by tests/coverage/sdk-version-agreement.test.ts
    expect(body.observations).toEqual([
      { host: "a.klaviyo.com", first_segment: "/api", method: "POST", header_name: "authorization", count: 2, first_seen: expect.any(String), last_seen: expect.any(String) },
    ]);
    expect(new Date(body.observations[0].first_seen).toISOString()).toBe(body.observations[0].first_seen);
    for (const leak of ["pk_live", "x=1", "x=2", "leak-in-query", "never-appears", "profiles"]) {
      expect(call.body).not.toContain(leak);
    }
    expect(onObservationFlush).toHaveBeenCalledWith({ accepted: 1, dropped: 0 });
  });

  it("nothing is recorded without a credential header, for own hosts, route-around, rerouted (route + ephemeral) or kill-switched requests", async () => {
    const seen: Seen[] = [];
    const client = makeClient(makeServer(seen, { manifest: [HUBSPOT_ROOT] }));
    const { target, original } = makeTarget();
    const handle = client.wrap.intercept({ hosts: ["api.resend.com", "api.stripe.com"], stacks: ["fetch"], target });
    await handle.ready;

    await target.fetch("https://unlisted.example/x", { headers: { accept: "*/*", "x-request-id": "1" } }); // no credential
    await target.fetch("https://api.test/v1/routes", { headers: { authorization: "Bearer kc_live_x" } }); // own_host
    await target.fetch("https://acme.knoxcall.com/x", { headers: { authorization: "Bearer kc_live_x" } }); // platform host
    await target.fetch("https://api.stripe.com/v1/tokens", { method: "POST", headers: { authorization: "Bearer sk_live_x" }, body: "card" }); // route_around
    expect(original).toHaveBeenCalledTimes(4);
    await target.fetch("https://api.hubapi.com/crm/v3/objects", { headers: { authorization: "Bearer t" } }); // route
    await target.fetch("https://api.resend.com/emails", { method: "POST", headers: { authorization: "Bearer re" }, body: "{}" }); // ephemeral
    process.env.KNOXCALL_INTERCEPT = "off";
    await target.fetch("https://unlisted.example/x", { headers: { authorization: "Bearer u" } }); // kill_switch
    delete process.env.KNOXCALL_INTERCEPT;

    handle.uninstall();
    await settle();
    await settle();
    expect(obsCalls(seen)).toHaveLength(0);
  });

  it("the flush rides the SDK's own request() and is never itself intercepted or observed, even when the SDK's fetch IS the patched global", async () => {
    const seen: Seen[] = [];
    const server = makeServer(seen, { manifest: [HUBSPOT_ROOT] });
    const target = { fetch: server };
    // The SDK's own calls go through the patched target: the manifest poll and
    // the observation report both carry Authorization to api.test.
    const client = makeClient((input, init) => target.fetch(input, init));
    const handle = client.wrap.intercept({ hosts: ["api.resend.com"], stacks: ["fetch"], target });
    await handle.ready;
    expect(target.fetch).not.toBe(server);

    await target.fetch("https://a.klaviyo.com/api/x", { headers: { "x-api-key": "k" } });
    handle.uninstall();
    await vi.waitFor(() => expect(obsCalls(seen)).toHaveLength(1));
    const body = bodyOf(obsCalls(seen)[0]);
    expect(body.observations.map((o) => o.host)).toEqual(["a.klaviyo.com"]); // not api.test, not the report itself
    expect(seen.filter((s) => s.url === "https://api.test/v1/proxy")).toHaveLength(0);
    expect(seen.filter((s) => s.url.startsWith("https://acme.test/"))).toHaveLength(0);
  });

  it("200 distinct keys flush immediately, in the background", async () => {
    const seen: Seen[] = [];
    const client = makeClient(makeServer(seen));
    const { target } = makeTarget();
    const handle = client.wrap.intercept({ stacks: ["fetch"], target });
    await handle.ready;
    for (let i = 0; i < 200; i++) await target.fetch(`https://h${i}.example/v1/x`, { headers: { authorization: "Bearer x" } });
    await vi.waitFor(() => expect(obsCalls(seen)).toHaveLength(1));
    expect(bodyOf(obsCalls(seen)[0]).observations).toHaveLength(200);
    handle.uninstall();
  });

  it("the timer flushes about once a minute (fake timers)", async () => {
    vi.useFakeTimers();
    const seen: Seen[] = [];
    const client = makeClient(makeServer(seen));
    const { target } = makeTarget();
    const handle = client.wrap.intercept({ stacks: ["fetch"], target });
    await handle.ready;
    await target.fetch("https://h.example/v1/x", { headers: { authorization: "Bearer x" } });
    expect(obsCalls(seen)).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(66_500); // 60 s + the 10 % jitter ceiling
    expect(obsCalls(seen)).toHaveLength(1);
    handle.uninstall();
  });

  it("opt-out: `observeUncovered: false`, KNOXCALL_OBSERVE_UNCOVERED=off and KNOXCALL_INTERCEPT=off each disable it", async () => {
    const run = async (opts: Record<string, unknown>, env?: [string, string]) => {
      const seen: Seen[] = [];
      const client = makeClient(makeServer(seen));
      const { target, original } = makeTarget();
      if (env) process.env[env[0]] = env[1];
      const handle = client.wrap.intercept({ stacks: ["fetch"], target, ...opts });
      await handle.ready;
      await target.fetch("https://h.example/v1/x", { headers: { authorization: "Bearer x" } });
      expect(original).toHaveBeenCalledTimes(1);
      handle.uninstall();
      await settle();
      await settle();
      if (env) delete process.env[env[0]];
      return obsCalls(seen).length;
    };
    expect(await run({ observeUncovered: false })).toBe(0);
    expect(await run({}, ["KNOXCALL_OBSERVE_UNCOVERED", "off"])).toBe(0);
    expect(await run({}, ["KNOXCALL_OBSERVE_UNCOVERED", "FALSE"])).toBe(0);
    expect(await run({}, ["KNOXCALL_OBSERVE_UNCOVERED", "0"])).toBe(0);
    expect(await run({}, ["KNOXCALL_INTERCEPT", "off"])).toBe(0);
    expect(await run({})).toBe(1); // the control: on by default
  });

  it("a 403 from the endpoint stops reporting for the handle with one warning", async () => {
    const warn = vi.spyOn(process, "emitWarning").mockImplementation(() => undefined);
    const seen: Seen[] = [];
    const client = makeClient(makeServer(seen, {
      observations: () => json(403, { error: { type: "forbidden", message: "insufficient scope", request_id: "r" } }),
    }));
    const { target, original } = makeTarget();
    const handle = client.wrap.intercept({ stacks: ["fetch"], target });
    await handle.ready;
    for (let i = 0; i < 200; i++) await target.fetch(`https://h${i}.example/v1/x`, { headers: { authorization: "Bearer x" } });
    await vi.waitFor(() => expect(obsCalls(seen)).toHaveLength(1));
    await vi.waitFor(() => expect(warn).toHaveBeenCalledTimes(1));
    expect(String(warn.mock.calls[0][0])).toContain("routes:read");
    for (let i = 0; i < 200; i++) await target.fetch(`https://k${i}.example/v1/x`, { headers: { authorization: "Bearer x" } });
    expect(original).toHaveBeenCalledTimes(400); // the application never noticed
    handle.uninstall();
    await settle();
    await settle();
    expect(obsCalls(seen)).toHaveLength(1);
    expect(warn).toHaveBeenCalledTimes(1);
  });

  it("a network error is dropped with one warning and never surfaces into the application's call; later flushes still go", async () => {
    const warn = vi.spyOn(process, "emitWarning").mockImplementation(() => undefined);
    const seen: Seen[] = [];
    let fail = true;
    const client = makeClient(makeServer(seen, {
      observations: () => (fail ? new TypeError("fetch failed: ECONNREFUSED") : undefined),
    }), { retry: { maxAttempts: 1 } });
    const { target } = makeTarget();
    const handle = client.wrap.intercept({ stacks: ["fetch"], target });
    await handle.ready;
    for (let i = 0; i < 200; i++) {
      const r = await target.fetch(`https://h${i}.example/v1/x`, { headers: { authorization: "Bearer x" } });
      expect(await r.text()).toBe("ORIGINAL");
    }
    await vi.waitFor(() => expect(obsCalls(seen)).toHaveLength(1));
    await vi.waitFor(() => expect(warn).toHaveBeenCalledTimes(1));
    fail = false;
    await target.fetch("https://later.example/v1/x", { headers: { authorization: "Bearer x" } });
    handle.uninstall();
    await vi.waitFor(() => expect(obsCalls(seen)).toHaveLength(2));
    expect(bodyOf(obsCalls(seen)[1]).observations.map((o) => o.host)).toEqual(["later.example"]); // the failed batch was not retried
    expect(warn).toHaveBeenCalledTimes(1);
  });
});

describe("wrap.intercept — uncovered-egress observations (node:http stack)", () => {
  function fakeHttpModule(): HttpModuleLike & { request: ReturnType<typeof vi.fn>; get: ReturnType<typeof vi.fn> } {
    const sentinel = () => ({ original: true });
    return { request: vi.fn((..._a: unknown[]) => sentinel()), get: vi.fn((..._a: unknown[]) => sentinel()) };
  }

  it("a direct `unlisted` http.request carrying a credential header is recorded; the reroute path is not", async () => {
    const seen: Seen[] = [];
    const client = makeClient(makeServer(seen, { manifest: [HUBSPOT_ROOT] }));
    const mod = fakeHttpModule();
    const originalRequest = mod.request;
    const originalGet = mod.get;
    const handle = client.wrap.intercept({ stacks: ["http"], httpModules: { https: mod } });
    await handle.ready;
    expect(mod.request).not.toBe(originalRequest);

    const r = mod.request({ hostname: "a.klaviyo.com", path: "/api/profiles/?x=1", method: "post", headers: { "X-Vendor-Api-Key": "vk_never" } });
    expect(r).toEqual({ original: true });
    mod.get("https://plain.example/health"); // no credential
    mod.request({ hostname: "api.test", path: "/v1/x", headers: { Authorization: "Bearer kc" } }); // own_host
    expect(originalRequest).toHaveBeenCalledTimes(2); // untouched
    expect(originalGet).toHaveBeenCalledTimes(1);
    handle.uninstall();
    await vi.waitFor(() => expect(obsCalls(seen)).toHaveLength(1));
    const body = bodyOf(obsCalls(seen)[0]);
    expect(body.observations).toEqual([
      expect.objectContaining({ host: "a.klaviyo.com", first_segment: "/api", method: "POST", header_name: "x-vendor-api-key", count: 1 }),
    ]);
    expect(obsCalls(seen)[0].body).not.toContain("vk_never");
    expect(obsCalls(seen)[0].body).not.toContain("x=1");
  });
});

describe("wrap.reportEgressObservations", () => {
  it("POSTs {sdk, observations} to /v1/wrap/egress-observations through request() and unwraps the envelope", async () => {
    const seen: Seen[] = [];
    const client = makeClient(makeServer(seen, {
      observations: () => json(202, { data: { accepted: 1, dropped: 1, reasons: { unknown_host: 1 } }, meta: { request_id: "o" } }),
    }));
    const observations: EgressObservation[] = [
      { host: "h.example", first_segment: "/v1", method: "GET", header_name: "authorization", count: 3, first_seen: "2026-09-26T00:00:00.000Z", last_seen: "2026-09-26T00:01:00.000Z" },
    ];
    const res = await client.wrap.reportEgressObservations(observations);
    expect(res).toEqual({ accepted: 1, dropped: 1, reasons: { unknown_host: 1 } });
    const call = obsCalls(seen)[0];
    expect(call.method).toBe("POST");
    expect(bodyOf(call)).toEqual({ sdk: `node/${SDK_VERSION}`, observations });
    expect(call.headers["authorization"]).toBe("Bearer kc_live_x");

    await client.wrap.reportEgressObservations(observations, { sdk: "custom/9.9.9" });
    expect(bodyOf(obsCalls(seen)[1]).sdk).toBe("custom/9.9.9");
  });

  it("wrap.fetch({ routes: 'auto' }) builds the reporter and stop() tears it down without a request when nothing was recorded", async () => {
    const seen: Seen[] = [];
    const wrapped = makeClient(makeServer(seen)).wrap.fetch({ routes: "auto", directFetch: (async () => new Response("D")) as unknown as typeof fetch });
    await wrapped.ready;
    await wrapped("https://api.test/v1/routes", { headers: { authorization: "Bearer x" } }); // own host: direct, never observed
    wrapped.stop();
    await settle();
    await settle();
    expect(obsCalls(seen)).toHaveLength(0);
  });
});
