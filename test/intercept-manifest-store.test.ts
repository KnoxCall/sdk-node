// The SDK-side manifest store (route-aware-interception-plan.md §2.5): TTL
// polling with jitter, single-flight, stale-keep on failure, permission
// refusals as "no manifest" with one warning, rate-limited out-of-cycle
// refreshes, and the diff hook.
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { InterceptManifestStore, type ManifestRefreshInfo } from "../src/intercept-manifest-store.js";
import { PermissionDeniedError, APIConnectionError } from "../src/error.js";
import { _resetWarnedForTests } from "../src/warn.js";
import type { InterceptManifest, InterceptManifestRoute } from "../src/index.js";

function entry(host: string, slug: string, base = "/"): InterceptManifestRoute {
  return { host, base_path: base, slug, route_id: `id-${slug}`, requires_clients: false, allowed_methods: null, updated_at: null };
}
function manifest(routes: InterceptManifestRoute[], version = `v:${routes.map((r) => r.slug).join(",")}`): InterceptManifest {
  return { version, ttl_seconds: 60, environment: "production", sandbox: false, routes };
}

beforeEach(() => {
  vi.useFakeTimers();
  _resetWarnedForTests();
});
afterEach(() => {
  vi.useRealTimers();
});

/** Let pending promise continuations run without advancing the fake clock. */
const flush = async () => {
  for (let i = 0; i < 5; i++) await Promise.resolve();
};

describe("InterceptManifestStore", () => {
  it("start() fetches once, ready resolves, get() serves the manifest, onRefresh reports every entry as added", async () => {
    const fetchManifest = vi.fn(async () => manifest([entry("a.example", "a")]));
    const onRefresh = vi.fn();
    const store = new InterceptManifestStore({ fetchManifest, onRefresh });
    store.start();
    store.start(); // idempotent
    await store.ready;
    expect(fetchManifest).toHaveBeenCalledTimes(1);
    expect(store.get()?.routes.map((r) => r.slug)).toEqual(["a"]);
    expect(store.version).toBe("v:a");
    expect(onRefresh).toHaveBeenCalledWith(expect.objectContaining({ reason: "start", added: [entry("a.example", "a")], removed: [] }));
    store.stop();
  });

  it("polls again after ttl_seconds (±10% jitter) and reports only the diff", async () => {
    let routes = [entry("a.example", "a")];
    const fetchManifest = vi.fn(async () => manifest(routes));
    const onRefresh = vi.fn();
    const store = new InterceptManifestStore({ fetchManifest, onRefresh, random: () => 0.5 }); // jitter = 1.0
    store.start();
    await store.ready;
    routes = [entry("b.example", "b")];
    await vi.advanceTimersByTimeAsync(59_000);
    expect(fetchManifest).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(2_000);
    await flush();
    expect(fetchManifest).toHaveBeenCalledTimes(2);
    expect(store.get()?.routes.map((r) => r.slug)).toEqual(["b"]);
    expect(onRefresh).toHaveBeenLastCalledWith(expect.objectContaining({ reason: "poll", added: [entry("b.example", "b")], removed: [entry("a.example", "a")] }));
    store.stop();
  });

  it("an unchanged version fires no onRefresh", async () => {
    const fetchManifest = vi.fn(async () => manifest([entry("a.example", "a")]));
    const onRefresh = vi.fn();
    const store = new InterceptManifestStore({ fetchManifest, onRefresh, random: () => 0.5 });
    store.start();
    await store.ready;
    await vi.advanceTimersByTimeAsync(61_000);
    await flush();
    expect(fetchManifest).toHaveBeenCalledTimes(2);
    expect(onRefresh).toHaveBeenCalledTimes(1);
    store.stop();
  });

  it("a transport fault keeps the last good manifest, reports onError and backs off", async () => {
    let fail = false;
    const fetchManifest = vi.fn(async () => {
      if (fail) throw new APIConnectionError("network error: ECONNRESET");
      return manifest([entry("a.example", "a")]);
    });
    const onError = vi.fn();
    const store = new InterceptManifestStore({ fetchManifest, onError, random: () => 0.5 });
    store.start();
    await store.ready;
    fail = true;
    await vi.advanceTimersByTimeAsync(61_000);
    await flush();
    expect(fetchManifest).toHaveBeenCalledTimes(2);
    expect(store.get()?.routes).toHaveLength(1); // stale-but-valid
    expect(onError).toHaveBeenCalledTimes(1);
    expect(store.lastError).toBeInstanceOf(APIConnectionError);
    // One transient failure does not lengthen the wait: the next poll is still at the TTL…
    await vi.advanceTimersByTimeAsync(61_000);
    await flush();
    expect(fetchManifest).toHaveBeenCalledTimes(3);
    // …the SECOND consecutive failure doubles it (2×TTL): nothing at +60s, a call at +120s.
    await vi.advanceTimersByTimeAsync(61_000);
    await flush();
    expect(fetchManifest).toHaveBeenCalledTimes(3);
    await vi.advanceTimersByTimeAsync(61_000);
    await flush();
    expect(fetchManifest).toHaveBeenCalledTimes(4);
    store.stop();
  });

  it("a permission refusal is 'no manifest': warns once, re-checks slowly, and recovers when the grant appears", async () => {
    let denied = true;
    const fetchManifest = vi.fn(async () => {
      if (denied) throw new PermissionDeniedError("insufficient scope", { status: 403 });
      return manifest([entry("a.example", "a")]);
    });
    const warn = vi.spyOn(process, "emitWarning").mockImplementation(() => undefined);
    const store = new InterceptManifestStore({ fetchManifest, random: () => 0.5 });
    store.start();
    await store.ready;
    expect(store.get()).toBeNull();
    expect(store.permissionDenied).toBe(true);
    expect(warn).toHaveBeenCalledTimes(1);
    // Not re-polled at the TTL…
    await vi.advanceTimersByTimeAsync(5 * 60_000);
    await flush();
    expect(fetchManifest).toHaveBeenCalledTimes(1);
    // …but at 10× the TTL (600 s), and the grant has appeared.
    denied = false;
    await vi.advanceTimersByTimeAsync(301_000);
    await flush();
    expect(fetchManifest).toHaveBeenCalledTimes(2);
    expect(store.permissionDenied).toBe(false);
    expect(store.get()?.routes).toHaveLength(1);
    expect(warn).toHaveBeenCalledTimes(1); // once per process
    warn.mockRestore();
    store.stop();
  });

  it("refresh() is single-flight and rate-limited; force bypasses the gap", async () => {
    let resolveFetch!: (m: InterceptManifest) => void;
    const fetchManifest = vi.fn(() => new Promise<InterceptManifest>((r) => { resolveFetch = r; }));
    const store = new InterceptManifestStore({ fetchManifest, random: () => 0.5, minRefreshGapMs: 5000 });
    const p1 = store.refresh("a", { force: true });
    const p2 = store.refresh("b", { force: true });
    expect(fetchManifest).toHaveBeenCalledTimes(1); // shared in-flight
    resolveFetch(manifest([entry("a.example", "a")]));
    await p1;
    await p2;
    // Inside the gap: no call.
    await store.refresh("hint");
    expect(fetchManifest).toHaveBeenCalledTimes(1);
    // Past the gap: a call.
    await vi.advanceTimersByTimeAsync(5_001);
    const p3 = store.refresh("hint");
    expect(fetchManifest).toHaveBeenCalledTimes(2);
    resolveFetch(manifest([entry("a.example", "a")]));
    await p3;
    // force: always a call.
    const p4 = store.refresh("manual", { force: true });
    expect(fetchManifest).toHaveBeenCalledTimes(3);
    resolveFetch(manifest([]));
    await p4;
    store.stop();
  });

  it("stop() drops the manifest, cancels the poll, and refuses to restart", async () => {
    const fetchManifest = vi.fn(async () => manifest([entry("a.example", "a")]));
    const store = new InterceptManifestStore({ fetchManifest, random: () => 0.5 });
    store.start();
    await store.ready;
    store.stop();
    expect(store.get()).toBeNull();
    await vi.advanceTimersByTimeAsync(10 * 60_000);
    await flush();
    expect(fetchManifest).toHaveBeenCalledTimes(1);
    store.start();
    expect(await store.refresh("x", { force: true })).toBeNull();
    expect(fetchManifest).toHaveBeenCalledTimes(1);
  });

  it("ready resolves even when the first fetch fails, and never rejects", async () => {
    const fetchManifest = vi.fn(async () => { throw new Error("boom"); });
    const store = new InterceptManifestStore({ fetchManifest, random: () => 0.5 });
    store.start();
    await expect(store.ready).resolves.toBeUndefined();
    expect(store.get()).toBeNull();
    store.stop();
  });
});

// The conditional poll (PARITY §21.1 "Conditional poll"), driven by the
// CROSS-LANGUAGE fixture sdk/fixtures/intercept-store-conditional.json: every
// SDK's store walks the same steps against a fake fetch. This is the reference.
interface ConditionalStep {
  name: string;
  forced?: boolean;
  respond: { status: number; manifest?: string };
  expect: {
    fetch_if_none_match: string | null;
    wire_if_none_match: string | null;
    version: string;
    refresh_fired: boolean;
    added?: string[];
    removed?: string[];
  };
}
interface ConditionalFixture {
  manifests: Record<string, InterceptManifest>;
  steps: ConditionalStep[];
}
const HERE = dirname(fileURLToPath(import.meta.url));
const CONDITIONAL_FIXTURE_PATH = join(HERE, "..", "..", "fixtures", "intercept-store-conditional.json");

describe("InterceptManifestStore — conditional poll (shared fixtures)", () => {
  const fixture: ConditionalFixture = JSON.parse(readFileSync(CONDITIONAL_FIXTURE_PATH, "utf8"));

  it("the fixture has the steps this test walks", () => {
    expect(fixture.steps.length).toBeGreaterThanOrEqual(4);
    expect(fixture.steps[0].expect.fetch_if_none_match).toBeNull();
    expect(fixture.steps.some((s) => s.respond.status === 304)).toBe(true);
    expect(fixture.steps.some((s) => s.forced)).toBe(true);
  });

  it("walks every step: the held version rides on every poll after the first (scheduled or forced); a 304 keeps the manifest and fires no onRefresh; a 200 with a new version replaces it and fires the diff", async () => {
    const sent: (string | null)[] = [];
    let respond: ConditionalStep["respond"] = fixture.steps[0].respond;
    const fetchManifest = vi.fn(async ({ ifNoneMatch }: { ifNoneMatch?: string }) => {
      sent.push(ifNoneMatch ?? null);
      if (respond.status === 304) return null;
      return fixture.manifests[respond.manifest!];
    });
    const onRefresh = vi.fn();
    const store = new InterceptManifestStore({ fetchManifest, onRefresh, random: () => 0.5 }); // jitter = 1.0

    for (const [i, step] of fixture.steps.entries()) {
      respond = step.respond;
      onRefresh.mockClear();
      if (i === 0) {
        store.start();
        await store.ready;
      } else if (step.forced) {
        await store.refresh("route_refused", { force: true });
      } else {
        await vi.advanceTimersByTimeAsync(61_000); // one TTL (+jitter 1.0) after the previous answer
        await flush();
      }
      expect(fetchManifest, step.name).toHaveBeenCalledTimes(i + 1);
      expect(sent[i], step.name).toBe(step.expect.fetch_if_none_match);
      expect(store.version, step.name).toBe(step.expect.version);
      expect(store.get()?.version, step.name).toBe(step.expect.version);
      expect(store.lastError, step.name).toBeNull();
      if (step.expect.refresh_fired) {
        expect(onRefresh, step.name).toHaveBeenCalledTimes(1);
        const info = onRefresh.mock.calls[0][0] as ManifestRefreshInfo;
        expect(info.version, step.name).toBe(step.expect.version);
        expect(info.added.map((e) => e.slug), step.name).toEqual(step.expect.added);
        expect(info.removed.map((e) => e.slug), step.name).toEqual(step.expect.removed);
      } else {
        expect(onRefresh, step.name).not.toHaveBeenCalled();
      }
    }
    store.stop();
  });

  it("a 304 is a success: it clears the backoff a run of faults built up and re-arms the poll at one TTL", async () => {
    let mode: "ok" | "fault" | "not_modified" = "ok";
    const fetchManifest = vi.fn(async () => {
      if (mode === "fault") throw new APIConnectionError("network error: ECONNRESET");
      if (mode === "not_modified") return null;
      return manifest([entry("a.example", "a")]);
    });
    const store = new InterceptManifestStore({ fetchManifest, random: () => 0.5 });
    store.start();
    await store.ready;
    mode = "fault";
    await vi.advanceTimersByTimeAsync(61_000); // fault #1 → next at TTL
    await flush();
    await vi.advanceTimersByTimeAsync(61_000); // fault #2 → next at 2×TTL
    await flush();
    expect(fetchManifest).toHaveBeenCalledTimes(3);
    mode = "not_modified";
    await vi.advanceTimersByTimeAsync(121_000); // the 2×TTL wait → a 304
    await flush();
    expect(fetchManifest).toHaveBeenCalledTimes(4);
    expect(store.get()?.routes.map((r) => r.slug)).toEqual(["a"]); // still held
    expect(store.lastError).toBeNull();
    await vi.advanceTimersByTimeAsync(61_000); // back to one TTL, not 4×
    await flush();
    expect(fetchManifest).toHaveBeenCalledTimes(5);
    store.stop();
  });

  it("after a permission refusal nothing is held, so the recovery poll is unconditional again", async () => {
    let denied = false;
    const sent: (string | null)[] = [];
    const fetchManifest = vi.fn(async ({ ifNoneMatch }: { ifNoneMatch?: string }) => {
      sent.push(ifNoneMatch ?? null);
      if (denied) throw new PermissionDeniedError("insufficient scope", { status: 403 });
      return manifest([entry("a.example", "a")]);
    });
    vi.spyOn(process, "emitWarning").mockImplementation(() => undefined);
    const store = new InterceptManifestStore({ fetchManifest, random: () => 0.5 });
    store.start();
    await store.ready;
    denied = true;
    await store.refresh("manual", { force: true });
    expect(sent).toEqual([null, "v:a"]);
    expect(store.version).toBeNull();
    denied = false;
    await store.refresh("manual", { force: true });
    expect(sent[2]).toBeNull();
    expect(store.version).toBe("v:a");
    store.stop();
  });
});
