// The route-aware decision table, driven by the CROSS-LANGUAGE fixtures in
// sdk/fixtures/intercept-resolver.json (route-aware-interception-plan.md §2.2).
// Node is the reference; python/go/php/ruby run the same file. A case added
// there must pass here first.
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { resolveIntercept, rebasePath, normaliseHost, entriesForHost, isPlatformHost } from "../src/intercept-resolver.js";
import { DEFAULT_ROUTE_AROUND } from "../src/wrap-transport.js";
import type { InterceptManifest } from "../src/index.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURE_PATH = join(HERE, "..", "..", "fixtures", "intercept-resolver.json");

interface FixtureCase {
  name: string;
  url: string;
  method: string;
  hosts: string[] | "all";
  kill_switch: boolean;
  require_context: boolean;
  in_context: boolean;
  manifest?: InterceptManifest | null;
  expect: { mode: string; reason: string; slug?: string; path?: string };
}
interface Fixture {
  own_hosts: string[];
  manifest: InterceptManifest;
  cases: FixtureCase[];
}

const fixture: Fixture = JSON.parse(readFileSync(FIXTURE_PATH, "utf8"));

describe("intercept resolver — shared fixtures", () => {
  it("the fixture file is non-trivial", () => {
    expect(fixture.cases.length).toBeGreaterThan(15);
    expect(fixture.manifest.routes.length).toBeGreaterThan(3);
  });

  for (const c of fixture.cases) {
    it(c.name, () => {
      const manifest = c.manifest === undefined ? fixture.manifest : c.manifest;
      const decision = resolveIntercept({
        url: c.url,
        method: c.method,
        hosts: c.hosts === "all" ? "all" : new Set(c.hosts.map(normaliseHost)),
        manifest,
        ownHosts: new Set(fixture.own_hosts.map(normaliseHost)),
        routeAround: DEFAULT_ROUTE_AROUND,
        killSwitch: c.kill_switch,
        requireContext: c.require_context,
        inContext: c.in_context,
      });
      expect(decision.mode, `mode for ${c.url}`).toBe(c.expect.mode);
      expect(decision.reason, `reason for ${c.url}`).toBe(c.expect.reason);
      if (c.expect.slug !== undefined) expect(decision.slug).toBe(c.expect.slug);
      if (c.expect.path !== undefined) expect(decision.path).toBe(c.expect.path);
      if (c.expect.mode !== "route") {
        expect(decision.slug).toBeUndefined();
        expect(decision.path).toBeUndefined();
      }
    });
  }
});

describe("intercept resolver — helpers", () => {
  it("rebasePath is segment-aware and keeps a leading slash", () => {
    expect(rebasePath("/crm/v3/objects", "/crm/v3")).toBe("/objects");
    expect(rebasePath("/crm/v3", "/crm/v3")).toBe("/");
    expect(rebasePath("/crm/v30/x", "/crm/v3")).toBeNull();
    expect(rebasePath("/anything", "/")).toBe("/anything");
    expect(rebasePath("", "/")).toBe("/");
    expect(rebasePath("x", "/")).toBe("/x");
  });

  it("normaliseHost lower-cases, strips a trailing dot and IPv6 brackets", () => {
    expect(normaliseHost(" API.Example. ")).toBe("api.example");
    expect(normaliseHost("[::1]")).toBe("::1");
    expect(normaliseHost("")).toBe("");
  });

  it("isPlatformHost covers knoxcall.com and every subdomain, nothing else", () => {
    expect(isPlatformHost("knoxcall.com")).toBe(true);
    expect(isPlatformHost("acme.knoxcall.com")).toBe(true);
    expect(isPlatformHost("x.wrap.knoxcall.com")).toBe(true);
    expect(isPlatformHost("knoxcall.com.evil.example")).toBe(false);
    expect(isPlatformHost("notknoxcall.com")).toBe(false);
  });

  it("entriesForHost orders longest base_path first, then slug, whatever order the manifest arrived in", () => {
    const m: InterceptManifest = {
      version: "v", ttl_seconds: 60, environment: "production", sandbox: false,
      routes: [
        { host: "h.example", base_path: "/", slug: "z", route_id: "1", requires_clients: false, allowed_methods: null, updated_at: null },
        { host: "h.example", base_path: "/a/b", slug: "deep", route_id: "2", requires_clients: false, allowed_methods: null, updated_at: null },
        { host: "H.EXAMPLE.", base_path: "/", slug: "a", route_id: "3", requires_clients: false, allowed_methods: null, updated_at: null },
        { host: "other.example", base_path: "/", slug: "o", route_id: "4", requires_clients: false, allowed_methods: null, updated_at: null },
      ],
    };
    expect(entriesForHost(m, "h.example").map((e) => e.slug)).toEqual(["deep", "a", "z"]);
    expect(entriesForHost(null, "h.example")).toEqual([]);
  });

  it("a port in the request URL never affects the host match", () => {
    const m: InterceptManifest = {
      version: "v", ttl_seconds: 60, environment: "production", sandbox: false,
      routes: [{ host: "h.example", base_path: "/", slug: "h", route_id: "1", requires_clients: false, allowed_methods: null, updated_at: null }],
    };
    const d = resolveIntercept({
      url: "https://h.example:8443/x?y=1", method: "GET", hosts: new Set(), manifest: m, ownHosts: new Set(),
      routeAround: [], killSwitch: false, requireContext: false, inContext: false,
    });
    expect(d).toMatchObject({ mode: "route", slug: "h", path: "/x?y=1" });
  });
});
