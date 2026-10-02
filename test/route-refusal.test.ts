// The route-mode refusal predicate, driven by the CROSS-LANGUAGE fixtures in
// sdk/fixtures/route-refusal.json (PARITY §21.1, "Refusal-driven refresh").
// Node is the reference; python/go/php/ruby consume the same cases unchanged.
// Add a case there, and every SDK must pass it.
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { isRouteRefusal } from "../src/route-refusal.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURE_PATH = join(HERE, "..", "..", "fixtures", "route-refusal.json");

interface Case {
  name: string;
  status: number;
  headers: Record<string, string>;
  body: string;
  expect: { refusal: boolean };
}
interface Fixture {
  cases: Case[];
}

const fixture: Fixture = JSON.parse(readFileSync(FIXTURE_PATH, "utf8"));

describe("route refusal predicate — shared fixtures", () => {
  it("has cases in both directions, so a predicate stuck on one answer cannot pass", () => {
    const answers = new Set(fixture.cases.map((c) => c.expect.refusal));
    expect(answers).toEqual(new Set([true, false]));
    expect(fixture.cases.length).toBeGreaterThanOrEqual(10);
  });

  for (const c of fixture.cases) {
    it(c.name, async () => {
      // A 204/304 cannot carry a body; every fixture status can, and does.
      const res = new Response(c.body === "" ? null : c.body, { status: c.status, headers: c.headers });
      expect(await isRouteRefusal(res)).toBe(c.expect.refusal);
      // The caller's body is untouched by the decision: it can still be read.
      expect(res.bodyUsed).toBe(false);
      expect(await res.text()).toBe(c.body);
    });
  }
});
