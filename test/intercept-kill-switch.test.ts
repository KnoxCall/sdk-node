// The KNOXCALL_INTERCEPT off-grammar, driven by the CROSS-LANGUAGE fixture in
// sdk/fixtures/intercept-kill-switch.json (PARITY §21.1).
//
// Five SDKs hand-write this predicate and already agree character for
// character. A sixth spelling accepted here would be a kill switch that works
// in four SDKs and silently does nothing in the fifth -- the worst shape a kill
// switch can have, because the operator believes interception is off.
import { describe, it, expect, afterEach } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { interceptKillSwitch } from "../src/index.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURE = JSON.parse(
  readFileSync(join(HERE, "..", "..", "fixtures", "intercept-kill-switch.json"), "utf8"),
) as { cases: Array<{ name: string; value: string | null; expect: boolean }> };

afterEach(() => {
  delete process.env.KNOXCALL_INTERCEPT;
});

describe("KNOXCALL_INTERCEPT off-grammar — shared fixtures", () => {
  for (const c of FIXTURE.cases) {
    it(`${c.name} -> ${c.expect}`, () => {
      if (c.value === null) delete process.env.KNOXCALL_INTERCEPT;
      else process.env.KNOXCALL_INTERCEPT = c.value;
      expect(interceptKillSwitch()).toBe(c.expect);
    });
  }

  it("the fixture is not vacuous", () => {
    expect(new Set(FIXTURE.cases.map((c) => c.expect))).toEqual(new Set([true, false]));
  });
});
