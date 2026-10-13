// The default-on interception hook (`@knoxcall/sdk/autostart`) and the Node
// half of the adoption contract.
//
// Node's hook cannot be tested the way Python's can — there is no `.pth`, so
// there is nothing to install into a fresh interpreter and observe. What is
// testable, and is tested here, is every decision the module makes: the env
// switches, the host contract, the non-interactive guards, the decline record,
// and that an explicit `intercept()` adopts the hook's install rather than
// refusing it.
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import * as autostart from "../src/autostart.js";
import {
  autostartInterceptor,
  releaseAutostartInterceptor,
  registerAutostartInterceptor,
} from "../src/egress-interceptor.js";
import * as state from "../src/local-state.js";
import { KnoxCall, interceptKillSwitch } from "../src/index.js";
import type { InterceptManifestRoute } from "../src/index.js";

const ENV_KEYS = [
  "KNOXCALL_AUTOSTART",
  "KNOXCALL_AUTOSTART_VERBOSE",
  "KNOXCALL_AUTOSTART_HOSTS",
  "KNOXCALL_INTERCEPT",
  "KNOXCALL_NO_INTERACTIVE",
  "KNOXCALL_CREDENTIALS_FILE",
  "CI",
] as const;

let saved: Record<string, string | undefined> = {};
let dir: string;
let savedFetch: typeof fetch;

beforeEach(async () => {
  saved = {};
  for (const k of ENV_KEYS) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
  savedFetch = globalThis.fetch;
  dir = mkdtempSync(join(tmpdir(), "knox-autostart-"));
  // Point BOTH state files at the temp dir, never the developer's ~/.knoxcall.
  process.env.KNOXCALL_CREDENTIALS_FILE = join(dir, "credentials.json");
  await autostart.resetForTests();
  registerAutostartInterceptor(null);
});

afterEach(async () => {
  await autostart.resetForTests();
  registerAutostartInterceptor(null);
  for (const k of ENV_KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
  globalThis.fetch = savedFetch;
  rmSync(dir, { recursive: true, force: true });
  vi.restoreAllMocks();
});

// ── env switches ────────────────────────────────────────────────────────────

describe("the off switches", () => {
  it.each([
    ["off", true],
    ["0", true],
    ["false", true],
    ["FALSE", true],
    ["  Off  ", true],
    ["no", false],
    ["on", false],
    ["1", false],
    ["", false],
  ])("KNOXCALL_AUTOSTART=%j disables the hook: %s", (value, disabled) => {
    process.env.KNOXCALL_AUTOSTART = value as string;
    expect(autostart.disabledByEnv()).toBe(disabled);
  });

  // Two different variables doing two different jobs, but a user will
  // reasonably expect a spelling that works on one to work on the other.
  it.each(["off", "0", "false", "FALSE", "  Off  ", "no", "on", "1", "", "yes", "true", "OFF"])(
    "reads %j exactly as the per-request kill switch does",
    (value) => {
      process.env.KNOXCALL_AUTOSTART = value;
      process.env.KNOXCALL_INTERCEPT = value;
      expect(autostart.disabledByEnv()).toBe(interceptKillSwitch());
    },
  );

  it("does not install when disabled, and leaves global fetch alone", () => {
    process.env.KNOXCALL_AUTOSTART = "off";
    const before = globalThis.fetch;
    expect(autostart.install()).toBe(false);
    expect(globalThis.fetch).toBe(before);
    expect(autostart.autostartState()).toBe("pending");
  });

  it("installs a fetch shim when enabled, and removes it on reset", async () => {
    const before = globalThis.fetch;
    expect(autostart.install()).toBe(true);
    expect(globalThis.fetch).not.toBe(before);
    await autostart.resetForTests();
    expect(globalThis.fetch).toBe(before);
  });

  it("refuses a second install while one is armed", () => {
    expect(autostart.install()).toBe(true);
    expect(autostart.install()).toBe(false);
  });

  it.each([
    ["a.example,b.example", ["a.example", "b.example"]],
    [" a.example , b.example ", ["a.example", "b.example"]],
    ["a.example;b.example", ["a.example", "b.example"]],
    ["", []],
    [",,", []],
  ])("KNOXCALL_AUTOSTART_HOSTS=%j parses to %j", (value, expected) => {
    process.env.KNOXCALL_AUTOSTART_HOSTS = value as string;
    expect(autostart.extraHosts()).toEqual(expected);
  });

  it("has no built-in host list", () => {
    expect(autostart.extraHosts()).toEqual([]);
  });

  it("diagnostics are opt-IN, and read the usual falsey spellings as off", () => {
    // The INVERSE of the switch this replaced: silent by default, so a
    // customer's CI log never carries a line nobody will act on.
    expect(autostart.verbose()).toBe(false);
    for (const v of ["0", "false", "no", "off", ""]) {
      process.env.KNOXCALL_AUTOSTART_VERBOSE = v;
      expect(autostart.verbose()).toBe(false);
    }
    for (const v of ["1", "true", "yes", "verbose"]) {
      process.env.KNOXCALL_AUTOSTART_VERBOSE = v;
      expect(autostart.verbose()).toBe(true);
    }
  });

  it("does NOT read the per-request kill switch at install time", () => {
    // KNOXCALL_INTERCEPT is documented as per-REQUEST. Reading it here would
    // quietly make it per-process.
    process.env.KNOXCALL_INTERCEPT = "off";
    expect(autostart.disabledByEnv()).toBe(false);
    expect(autostart.install()).toBe(true);
  });
});

// ── the host contract ───────────────────────────────────────────────────────

describe("what is worth promoting", () => {
  // `worthPromoting` is module-private, so drive it the way a request does and
  // observe whether the shim reached for a promotion at all. A platform host
  // must never promote, or the SDK's own manifest poll would recurse.
  function armWithStub(): ReturnType<typeof vi.fn> {
    const stub = vi.fn(async () => new Response("ORIGINAL"));
    globalThis.fetch = stub as unknown as typeof fetch;
    expect(autostart.install()).toBe(true);
    return stub;
  }

  it("never promotes on a KnoxCall host", async () => {
    const stub = armWithStub();
    for (const url of ["https://knoxcall.com/x", "https://api.knoxcall.com/v1/routes"]) {
      expect(await (await globalThis.fetch(url)).text()).toBe("ORIGINAL");
    }
    expect(stub).toHaveBeenCalledTimes(2);
    expect(autostart.autostartState()).toBe("pending");
  });

  it("passes an unparseable input straight through without promoting", async () => {
    const stub = armWithStub();
    expect(await (await globalThis.fetch("not a url")).text()).toBe("ORIGINAL");
    expect(stub).toHaveBeenCalledTimes(1);
    expect(autostart.autostartState()).toBe("pending");
  });

  it("the kill switch stops promotion per request", async () => {
    process.env.KNOXCALL_INTERCEPT = "off";
    const stub = armWithStub();
    expect(await (await globalThis.fetch("https://a.klaviyo.com/x")).text()).toBe("ORIGINAL");
    expect(stub).toHaveBeenCalledTimes(1);
    expect(autostart.autostartState()).toBe("pending");
  });
});

// ── the login guards ────────────────────────────────────────────────────────

/** Every credential probe misses. `autoDetectBootstrap`'s GCP leg is an
 *  UNGATED metadata fetch, so without this the suite would make a real network
 *  call — and if anything answered it, the probe would read the body as a
 *  subject token and promotion would take a path no test meant. */
function noCredentialFetch(): typeof fetch {
  return (async () => {
    throw new TypeError("fetch failed");
  }) as unknown as typeof fetch;
}

describe("the one-time login prompt", () => {
  function captureStderr(): { lines: string[]; restore: () => void } {
    const lines: string[] = [];
    const spy = vi.spyOn(process.stderr, "write").mockImplementation(((chunk: unknown) => {
      lines.push(String(chunk));
      return true;
    }) as never);
    return { lines, restore: () => spy.mockRestore() };
  }

  it.each(["KNOXCALL_NO_INTERACTIVE", "CI"])(
    "never prompts when %s is set, and says NOTHING",
    async (key) => {
      // Operator decision, 2026-10-08: the hook says nothing on its own. An
      // unprompted line costs every customer's CI log one copy per process,
      // forever, and the documentation is what points people at
      // `knoxcall login`.
      process.env[key] = "1";
      globalThis.fetch = noCredentialFetch();
      const { lines, restore } = captureStderr();
      const result = await autostart.ready();
      restore();
      expect(result).toBe("disabled");
      expect(lines.filter((l) => l.startsWith("KnoxCall:"))).toEqual([]);
    },
  );

  it("is silent even when promotion fails outright", async () => {
    process.env.KNOXCALL_NO_INTERACTIVE = "1";
    globalThis.fetch = (() => {
      throw new RangeError("something unexpected");
    }) as unknown as typeof fetch;
    const { lines, restore } = captureStderr();
    await autostart.ready();
    restore();
    expect(autostart.autostartState()).toBe("disabled");
    expect(lines.filter((l) => l.startsWith("KnoxCall:"))).toEqual([]);
  });

  it.each(["KNOXCALL_NO_INTERACTIVE", "CI"])(
    "says it once under KNOXCALL_AUTOSTART_VERBOSE when %s is set",
    async (key) => {
      process.env[key] = "1";
      process.env.KNOXCALL_AUTOSTART_VERBOSE = "1";
      globalThis.fetch = noCredentialFetch();
      const { lines, restore } = captureStderr();
      await autostart.ready();
      restore();
      const said = lines.filter((l) => l.startsWith("KnoxCall:"));
      expect(said).toHaveLength(1);
      expect(said[0]).toContain("knoxcall login");
    },
  );

  it("records a no-credential verdict so the next process does not re-detect", async () => {
    process.env.KNOXCALL_NO_INTERACTIVE = "1";
    globalThis.fetch = noCredentialFetch();
    const { restore } = captureStderr();
    await autostart.ready();
    restore();
    expect(state.noCredentialRecorded("default")).toBe(true);
  });
});

// ── local-state ─────────────────────────────────────────────────────────────

describe("local-state", () => {
  it("round-trips a decline and reads it back", () => {
    expect(state.loginDeclined("default")).toBe(false);
    expect(state.recordLoginDeclined("default", "timeout")).toBe(true);
    expect(state.loginDeclined("default")).toBe(true);
    expect(state.readAutostartState("default").reason).toBe("timeout");
  });

  it("clears a decline AND the no-credential verdict together", () => {
    state.recordLoginDeclined("default", "timeout");
    state.recordNoCredential("default");
    expect(state.clearLoginDeclined("default")).toBe(true);
    expect(state.loginDeclined("default")).toBe(false);
    expect(state.noCredentialRecorded("default")).toBe(false);
  });

  it("keeps other profiles untouched", () => {
    state.recordLoginDeclined("default", "timeout");
    state.recordLoginDeclined("other", "interrupted");
    expect(state.loginDeclined("default")).toBe(true);
    expect(state.loginDeclined("other")).toBe(true);
    state.clearLoginDeclined("default");
    expect(state.loginDeclined("other")).toBe(true);
  });

  it("expires the no-credential verdict", () => {
    state.recordNoCredential("default");
    expect(state.noCredentialRecorded("default")).toBe(true);
    vi.spyOn(Date, "now").mockReturnValue(Date.now() + state.NO_CREDENTIAL_TTL_MS + 1000);
    expect(state.noCredentialRecorded("default")).toBe(false);
  });

  it.each(["", "not json", "[]", '{"profiles": 5}'])(
    "reads a corrupt state file (%j) as absent",
    (body) => {
      const p = join(dir, "autostart.json");
      writeFileSync(p, body as string, "utf8");
      expect(state.readAutostartState("default", p)).toEqual({});
      expect(state.loginDeclined("default", p)).toBe(false);
    },
  );

  it("never fails on an unwritable location", () => {
    const blocker = join(dir, "blocker");
    writeFileSync(blocker, "x", "utf8");
    expect(state.writeAutostartState("default", { reason: "x" }, join(blocker, "sub", "a.json"))).toBe(false);
  });

  it("holds no credential material", () => {
    state.recordLoginDeclined("default", "timeout");
    const raw = readFileSync(join(dir, "autostart.json"), "utf8");
    for (const forbidden of ["access_token", "refresh_token", "client_secret", "Bearer", "kc_"]) {
      expect(raw).not.toContain(forbidden);
    }
  });

  it("puts its state beside the credentials file, not in the home directory", () => {
    expect(state.autostartStatePath()).toBe(join(dir, "autostart.json"));
  });
});

// ── adoption ────────────────────────────────────────────────────────────────

function entry(over: Partial<InterceptManifestRoute> & { host: string; slug: string }): InterceptManifestRoute {
  return { base_path: "/", route_id: `id-${over.slug}`, requires_clients: false, allowed_methods: null, updated_at: null, ...over };
}

function makeClient(routes: InterceptManifestRoute[], seen: string[]) {
  const fetchImpl: typeof fetch = async (input, init) => {
    const url = typeof input === "string" ? input : (input as Request).url;
    seen.push(url);
    if (url.startsWith("https://api.test/v1/wrap/intercept-manifest")) {
      return new Response(
        JSON.stringify({ data: { version: "v1", ttl_seconds: 60, environment: "production", sandbox: false, routes }, meta: {} }),
        { status: 200, headers: { "Content-Type": "application/json", ETag: 'W/"v1"' } },
      );
    }
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "Content-Type": "application/json", "X-Knox-Upstream-Status": "200" },
    });
  };
  return new KnoxCall({
    tenant: "acme", baseUrl: "https://api.test", proxyBaseUrl: "https://acme.test",
    apiKey: "kc_live_x", sandbox: false, fetchImpl,
  });
}

describe("an explicit intercept() adopts the hook's install", () => {
  const KLAVIYO = entry({ host: "a.klaviyo.com", slug: "klaviyo" });

  it("replaces it instead of throwing, and uninstalls the hook's handle", async () => {
    const hookSeen: string[] = [];
    const target = { fetch: (async () => new Response("ORIGINAL")) as typeof fetch };
    const hook = makeClient([KLAVIYO], hookSeen).wrap.intercept({ hosts: [], target, autostart: true });
    await hook.ready;
    expect(autostartInterceptor()).not.toBeNull();

    const appSeen: string[] = [];
    const explicit = makeClient([KLAVIYO], appSeen).wrap.intercept({ hosts: [], target });
    try {
      await explicit.ready;
      expect(autostartInterceptor()).toBeNull();
      expect(hook.installed).toBe(false);
      await target.fetch("https://a.klaviyo.com/api/profiles");
      expect(appSeen.some((u) => u.startsWith("https://acme.test/"))).toBe(true);
      expect(hookSeen.some((u) => u.startsWith("https://acme.test/"))).toBe(false);
    } finally {
      explicit.uninstall();
    }
  });

  it("still refuses two EXPLICIT installs", async () => {
    const target = { fetch: (async () => new Response("ORIGINAL")) as typeof fetch };
    const first = makeClient([KLAVIYO], []).wrap.intercept({ hosts: [], target });
    try {
      await first.ready;
      expect(() => makeClient([KLAVIYO], []).wrap.intercept({ hosts: [], target })).toThrow(/already installed/);
    } finally {
      first.uninstall();
    }
  });

  it("does not resurrect the hook when the explicit install is uninstalled", async () => {
    const target = { fetch: (async () => new Response("ORIGINAL")) as typeof fetch };
    const preHook = target.fetch;
    const hook = makeClient([KLAVIYO], []).wrap.intercept({ hosts: [], target, autostart: true });
    await hook.ready;
    const explicit = makeClient([KLAVIYO], []).wrap.intercept({ hosts: [], target });
    await explicit.ready;
    explicit.uninstall();
    expect(target.fetch).toBe(preHook);
    expect(hook.installed).toBe(false);
  });

  it("releaseAutostartInterceptor is idempotent and safe with nothing registered", () => {
    expect(() => releaseAutostartInterceptor()).not.toThrow();
    expect(autostartInterceptor()).toBeNull();
  });
});
