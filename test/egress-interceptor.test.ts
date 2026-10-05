// EXPERIMENTAL egress interceptor — install/uninstall, host scoping, context
// gating, anti-recursion, double-install + anti-clobber. All tests install onto
// a FAKE target object (never the real globalThis.fetch), so nothing leaks
// between tests.

import { describe, it, expect, vi } from "vitest";
import {
  installEgressInterceptor,
  installHttpEgressInterceptor,
  runRouted,
  inRoutedContext,
  type HttpModuleLike,
} from "../src/egress-interceptor.js";
import { WrapResource } from "../src/resources/wrap.js";

describe("installEgressInterceptor", () => {
  it("reroutes a listed host and passes every other host through", async () => {
    const original = vi.fn(async () => new Response("ORIGINAL"));
    const reroute = vi.fn(async () => new Response("REROUTED"));
    const target = { fetch: original };

    const handle = installEgressInterceptor({ hosts: ["api.stripe.com"], reroute, target });
    expect(handle.installed).toBe(true);

    const r1 = await target.fetch("https://api.stripe.com/v1/charges");
    expect(await r1.text()).toBe("REROUTED");
    expect(reroute).toHaveBeenCalledTimes(1);
    expect(original).not.toHaveBeenCalled();

    const r2 = await target.fetch("https://api.openai.com/v1/models");
    expect(await r2.text()).toBe("ORIGINAL");
    expect(original).toHaveBeenCalledTimes(1);

    handle.uninstall();
    expect(handle.installed).toBe(false);
    expect(target.fetch).toBe(original);
  });

  it("normalizes the host (case + trailing dot)", async () => {
    const original = vi.fn(async () => new Response("O"));
    const reroute = vi.fn(async () => new Response("R"));
    const target = { fetch: original };
    installEgressInterceptor({ hosts: ["API.Stripe.com"], reroute, target });
    await target.fetch("https://api.stripe.com./v1/x"); // trailing-dot FQDN
    expect(reroute).toHaveBeenCalledTimes(1);
  });

  it("passes an unparseable input through untouched", async () => {
    const original = vi.fn(async () => new Response("O"));
    const reroute = vi.fn();
    const target = { fetch: original };
    installEgressInterceptor({ hosts: ["api.stripe.com"], reroute, target });
    await target.fetch("::: not a url :::");
    expect(original).toHaveBeenCalledTimes(1);
    expect(reroute).not.toHaveBeenCalled();
  });

  it("requireContext: reroutes ONLY inside routed()", async () => {
    const original = vi.fn(async () => new Response("O"));
    const reroute = vi.fn(async () => new Response("R"));
    const target = { fetch: original };
    installEgressInterceptor({ hosts: ["api.stripe.com"], reroute, target, requireContext: true });

    await target.fetch("https://api.stripe.com/x"); // outside context → passthrough
    expect(reroute).not.toHaveBeenCalled();
    expect(original).toHaveBeenCalledTimes(1);

    await runRouted(() => target.fetch("https://api.stripe.com/x")); // inside → reroute
    expect(reroute).toHaveBeenCalledTimes(1);
    expect(inRoutedContext()).toBe(false); // scope closed after
  });

  it("refuses a double install and allows a fresh one after uninstall", () => {
    const target = { fetch: vi.fn(async () => new Response("O")) };
    const first = installEgressInterceptor({ hosts: ["h.example"], reroute: vi.fn(), target });
    expect(() =>
      installEgressInterceptor({ hosts: ["h.example"], reroute: vi.fn(), target }),
    ).toThrow(/already installed/i);
    first.uninstall();
    const second = installEgressInterceptor({ hosts: ["h.example"], reroute: vi.fn(), target });
    second.uninstall();
  });

  it("does not clobber a fetch patched ON TOP of it at uninstall", () => {
    const original = vi.fn();
    const target: { fetch: any } = { fetch: original };
    const handle = installEgressInterceptor({ hosts: ["h.example"], reroute: vi.fn(), target });
    const laterPatch = vi.fn(); // e.g. an APM agent installed after us
    target.fetch = laterPatch;
    handle.uninstall();
    expect(target.fetch).toBe(laterPatch); // left the later patch in place
  });

  it("throws with no fetch or empty hosts", () => {
    expect(() =>
      installEgressInterceptor({ hosts: ["h"], reroute: vi.fn(), target: {} as any }),
    ).toThrow(/global fetch/i);
    expect(() =>
      installEgressInterceptor({ hosts: [], reroute: vi.fn(), target: { fetch: vi.fn() } as any }),
    ).toThrow(/non-empty/i);
  });
});

describe("WrapResource.interceptEgress", () => {
  function stubClient() {
    return {
      sandbox: false,
      ephemeral: vi.fn(async () => new Response("VIA_KNOX")),
      call: vi.fn(async () => new Response("VIA_ROUTE")),
    } as any;
  }

  it("routes a matching host through the KnoxCall client; others go direct", async () => {
    const client = stubClient();
    const wrap = new WrapResource(client);
    const original = vi.fn(async () => new Response("DIRECT"));
    const target = { fetch: original };

    const handle = wrap.interceptEgress({ hosts: ["api.stripe.com"], target, stacks: ["fetch"] });
    const r1 = await target.fetch("https://api.stripe.com/v1/charges", { method: "POST", body: "amount=100" });
    expect(await r1.text()).toBe("VIA_KNOX");
    expect(client.ephemeral).toHaveBeenCalledTimes(1);
    expect(original).not.toHaveBeenCalled();

    const r2 = await target.fetch("https://api.openai.com/x");
    expect(await r2.text()).toBe("DIRECT");
    handle.uninstall();
  });

  it("route-around calls go DIRECT via the ORIGINAL fetch — no recursion, no KnoxCall", async () => {
    const client = stubClient();
    const wrap = new WrapResource(client);
    const original = vi.fn(async () => new Response("DIRECT"));
    const target = { fetch: original };

    // api.stripe.com /v1/tokens is a DEFAULT_ROUTE_AROUND (raw-card). The reroute
    // closure must send it straight to the provider via the pinned original fetch,
    // never through the interceptor again or the KnoxCall client.
    wrap.interceptEgress({ hosts: ["api.stripe.com"], target, stacks: ["fetch"] });
    const r = await target.fetch("https://api.stripe.com/v1/tokens", { method: "POST", body: "card=x" });
    expect(await r.text()).toBe("DIRECT");
    expect(original).toHaveBeenCalledTimes(1);
    expect(client.ephemeral).not.toHaveBeenCalled();
  });
});

// ── node:http / node:https stack ─────────────────────────────────────────────
// All tests install onto a FAKE module object (never the real node:http), so
// nothing leaks between tests or into the process.

// A minimal node:http-like module whose original request/get return a sentinel
// with an `end()` no-op, so passthrough is observable and safe to call.
function fakeHttpModule(): HttpModuleLike & {
  request: ReturnType<typeof vi.fn>;
  get: ReturnType<typeof vi.fn>;
} {
  const sentinel = () => ({ __original: true, end() {}, on() {}, once() {} });
  return {
    request: vi.fn((..._args: unknown[]) => sentinel()),
    get: vi.fn((..._args: unknown[]) => sentinel()),
  } as any;
}

// Drive a FetchBackedClientRequest to completion, collecting the IncomingMessage.
function drive(req: any, body?: string): Promise<{ status: number; text: string; headers: any }> {
  return new Promise((resolve, reject) => {
    req.on("response", (res: any) => {
      let data = "";
      res.on("data", (c: Buffer) => {
        data += Buffer.isBuffer(c) ? c.toString("utf8") : String(c);
      });
      res.on("end", () => resolve({ status: res.statusCode, text: data, headers: res.headers }));
      res.on("error", reject);
    });
    req.on("error", reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

describe("installHttpEgressInterceptor", () => {
  it("reroutes a listed host and returns an IncomingMessage-shaped response", async () => {
    const reroute = vi.fn(async (_url: string | URL | Request, _init?: RequestInit) =>
      new Response("REROUTED", { status: 201, headers: { "x-k": "1" } }),
    );
    const mod = fakeHttpModule();
    const origReq = mod.request;

    const handle = installHttpEgressInterceptor({ hosts: ["api.stripe.com"], reroute, modules: { https: mod } });
    expect(handle.installed).toBe(true);
    expect(mod.request).not.toBe(origReq); // patched

    const out = await drive(
      mod.request("https://api.stripe.com/v1/charges", { method: "POST" }, () => {}),
      "amount=100",
    );
    expect(reroute).toHaveBeenCalledTimes(1);
    expect(out.status).toBe(201);
    expect(out.text).toBe("REROUTED");
    expect(out.headers["x-k"]).toBe("1");
    expect(origReq).not.toHaveBeenCalled(); // never hit the original transport

    // The reroute saw the URL + method + body the caller wrote.
    const [url, init] = reroute.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://api.stripe.com/v1/charges");
    expect(init.method).toBe("POST");
    expect(Buffer.from(init.body as Uint8Array).toString("utf8")).toBe("amount=100");

    handle.uninstall();
    expect(handle.installed).toBe(false);
    expect(mod.request).toBe(origReq); // restored
  });

  it("passes an unmatched host through the ORIGINAL request untouched", () => {
    const reroute = vi.fn();
    const mod = fakeHttpModule();
    const origReq = mod.request;
    installHttpEgressInterceptor({ hosts: ["api.stripe.com"], reroute, modules: { https: mod } });

    const r: any = mod.request("https://api.openai.com/v1/models", () => {});
    expect(r.__original).toBe(true);
    expect(origReq).toHaveBeenCalledTimes(1);
    expect(reroute).not.toHaveBeenCalled();
  });

  it("passes an unparseable target through the original untouched", () => {
    const reroute = vi.fn();
    const mod = fakeHttpModule();
    const origReq = mod.request;
    installHttpEgressInterceptor({ hosts: ["api.stripe.com"], reroute, modules: { https: mod } });
    // options object whose host cannot form a URL
    mod.request({ host: ":::bad:::", path: "/x" }, () => {});
    expect(origReq).toHaveBeenCalledTimes(1);
    expect(reroute).not.toHaveBeenCalled();
  });

  it("matches from an options object (hostname/port/path) and normalizes the host", async () => {
    const reroute = vi.fn(async (_url: string | URL | Request, _init?: RequestInit) => new Response("R"));
    const mod = fakeHttpModule();
    installHttpEgressInterceptor({ hosts: ["API.Stripe.com"], reroute, modules: { https: mod } });

    await drive(
      mod.request({ hostname: "api.stripe.com", path: "/v1/x", method: "POST", headers: { "content-type": "text/plain" } }),
      "hi",
    );
    expect(reroute).toHaveBeenCalledTimes(1);
    const [url, init] = reroute.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://api.stripe.com/v1/x");
    expect(init.method).toBe("POST");
  });

  it("patches .get and auto-ends it", async () => {
    const reroute = vi.fn(async () => new Response("G", { status: 200 }));
    const mod = fakeHttpModule();
    installHttpEgressInterceptor({ hosts: ["api.stripe.com"], reroute, modules: { https: mod } });

    const out = await new Promise<{ status: number; text: string }>((resolve, reject) => {
      const req: any = mod.get("https://api.stripe.com/v1/ping", (res: any) => {
        let data = "";
        res.on("data", (c: Buffer) => (data += c.toString()));
        res.on("end", () => resolve({ status: res.statusCode, text: data }));
      });
      req.on("error", reject);
      // NOTE: no req.end() — get() must end itself.
    });
    expect(reroute).toHaveBeenCalledTimes(1);
    expect(out.text).toBe("G");
  });

  it("requireContext: reroutes ONLY inside runRouted()", async () => {
    const reroute = vi.fn(async () => new Response("R"));
    const mod = fakeHttpModule();
    const origReq = mod.request;
    installHttpEgressInterceptor({
      hosts: ["api.stripe.com"],
      reroute,
      modules: { https: mod },
      requireContext: true,
    });

    // Outside a routed scope → passthrough.
    mod.request("https://api.stripe.com/x", () => {});
    expect(origReq).toHaveBeenCalledTimes(1);
    expect(reroute).not.toHaveBeenCalled();

    // Inside → rerouted.
    await runRouted(() => drive(mod.request("https://api.stripe.com/x", () => {})));
    expect(reroute).toHaveBeenCalledTimes(1);
    expect(inRoutedContext()).toBe(false);
  });

  it("suppresses re-entry: http egress performed BY the reroute hits the ORIGINAL", async () => {
    const mod = fakeHttpModule();
    const origReq = mod.request;
    // The reroute simulates a fetch polyfill / route-around that egresses via
    // http.request to the SAME matched host — it must NOT re-enter the reroute.
    let innerResult: any;
    const reroute = vi.fn(async () => {
      innerResult = (mod.request as any)("https://api.stripe.com/internal", () => {});
      return new Response("OK");
    });
    installHttpEgressInterceptor({ hosts: ["api.stripe.com"], reroute, modules: { https: mod } });

    await drive(mod.request("https://api.stripe.com/v1/charges", () => {}));
    expect(reroute).toHaveBeenCalledTimes(1); // outer only — no recursion
    expect(innerResult.__original).toBe(true); // inner went to the original transport
    expect(origReq).toHaveBeenCalledTimes(1); // exactly one passthrough
  });

  it("emits 'error' on the request when the reroute rejects", async () => {
    const reroute = vi.fn(async () => {
      throw new Error("boom");
    });
    const mod = fakeHttpModule();
    installHttpEgressInterceptor({ hosts: ["api.stripe.com"], reroute, modules: { https: mod } });

    const err = await new Promise<Error>((resolve) => {
      const req: any = mod.request("https://api.stripe.com/x", () => {});
      req.on("error", resolve);
      req.end();
    });
    expect(err.message).toBe("boom");
  });

  it("refuses a double install and allows a fresh one after uninstall", () => {
    const mod = fakeHttpModule();
    const first = installHttpEgressInterceptor({ hosts: ["h.example"], reroute: vi.fn(), modules: { https: mod } });
    expect(() =>
      installHttpEgressInterceptor({ hosts: ["h.example"], reroute: vi.fn(), modules: { https: mod } }),
    ).toThrow(/already installed/i);
    first.uninstall();
    const second = installHttpEgressInterceptor({ hosts: ["h.example"], reroute: vi.fn(), modules: { https: mod } });
    second.uninstall();
  });

  it("does not clobber a request patched ON TOP of it at uninstall", () => {
    const mod = fakeHttpModule();
    const handle = installHttpEgressInterceptor({ hosts: ["h.example"], reroute: vi.fn(), modules: { https: mod } });
    const laterPatch = vi.fn(); // e.g. an APM agent installed after us
    mod.request = laterPatch as any;
    handle.uninstall();
    expect(mod.request).toBe(laterPatch); // left the later patch in place
  });

  it("throws with empty hosts", () => {
    expect(() =>
      installHttpEgressInterceptor({ hosts: [], reroute: vi.fn(), modules: { https: fakeHttpModule() } }),
    ).toThrow(/non-empty/i);
  });
});

describe("WrapResource.interceptEgress — http stack", () => {
  function stubClient() {
    return {
      sandbox: false,
      ephemeral: vi.fn(async () => new Response("VIA_KNOX")),
      call: vi.fn(async () => new Response("VIA_ROUTE")),
    } as any;
  }

  it("routes a matching http(s) host through the KnoxCall client; others pass through", async () => {
    const client = stubClient();
    const wrap = new WrapResource(client);
    const mod = fakeHttpModule();
    const origReq = mod.request;

    const handle = wrap.interceptEgress({
      hosts: ["api.stripe.com"],
      stacks: ["http"],
      httpModules: { https: mod },
    });

    const out = await drive(mod.request("https://api.stripe.com/v1/charges", () => {}), "amount=100");
    expect(out.text).toBe("VIA_KNOX");
    expect(client.ephemeral).toHaveBeenCalledTimes(1);
    expect(origReq).not.toHaveBeenCalled();

    const passthrough: any = mod.request("https://api.openai.com/x", () => {});
    expect(passthrough.__original).toBe(true);

    handle.uninstall();
    expect(mod.request).toBe(origReq);
  });

  it("defaults to BOTH stacks — the http fake is patched with no `stacks` given", async () => {
    const client = stubClient();
    const wrap = new WrapResource(client);
    const mod = fakeHttpModule();
    const origReq = mod.request;
    // Provide fakes for BOTH stacks so the default (fetch+http) never touches
    // real process globals; omit `stacks` to exercise the default.
    const fetchTarget = { fetch: vi.fn(async () => new Response("DIRECT")) };
    const handle = wrap.interceptEgress({ hosts: ["api.stripe.com"], target: fetchTarget, httpModules: { https: mod } });
    expect(mod.request).not.toBe(origReq); // http stack installed by default
    expect(fetchTarget.fetch).not.toBe(undefined);

    const out = await drive(mod.request("https://api.stripe.com/v1/charges", { method: "POST" }, () => {}), "amount=100");
    expect(out.text).toBe("VIA_KNOX");
    expect(client.ephemeral).toHaveBeenCalledTimes(1);

    handle.uninstall();
    expect(mod.request).toBe(origReq);
  });

  it("route-around goes DIRECT via the original fetch, never the KnoxCall client", async () => {
    const client = stubClient();
    const wrap = new WrapResource(client);
    const mod = fakeHttpModule();
    // Pin the reroute's directFetch (original global fetch) to a spy so we can
    // observe the route-around going direct rather than through the client.
    const originalFetch = vi.fn(async () => new Response("DIRECT"));
    const fetchTarget = { fetch: originalFetch };

    wrap.interceptEgress({
      hosts: ["api.stripe.com"],
      stacks: ["http"],
      httpModules: { https: mod },
      target: fetchTarget, // supplies the ORIGINAL fetch used for route-around
    });

    // /v1/tokens is a DEFAULT_ROUTE_AROUND → straight to the provider via fetch.
    const out = await drive(
      mod.request("https://api.stripe.com/v1/tokens", { method: "POST" }, () => {}),
      "card=x",
    );
    expect(out.text).toBe("DIRECT");
    expect(originalFetch).toHaveBeenCalledTimes(1);
    expect(client.ephemeral).not.toHaveBeenCalled();
  });
});
