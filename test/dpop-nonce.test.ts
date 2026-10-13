// The DPoP server nonce (RFC 9449 §8) — PARITY §7.1, client Phase 4.3.
//
// Four behaviours, and the fourth is the one that is easy to get wrong:
//
//  1. remember the most recent `DPoP-Nonce` per ORIGIN;
//  2. send it as the proof's `nonce` claim on every later request there;
//  3. on the server's "use a nonce" refusal, re-sign ONCE with the nonce that
//     refusal carried, with a new `jti`, and never loop;
//  4. that refusal is NOT an authentication failure. A 401 normally purges the
//     cached token and spends the one re-auth; a `use_dpop_nonce` 401 must do
//     neither, or every nonce rotation costs a token mint — and the retry would
//     then succeed anyway, which is what would hide it.
//
// Capture is at the HTTP boundary (an injected `fetchImpl` that records the
// proofs it is sent and answers with the headers the real server sends), so
// these drive the real signer, the real store and the real retry loops.
import { describe, it, expect } from "vitest";

import { KnoxCall } from "../src/index.js";
import { DpopNonceStore, isUseDpopNonce, originOf } from "../src/auth/dpop-nonce.js";

function proofClaims(proof: string): Record<string, unknown> {
  const payload = proof.split(".")[1];
  return JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
}

// ── the store ───────────────────────────────────────────────────────────────

describe("origin", () => {
  it.each([
    ["https://api.knoxcall.com/v1/routes", "https://api.knoxcall.com"],
    ["https://api.knoxcall.com/v1/routes?a=1#f", "https://api.knoxcall.com"],
    ["https://API.KnoxCall.com/v1", "https://api.knoxcall.com"],
    ["http://localhost:3000/v1", "http://localhost:3000"],
    ["https://api.knoxcall.com:8443/v1", "https://api.knoxcall.com:8443"],
    ["not a url", ""],
    ["", ""],
  ])("%s -> %s", (url, expected) => {
    expect(originOf(url)).toBe(expected);
  });
});

describe("DpopNonceStore", () => {
  it("is keyed by origin, not by URL", () => {
    const s = new DpopNonceStore();
    s.remember("https://api.knoxcall.com/oauth/token", { "dpop-nonce": "A" });
    expect(s.get("https://api.knoxcall.com/v1/routes?x=1")).toBe("A");
    // A DIFFERENT origin has not answered yet. The management API and a
    // tenant's data plane issue different values; sending one to the other
    // would be refused.
    expect(s.get("https://acme.knoxcall.com/api/anything")).toBeUndefined();
    s.remember("https://acme.knoxcall.com/api/x", { "dpop-nonce": "B" });
    expect(s.get("https://acme.knoxcall.com/api/y")).toBe("B");
    expect(s.get("https://api.knoxcall.com/v1/routes")).toBe("A");
  });

  it("last write wins, and a blank value never erases what we hold", () => {
    const s = new DpopNonceStore();
    s.remember("https://api.test/x", { "dpop-nonce": "first" });
    s.remember("https://api.test/x", { "dpop-nonce": "second" });
    expect(s.get("https://api.test/x")).toBe("second");
    for (const headers of [{}, { "dpop-nonce": "" }, { "dpop-nonce": "   " }, undefined]) {
      expect(s.remember("https://api.test/x", headers)).toBeUndefined();
      expect(s.get("https://api.test/x")).toBe("second");
    }
  });

  it("does not remember a hostless URL", () => {
    const s = new DpopNonceStore();
    expect(s.remember("not a url", { "dpop-nonce": "x" })).toBeUndefined();
    expect(s.snapshot()).toEqual({});
  });
});

// ── the refusal predicate ───────────────────────────────────────────────────

describe("isUseDpopNonce", () => {
  it("recognises the authorization server's 400 + OAuth body", () => {
    expect(isUseDpopNonce({ status: 400, code: "use_dpop_nonce" })).toBe(true);
  });

  it("recognises a resource server from the challenge header ALONE", () => {
    // The tenant data plane keeps its deliberately opaque `Unauthorized` body,
    // so the header is the only signal there. A predicate that read the body
    // would work on /v1 and silently never fire on the data plane.
    expect(
      isUseDpopNonce({ status: 401, headers: { "www-authenticate": 'DPoP error="use_dpop_nonce"' } }),
    ).toBe(true);
    expect(
      isUseDpopNonce({
        status: 401,
        headers: { "www-authenticate": 'DPoP realm="knoxcall", ERROR="USE_DPOP_NONCE"' },
      }),
    ).toBe(true);
  });

  it.each([
    [{ status: 401, code: "invalid_token" }],
    [{ status: 401, headers: { "www-authenticate": 'DPoP error="invalid_token"' } }],
    [{ status: 403, code: "use_dpop_nonce" }],
    [{ status: 500, code: "use_dpop_nonce" }],
    [{ status: 200 }],
    [{}],
  ])("nothing else is a nonce refusal: %j", (args) => {
    expect(isUseDpopNonce(args)).toBe(false);
  });
});

// ── end to end, through the real client ─────────────────────────────────────

interface Seen {
  url: string;
  proof?: Record<string, unknown>;
}

function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

function tokenResponse(nonce?: string): Response {
  return json(
    200,
    { access_token: "kc_at_x", token_type: "DPoP", expires_in: 3600 },
    nonce ? { "DPoP-Nonce": nonce } : {},
  );
}

/** Records every request, answering from PER-SURFACE queues so a token
 *  response can never answer a `/v1` request once a queue runs dry. */
function recorder(script: { token?: Response[]; api?: Response[]; fallback?: () => Response }) {
  const token = [...(script.token ?? [])];
  const api = [...(script.api ?? [])];
  const seen: Seen[] = [];
  const fetchImpl: typeof fetch = async (input, init) => {
    const url = typeof input === "string" ? input : (input as Request).url;
    const headers = new Headers(init?.headers as HeadersInit);
    const proof = headers.get("dpop");
    seen.push({ url, proof: proof ? proofClaims(proof) : undefined });
    const queue = url.includes("/oauth/token") ? token : api;
    if (queue.length > 0) return queue.shift()!;
    if (script.fallback) return script.fallback();
    throw new Error(`unscripted request: ${url}`);
  };
  return {
    fetchImpl,
    seen,
    proofs: (match?: string) =>
      seen.filter((s) => (match ? s.url.includes(match) : true) && s.proof).map((s) => s.proof!),
    mints: () => seen.filter((s) => s.url.includes("/oauth/token")),
  };
}

function clientFor(fetchImpl: typeof fetch) {
  return new KnoxCall({
    tenant: "acme",
    baseUrl: "https://api.test",
    proxyBaseUrl: "https://acme.test",
    clientId: "tk_id",
    clientSecret: "shh",
    dpop: "always",
    fetchImpl,
    maxRetries: 3,
  });
}

describe("DPoP nonce — end to end", () => {
  it("sends the mint's nonce on the next API call, and the API's on the one after", async () => {
    const rec = recorder({
      token: [tokenResponse("NONCE-1")],
      api: [json(200, { data: { ok: true } }, { "DPoP-Nonce": "NONCE-2" }), json(200, { data: { ok: true } })],
    });
    const knox = clientFor(rec.fetchImpl);
    await knox.routes.list();
    await knox.routes.list();

    const [mint, first, second] = rec.proofs();
    // The very first proof — the mint — has no nonce to send, and the server
    // accepts that.
    expect(mint.nonce).toBeUndefined();
    expect(first.nonce).toBe("NONCE-1");
    expect(second.nonce).toBe("NONCE-2");
  });

  it("re-signs once on a resource-server refusal and succeeds", async () => {
    const rec = recorder({
      token: [tokenResponse("STALE")],
      api: [
        json(
          401,
          { error: { type: "use_dpop_nonce", message: "nonce required" } },
          { "www-authenticate": 'DPoP error="use_dpop_nonce"', "DPoP-Nonce": "FRESH" },
        ),
        json(200, { data: { ok: true } }),
      ],
    });
    const knox = clientFor(rec.fetchImpl);
    await knox.routes.list();

    const calls = rec.proofs("/v1/routes");
    expect(calls).toHaveLength(2);
    expect(calls[0].nonce).toBe("STALE");
    expect(calls[1].nonce).toBe("FRESH");
    expect(calls[0].jti).not.toBe(calls[1].jti);
    expect(rec.mints()).toHaveLength(1);
  });

  it("does NOT spend the token re-mint on a nonce refusal", async () => {
    const rec = recorder({
      token: [tokenResponse("STALE")],
      api: [
        new Response(null, {
          status: 401,
          headers: { "www-authenticate": 'DPoP error="use_dpop_nonce"', "DPoP-Nonce": "FRESH" },
        }),
        json(200, { data: { ok: true } }),
      ],
    });
    const knox = clientFor(rec.fetchImpl);
    await knox.routes.list();
    expect(rec.mints(), "the nonce refusal spent a token mint").toHaveLength(1);
  });

  it("still re-mints on a real 401", async () => {
    const rec = recorder({
      token: [tokenResponse("N1"), tokenResponse("N2")],
      api: [json(401, { error: { type: "invalid_token", message: "nope" } }), json(200, { data: { ok: true } })],
    });
    const knox = clientFor(rec.fetchImpl);
    await knox.routes.list();
    expect(rec.mints()).toHaveLength(2);
  });

  it("never loops, and never costs a mint", async () => {
    const refusal = () =>
      json(
        401,
        { error: { type: "use_dpop_nonce", message: "nonce required" } },
        { "www-authenticate": 'DPoP error="use_dpop_nonce"', "DPoP-Nonce": "N" },
      );
    const rec = recorder({ token: [tokenResponse("N")], api: [], fallback: refusal });
    const knox = clientFor(rec.fetchImpl);
    await expect(knox.routes.list()).rejects.toThrow();
    // ONE nonce re-sign, then the error surfaces. It must not also spend the
    // re-auth: the token was deliberately not purged, so that retry would
    // resend an identical request.
    expect(rec.proofs("/v1/routes")).toHaveLength(2);
    expect(rec.mints()).toHaveLength(1);
  });

  it("re-signs the MINT once on the authorization server's 400", async () => {
    const rec = recorder({
      token: [
        json(400, { error: "use_dpop_nonce", error_description: "nonce required" }, { "DPoP-Nonce": "FRESH" }),
        tokenResponse("FRESH"),
      ],
      api: [json(200, { data: { ok: true } })],
    });
    const knox = clientFor(rec.fetchImpl);
    await knox.routes.list();

    const mints = rec.proofs("/oauth/token");
    expect(mints).toHaveLength(2);
    expect(mints[0].nonce).toBeUndefined();
    expect(mints[1].nonce).toBe("FRESH");
    expect(mints[0].jti).not.toBe(mints[1].jti);
  });

  it("re-signs the mint in place, with NO outer retry loop to fall back on", async () => {
    // Isolates the mint-level retry. `authenticate()` calls the token fetch
    // directly, outside `request()`'s loop — so if the mint did not retry
    // itself, this 400 would reach the caller. The test above cannot show that:
    // it goes through `request()`, whose own nonce branch also matches a 400
    // and would mask a missing mint-level retry entirely (found by
    // break-verifying, which is the only reason this test exists).
    const rec = recorder({
      token: [
        json(400, { error: "use_dpop_nonce", error_description: "nonce required" }, { "DPoP-Nonce": "FRESH" }),
        tokenResponse("FRESH"),
      ],
    });
    const knox = clientFor(rec.fetchImpl);
    await knox.authenticate();

    const mints = rec.proofs("/oauth/token");
    expect(mints).toHaveLength(2);
    expect(mints[0].nonce).toBeUndefined();
    expect(mints[1].nonce).toBe("FRESH");
    expect(mints[0].jti).not.toBe(mints[1].jti);
  });

  it("retries the data plane from the challenge header alone", async () => {
    const rec = recorder({
      token: [tokenResponse("STALE")],
      api: [
        new Response("Unauthorized", {
          status: 401,
          headers: { "www-authenticate": 'DPoP error="use_dpop_nonce"', "DPoP-Nonce": "FRESH" },
        }),
        json(200, { ok: true }),
      ],
    });
    const knox = clientFor(rec.fetchImpl);
    const res = await knox.call("my-route", { path: "/v1/things" });
    expect(res.status).toBe(200);

    const calls = rec.proofs("acme.test");
    expect(calls).toHaveLength(2);
    // The data plane is a DIFFERENT ORIGIN from the management API, so the
    // nonce the mint returned (api.test) is correctly NOT sent here: this
    // origin has not answered yet. The retry uses the one its own refusal
    // carried. A store keyed coarser than the origin would have sent
    // api.test's nonce and been refused for it.
    expect(calls[0].nonce).toBeUndefined();
    expect(calls[1].nonce).toBe("FRESH");
    expect(rec.mints()).toHaveLength(1);
  });

  it("treats an UPSTREAM 401 as the upstream's answer, not a nonce refusal", async () => {
    const rec = recorder({
      token: [tokenResponse("N")],
      api: [
        new Response("upstream says no", {
          status: 401,
          headers: {
            "x-knox-upstream-status": "401",
            "www-authenticate": 'DPoP error="use_dpop_nonce"',
          },
        }),
      ],
    });
    const knox = clientFor(rec.fetchImpl);
    const res = await knox.call("my-route", { path: "/v1/things" });
    expect(res.status).toBe(401);
    expect(rec.proofs("acme.test"), "no retry on an upstream answer").toHaveLength(1);
  });
});
