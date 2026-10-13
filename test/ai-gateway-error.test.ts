// AIGW-163 — the AI DATA plane's typed refusal.
//
// The SDK deliberately does not make the data-plane call for you: you point an
// existing Anthropic or OpenAI client at the agent's `agent_url`. So what the
// SDK owes you is the ability to TYPE what that client hands back — a
// `{error, error_description, code}` body which is not the Management API's
// `{error: {type, message, request_id}}` and must not be mistaken for it.

import { describe, it, expect } from "vitest";
import {
  AIGatewayError,
  KnoxCallError,
  aiGatewayErrorFrom,
  isAIGatewayErrorBody,
} from "../src/index.js";

const REFUSAL = {
  error: "budget_exceeded",
  error_description: "Daily budget exceeded: $50.0031 >= $50",
  code: "budget_exceeded",
  utilization_pct: 100.006,
};

describe("aiGatewayErrorFrom", () => {
  it("returns the typed class carrying code, description and Retry-After", () => {
    const err = aiGatewayErrorFrom(429, REFUSAL, {
      "retry-after": "3600",
      "x-request-id": "0d5b2a9e-1f3c-4a7d-8e2b-6c9a1f4d7e35",
    });
    expect(err).toBeInstanceOf(AIGatewayError);
    expect(err!.code).toBe("budget_exceeded");
    expect(err!.status).toBe(429);
    expect(err!.errorDescription).toBe("Daily budget exceeded: $50.0031 >= $50");
    expect(err!.retryAfter).toBe(3600);
    expect(err!.requestId).toBe("0d5b2a9e-1f3c-4a7d-8e2b-6c9a1f4d7e35");
    expect(err!.message).toBe("Daily budget exceeded: $50.0031 >= $50");
  });

  it("is a KnoxCallError, so an existing catch still catches it", () => {
    // PARITY §1: every new typed error is re-parented into the hierarchy.
    const err = aiGatewayErrorFrom(403, {
      error: "model_not_allowed",
      error_description: "not on the allowlist",
      code: "model_not_allowed",
    });
    expect(err).toBeInstanceOf(KnoxCallError);
  });

  it("reads a fetch Headers object as well as a plain one", () => {
    const h = new Headers({ "Retry-After": "60" });
    expect(aiGatewayErrorFrom(429, REFUSAL, h)!.retryAfter).toBe(60);
  });

  it("leaves retryAfter undefined when the header is absent or not whole seconds", () => {
    // Absent is meaningful: the gateway sends no header rather than a guess, so
    // `undefined` must not become 0 (an immediate retry against a spent cap).
    expect(aiGatewayErrorFrom(429, REFUSAL)!.retryAfter).toBeUndefined();
    expect(aiGatewayErrorFrom(429, REFUSAL, { "retry-after": "" })!.retryAfter).toBeUndefined();
    // An HTTP-date Retry-After is legal but is not delta-seconds.
    expect(
      aiGatewayErrorFrom(429, REFUSAL, { "retry-after": "Wed, 09 Sep 2026 00:00:00 GMT" })!.retryAfter,
    ).toBeUndefined();
  });

  it("returns null for the MANAGEMENT envelope, which is a different contract", () => {
    // The nested shape every other /v1 resource answers. Typing it as an AI
    // refusal would put a control-plane `not_found` in the same catch as a
    // data-plane budget refusal.
    expect(
      aiGatewayErrorFrom(404, { error: { type: "not_found", message: "Gateway not found." } }),
    ).toBeNull();
  });

  it("returns null for an RFC 6749 OAuth error, which carries no `code`", () => {
    expect(
      aiGatewayErrorFrom(400, { error: "invalid_grant", error_description: "bad subject token" }),
    ).toBeNull();
  });

  it("returns null when `error` and `code` disagree", () => {
    // The pre-AIGW-163 auth shape. It is not this envelope, and quietly
    // accepting it would make `err.code` mean two things again.
    expect(
      aiGatewayErrorFrom(401, { error: "Unauthorized", code: "expired", reason: "Token has expired" }),
    ).toBeNull();
  });

  it("returns null for a non-object body", () => {
    expect(aiGatewayErrorFrom(502, "<html>502 Bad Gateway</html>")).toBeNull();
    expect(aiGatewayErrorFrom(502, null)).toBeNull();
    expect(aiGatewayErrorFrom(502, undefined)).toBeNull();
  });

  it("keeps the raw body for anything the typed fields do not carry", () => {
    expect((aiGatewayErrorFrom(429, REFUSAL)!.body as any).utilization_pct).toBe(100.006);
  });

  it("isAIGatewayErrorBody is the discriminator on its own", () => {
    expect(isAIGatewayErrorBody(REFUSAL)).toBe(true);
    expect(isAIGatewayErrorBody({ error: "x", code: "x" })).toBe(false); // no description
    expect(isAIGatewayErrorBody({ error: "x", error_description: "y" })).toBe(false); // no code
  });
});
