// Headless signup — the one /v1 surface that needs no credentials, so these are
// standalone functions rather than resources on the authenticated client.
//
// TWO steps since 2026-08-28 (founder decision F-25). `signup()` never returns
// a credential: it returns a claim handle and emails a sign-in link, and the
// starter key is minted when the link has been clicked and the claim collected.
//
//   import { signup, claimSignup, KnoxCall } from "@knoxcall/sdk";
//
//   const { claim_handle, poll_after_seconds } = await signup({
//     email: "dev@example.com",
//     tenant_name: "Acme Inc",
//   });
//   // …the account owner clicks the emailed sign-in link…
//   let claim = await claimSignup({ claim_handle });
//   while (claim.status === "pending") {
//     await new Promise((r) => setTimeout(r, poll_after_seconds * 1000));
//     claim = await claimSignup({ claim_handle });
//   }
//   // claim.starter.api_key.api_key is shown exactly once — store it now.
//   const client = new KnoxCall({ apiKey: claim.starter!.api_key.api_key, sandbox: true });

import { SignupError } from "../error.js";

export interface SignupInput {
  /** Account owner's email. Receives the sign-in link that creates the tenant. */
  email: string;
  /** Company or team name. */
  tenant_name: string;
  /** Owner's full name. Defaults to the tenant name. */
  full_name?: string;
  /**
   * Desired subdomain ({slug}.knoxcall.com). Omit to have one derived from
   * tenant_name automatically — recommended for headless callers, the server
   * converges on an available slug on its own.
   */
  tenant_slug?: string;
  /** ISO 3166-1 alpha-2 country code; derives the data region when region is omitted. */
  country?: string;
  /** Explicit data region. Immutable after signup. */
  region?: "us" | "eu" | "au";
}

export interface SignupStarter {
  /** The seeded demo route (null if seeding did not produce one). */
  route: { id: string; name: string; target_base_url: string } | null;
  api_key: {
    id: string;
    key_id: string;
    /** Plaintext test key — only ever present in this response. */
    api_key: string;
    key_prefix: string;
    key_type: "test";
  };
  sandbox_host: string;
  /** Ready-to-run curl that exercises the demo route. */
  curl: string;
}

/**
 * The 202 every signup gets — identical whether or not the address already has
 * an account, which is what makes this call enumeration-safe. It carries no
 * credential of any kind.
 */
export interface SignupResponse {
  status: "pending";
  /**
   * Opaque single-use handle. Treat it as a secret: it is what collects the
   * starter credential once the emailed link has been clicked.
   */
  claim_handle: string;
  /** Path to poll on the same host — `/v1/signup/claim`. */
  claim_path: string;
  /** Suggested delay between polls, in seconds. */
  poll_after_seconds: number;
  /** After this, the handle is rejected exactly like an unknown one. */
  expires_at: string;
  message: string;
  documentation: string;
}

export interface ClaimSignupInput {
  /** The handle returned by `signup()`. */
  claim_handle: string;
}

/** The claim poll's 202 — the sign-in link has not been used yet. */
export interface SignupClaimPending {
  status: "pending";
  message: string;
  poll_after_seconds: number;
  expires_at: string;
}

/** The claim poll's 200 — returned exactly once. */
export interface SignupClaimReady {
  status: "ready";
  tenant: { id: string; slug: string; name: string; region: string; plan: string };
  /** Seeded Test-mode demo route + one-time test API key. */
  starter: SignupStarter;
  sandbox: { management_api: string; proxy_host: string; note: string };
  documentation: string;
}

/**
 * Discriminated on `status`, so `claim.status === "ready"` narrows to the shape
 * that actually carries the credential. A `pending` reply is a normal SUCCESS,
 * never an error — code that treats it as one will fail on every poll but the
 * last (wave-2 row 2-562).
 */
export type SignupClaimResponse = SignupClaimPending | SignupClaimReady;

const DEFAULT_BASE_URL = "https://api.knoxcall.com";

async function postJson<T>(
  path: string,
  input: unknown,
  options: { baseUrl?: string; fetch?: typeof fetch } | undefined,
  what: string,
): Promise<T> {
  const doFetch = options?.fetch ?? fetch;
  const base = (options?.baseUrl ?? DEFAULT_BASE_URL).replace(/\/$/, "");

  const res = await doFetch(`${base}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  });

  const body = (await res.json()) as { data?: T; error?: { type: string; message: string } };
  if (!res.ok || !body.data) {
    const message = body.error?.message ?? `${what} failed with status ${res.status}`;
    throw new SignupError(message, { status: res.status, type: body.error?.type, body });
  }
  return body.data;
}

/**
 * Start creating a KnoxCall account. Always answers 202 with a claim handle and
 * emails a sign-in link to the address — no account, tenant or credential
 * exists until that link is clicked. Rate limited to 3 signups/hour/IP.
 *
 * Enumeration-safe: the reply is identical for an address that already has an
 * account (it receives a sign-in link and a handle that stays `pending`).
 */
export async function signup(
  input: SignupInput,
  options?: { baseUrl?: string; fetch?: typeof fetch },
): Promise<SignupResponse> {
  return postJson<SignupResponse>("/v1/signup", input, options, "Signup");
}

/**
 * Poll a claim handle. Returns `{status:"pending"}` until the emailed sign-in
 * link has been clicked, then once returns `{status:"ready"}` with the tenant
 * and a one-time Test-mode API key. Polling again after that raises a
 * SignupError (409) — the credential is shown exactly once.
 *
 * Do not poll faster than the `poll_after_seconds` returned by `signup()`.
 */
export async function claimSignup(
  input: ClaimSignupInput,
  options?: { baseUrl?: string; fetch?: typeof fetch },
): Promise<SignupClaimResponse> {
  return postJson<SignupClaimResponse>("/v1/signup/claim", input, options, "Signup claim");
}
