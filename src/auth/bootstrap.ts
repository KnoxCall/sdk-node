// Platform auto-detection — finds the strongest available identity proof.
//
// Priority (first match wins):
//   1. KNOXCALL_ACCESS_TOKEN (or KNOXCALL_API_KEY) env var (pre-acquired)
//   2. Credentials file written by `knoxcall login` (~/.knoxcall/credentials.json)
//   3. GitHub Actions OIDC
//   4. GCP metadata service
//   5. AWS IRSA / IMDS
//   6. Azure Managed Identity
//   7. Vercel / CircleCI / GitLab CI / Buildkite OIDC
//   8. KNOXCALL_CLIENT_ID + KNOXCALL_CLIENT_SECRET env vars
//
// Detection is lazy — runs on first API call, not constructor — so users
// can override before any HTTP fires.

import { readFile } from "fs/promises";
import { BootstrapError, NotAuthenticatedError } from "../error.js";
import { profileAvailable, resolveCredentialsPath, resolveProfile } from "./credentials-file.js";

export type Bootstrap =
  | { type: "access_token"; accessToken: string }
  | { type: "oidc_token_exchange"; subjectToken: string; issuer: string }
  | { type: "client_credentials"; clientId: string; clientSecret: string }
  | { type: "stored_credentials"; path?: string; profile?: string };

// Credential classes hide secret fields from util.inspect / JSON.stringify
// so a logger (or a tool that serializes captured state, e.g. Sentry) never
// prints the secret. The `type` discriminator defaults per class, so callers
// never need to spell it out. Plain object literals matching the Bootstrap
// union remain accepted for back-compat.

const INSPECT_CUSTOM = Symbol.for("nodejs.util.inspect.custom");

export class AccessToken {
  readonly type = "access_token" as const;
  readonly accessToken: string;
  constructor(input: { accessToken: string }) {
    this.accessToken = input.accessToken;
  }
  toJSON(): Record<string, unknown> {
    return { type: this.type, accessToken: "[REDACTED]" };
  }
  [INSPECT_CUSTOM](): string {
    return "AccessToken { accessToken: '[REDACTED]' }";
  }
}

export class OidcTokenExchange {
  readonly type = "oidc_token_exchange" as const;
  readonly subjectToken: string;
  readonly issuer: string;
  constructor(input: { subjectToken: string; issuer: string }) {
    this.subjectToken = input.subjectToken;
    this.issuer = input.issuer;
  }
  toJSON(): Record<string, unknown> {
    return { type: this.type, subjectToken: "[REDACTED]", issuer: this.issuer };
  }
  [INSPECT_CUSTOM](): string {
    return `OidcTokenExchange { subjectToken: '[REDACTED]', issuer: '${this.issuer}' }`;
  }
}

export class ClientCredentials {
  readonly type = "client_credentials" as const;
  readonly clientId: string;
  readonly clientSecret: string;
  constructor(input: { clientId: string; clientSecret: string }) {
    this.clientId = input.clientId;
    this.clientSecret = input.clientSecret;
  }
  toJSON(): Record<string, unknown> {
    // clientId is not sensitive — keep it for debuggability.
    return { type: this.type, clientId: this.clientId, clientSecret: "[REDACTED]" };
  }
  [INSPECT_CUSTOM](): string {
    return `ClientCredentials { clientId: '${this.clientId}', clientSecret: '[REDACTED]' }`;
  }
}

/**
 * Credentials file written by `knoxcall login`.
 *
 * Holds no secrets itself — tokens are read from the file (path/profile
 * resolved from `KNOXCALL_CREDENTIALS_FILE` / `KNOXCALL_PROFILE` when not
 * given) at token-fetch time and wrapped in `Redacted` immediately.
 */
export class StoredCredentials {
  readonly type = "stored_credentials" as const;
  readonly path?: string;
  readonly profile?: string;
  constructor(input: { path?: string; profile?: string } = {}) {
    this.path = input.path;
    this.profile = input.profile;
  }
  toJSON(): Record<string, unknown> {
    // No secret fields — the tokens live in the file, never on this object.
    return { type: this.type, path: this.path, profile: this.profile };
  }
  [INSPECT_CUSTOM](): string {
    return `StoredCredentials { path: ${this.path ? `'${this.path}'` : "undefined"}, profile: ${this.profile ? `'${this.profile}'` : "undefined"} }`;
  }
}

// Deprecated aliases — the pre-release names. Remove before 2.0.
/** @deprecated Use {@link AccessToken}. Removed in 2.0. */
export const AccessTokenBootstrap = AccessToken;
/** @deprecated Use {@link AccessToken}. Removed in 2.0. */
export type AccessTokenBootstrap = AccessToken;
/** @deprecated Use {@link OidcTokenExchange}. Removed in 2.0. */
export const OidcTokenExchangeBootstrap = OidcTokenExchange;
/** @deprecated Use {@link OidcTokenExchange}. Removed in 2.0. */
export type OidcTokenExchangeBootstrap = OidcTokenExchange;
/** @deprecated Use {@link ClientCredentials}. Removed in 2.0. */
export const ClientCredentialsBootstrap = ClientCredentials;
/** @deprecated Use {@link ClientCredentials}. Removed in 2.0. */
export type ClientCredentialsBootstrap = ClientCredentials;

const PROBE_TIMEOUT_MS = 250;

async function fetchWithTimeout(url: string, init: RequestInit & { timeoutMs?: number } = {}): Promise<Response | null> {
  const { timeoutMs = PROBE_TIMEOUT_MS, ...rest } = init;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...rest, signal: controller.signal });
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

async function tryGhaOidc(): Promise<Bootstrap | null> {
  const url = process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
  const token = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if (!url || !token) return null;
  const res = await fetchWithTimeout(
    `${url}&audience=knoxcall:api`,
    { headers: { Authorization: `Bearer ${token}`, "User-Agent": "knoxcall-sdk" } },
  );
  if (!res || !res.ok) return null;
  const body = (await res.json()) as { value?: string };
  if (!body.value) return null;
  return new OidcTokenExchange({
    subjectToken: body.value,
    issuer: "https://token.actions.githubusercontent.com",
  });
}

async function tryGcpMetadata(): Promise<Bootstrap | null> {
  const res = await fetchWithTimeout(
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=knoxcall:api",
    { headers: { "Metadata-Flavor": "Google" } },
  );
  if (!res || !res.ok) return null;
  const token = (await res.text()).trim();
  if (!token) return null;
  return new OidcTokenExchange({ subjectToken: token, issuer: "https://accounts.google.com" });
}

async function tryAwsIrsa(): Promise<Bootstrap | null> {
  const tokenFile = process.env.AWS_WEB_IDENTITY_TOKEN_FILE;
  if (!tokenFile) return null;
  try {
    const token = (await readFile(tokenFile, "utf8")).trim();
    if (!token) return null;
    return new OidcTokenExchange({
      subjectToken: token,
      issuer: "https://sts.amazonaws.com",
    });
  } catch {
    return null;
  }
}

async function tryAzureManagedIdentity(): Promise<Bootstrap | null> {
  const endpoint = process.env.IDENTITY_ENDPOINT;
  const header = process.env.IDENTITY_HEADER;
  if (!endpoint || !header) return null;
  const res = await fetchWithTimeout(
    `${endpoint}?api-version=2019-08-01&resource=knoxcall:api`,
    { headers: { "X-IDENTITY-HEADER": header } },
  );
  if (!res || !res.ok) return null;
  const body = (await res.json()) as { access_token?: string };
  if (!body.access_token) return null;
  return new OidcTokenExchange({
    subjectToken: body.access_token,
    issuer: "https://login.microsoftonline.com",
  });
}

function tryVercelOidc(): Bootstrap | null {
  const token = process.env.VERCEL_OIDC_TOKEN;
  if (!token) return null;
  return new OidcTokenExchange({ subjectToken: token, issuer: "https://oidc.vercel.com" });
}

function tryCircleCiOidc(): Bootstrap | null {
  const token = process.env.CIRCLE_OIDC_TOKEN_V2;
  if (!token) return null;
  return new OidcTokenExchange({ subjectToken: token, issuer: "https://oidc.circleci.com" });
}

function tryBuildkiteOidc(): Bootstrap | null {
  const token = process.env.BUILDKITE_OIDC_TOKEN;
  if (!token) return null;
  return new OidcTokenExchange({
    subjectToken: token,
    issuer: "https://agent.buildkite.com",
  });
}

function tryEnvClientCreds(): Bootstrap | null {
  const id = process.env.KNOXCALL_CLIENT_ID;
  const secret = process.env.KNOXCALL_CLIENT_SECRET;
  if (!id || !secret) return null;
  return new ClientCredentials({ clientId: id, clientSecret: secret });
}

function tryEnvAccessToken(): Bootstrap | null {
  // Two spellings, one behavior; ACCESS_TOKEN wins when both are set.
  const token = process.env.KNOXCALL_ACCESS_TOKEN || process.env.KNOXCALL_API_KEY;
  if (!token) return null;
  return new AccessToken({ accessToken: token });
}

function tryCredentialsFile(): Bootstrap | null {
  // Slot 2: the file written by `knoxcall login`.
  //
  // Present = file exists AND the selected profile parses; anything
  // missing/malformed skips the provider silently (the chain continues).
  try {
    if (profileAvailable(resolveCredentialsPath(), resolveProfile())) {
      return new StoredCredentials();
    }
  } catch {
    return null;
  }
  return null;
}

/**
 * Detect bootstrap credentials from the environment. Returns the first
 * candidate found in priority order. Throws BootstrapError if nothing
 * matches.
 */
export async function autoDetectBootstrap(): Promise<Bootstrap> {
  const direct = tryEnvAccessToken();
  if (direct) return direct;

  const stored = tryCredentialsFile();
  if (stored) return stored;

  // OIDC paths next — no stored secret is the strongest tier.
  const gha = await tryGhaOidc();
  if (gha) return gha;

  const gcp = await tryGcpMetadata();
  if (gcp) return gcp;

  const aws = await tryAwsIrsa();
  if (aws) return aws;

  const azure = await tryAzureManagedIdentity();
  if (azure) return azure;

  const vercel = tryVercelOidc();
  if (vercel) return vercel;

  const circle = tryCircleCiOidc();
  if (circle) return circle;

  const bk = tryBuildkiteOidc();
  if (bk) return bk;

  const envCreds = tryEnvClientCreds();
  if (envCreds) return envCreds;

  throw new NotAuthenticatedError(
    "Could not detect KnoxCall credentials. Run `knoxcall login`, set " +
      "KNOXCALL_CLIENT_ID + KNOXCALL_CLIENT_SECRET (or KNOXCALL_API_KEY / " +
      "KNOXCALL_ACCESS_TOKEN) env vars, or run on a supported cloud platform " +
      "(GitHub Actions, GCP, AWS, Azure, Vercel). See https://docs.knoxcall.com/api-reference/authentication",
  );
}
