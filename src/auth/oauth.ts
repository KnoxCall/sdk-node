// OAuth 2.1 client — talks to KnoxCall's /oauth/token endpoint.
//
// Handles three grant types in v1.0:
//   - client_credentials (server-to-server)
//   - urn:ietf:params:oauth:grant-type:token-exchange (workload OIDC)
//   - refresh_token (rotates access + refresh)
//
// StoredCredentials bootstraps delegate to auth/credentials-file.ts, which
// owns the `knoxcall login` file's fast path + locked refresh-token grant.

import { redact, Redacted } from "../redacted.js";
import { errorFromResponse, KnoxCallError } from "../error.js";
import type { Bootstrap } from "./bootstrap.js";
import { fetchStoredToken, resolveCredentialsPath, resolveProfile } from "./credentials-file.js";
import type { CachedToken } from "./token-store.js";
import type { DpopKeyPair } from "./dpop.js";

interface OAuthTokenResponse {
  access_token: string;
  token_type: string;
  // Some auth servers serialize expires_in as a string — tolerate both.
  expires_in: number | string;
  refresh_token?: string;
  scope?: string;
  tenant?: string; // extension member: tenant slug for auto-discovery
}

/**
 * Map a token-endpoint response to a CachedToken, surviving the real-world
 * failure shapes: non-JSON 200 bodies (edge-proxy HTML), string expires_in,
 * and missing access_token — all become typed errors, never TypeErrors.
 */
function tokenFromResponse(
  status: number,
  bodyJson: unknown,
  headers: Record<string, string>,
  dpop: DpopKeyPair | undefined,
  fallbackScope: string[],
): CachedToken {
  if (status >= 400) {
    throw errorFromResponse(status, bodyJson, headers);
  }
  const body = (bodyJson && typeof bodyJson === "object" ? bodyJson : {}) as Partial<OAuthTokenResponse>;
  if (!body.access_token) {
    // e.g. an HTML page from an edge proxy with a 200 status
    throw new KnoxCallError(
      `token endpoint returned an unexpected response (status ${status})`,
      { status, headers, body: bodyJson },
    );
  }

  const tokenType = body.token_type === "DPoP" ? "DPoP" : "Bearer";
  if (tokenType === "DPoP" && !dpop) {
    // Sending `Authorization: DPoP` without a proof would 401-loop forever.
    throw new KnoxCallError(
      "server issued a DPoP-bound token but this client holds no DPoP " +
        'keypair — construct the client with dpop: "always"',
    );
  }

  const expiresIn =
    typeof body.expires_in === "number" ? body.expires_in : Number.parseFloat(String(body.expires_in ?? ""));
  const lifetimeMs = (Number.isFinite(expiresIn) ? expiresIn : 3600) * 1000;
  return {
    accessToken: redact(body.access_token),
    refreshToken: body.refresh_token ? redact(body.refresh_token) : undefined,
    expiresAt: Date.now() + lifetimeMs,
    lifetime: lifetimeMs,
    scope: body.scope ? body.scope.split(/\s+/).filter(Boolean) : fallbackScope,
    tokenType,
    cnfJkt: dpop?.thumbprint(),
    // extension member (RFC 6749 §5.1), used for tenant auto-discovery
    tenant: typeof body.tenant === "string" && body.tenant ? body.tenant : undefined,
  };
}

export interface FetchTokenInput {
  tokenEndpoint: string;
  bootstrap: Bootstrap;
  scope?: string[];
  dpop?: DpopKeyPair;
  fetchImpl?: typeof fetch;
}

async function postForm(
  url: string,
  body: Record<string, string>,
  init: { auth?: { user: string; pass: string }; dpopProof?: string; fetchImpl?: typeof fetch },
): Promise<{ status: number; bodyJson: unknown; headers: Record<string, string> }> {
  const headers: Record<string, string> = {
    "Content-Type": "application/x-www-form-urlencoded",
    Accept: "application/json",
  };
  if (init.auth) {
    headers.Authorization = "Basic " + Buffer.from(`${init.auth.user}:${init.auth.pass}`).toString("base64");
  }
  if (init.dpopProof) {
    headers.DPoP = init.dpopProof;
  }
  const form = new URLSearchParams(body).toString();
  const fetchImpl = init.fetchImpl ?? fetch;
  const res = await fetchImpl(url, { method: "POST", headers, body: form });
  const respHeaders: Record<string, string> = {};
  res.headers.forEach((v, k) => {
    respHeaders[k.toLowerCase()] = v;
  });
  let bodyJson: unknown = null;
  const text = await res.text();
  if (text) {
    try {
      bodyJson = JSON.parse(text);
    } catch {
      bodyJson = text;
    }
  }
  return { status: res.status, bodyJson, headers: respHeaders };
}

export async function fetchToken(input: FetchTokenInput): Promise<CachedToken> {
  const { bootstrap, tokenEndpoint, scope, dpop, fetchImpl } = input;

  // KNOXCALL_ACCESS_TOKEN — pre-acquired, no token endpoint call needed.
  if (bootstrap.type === "access_token") {
    return {
      accessToken: redact(bootstrap.accessToken),
      expiresAt: Date.now() + 60 * 60 * 1000, // assume 1h
      scope: scope ?? [],
      tokenType: dpop ? "DPoP" : "Bearer",
      cnfJkt: dpop?.thumbprint(),
    };
  }

  if (bootstrap.type === "stored_credentials") {
    // Tokens come from the `knoxcall login` credentials file. The file is
    // the cross-process cache and refresh authority (single-use rotated
    // refresh tokens); scope/DPoP posture is whatever login negotiated.
    return fetchStoredToken({
      path: resolveCredentialsPath(bootstrap.path),
      profile: resolveProfile(bootstrap.profile),
      tokenEndpoint,
      fetchImpl,
    });
  }

  const dpopProof = dpop?.sign({ method: "POST", url: tokenEndpoint });

  let formBody: Record<string, string>;
  let auth: { user: string; pass: string } | undefined;

  if (bootstrap.type === "client_credentials") {
    formBody = { grant_type: "client_credentials" };
    if (scope && scope.length > 0) formBody.scope = scope.join(" ");
    auth = { user: bootstrap.clientId, pass: bootstrap.clientSecret };
  } else if (bootstrap.type === "oidc_token_exchange") {
    formBody = {
      grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
      subject_token_type: "urn:ietf:params:oauth:token-type:id_token",
      subject_token: bootstrap.subjectToken,
      audience: "knoxcall:api",
    };
    if (scope && scope.length > 0) formBody.scope = scope.join(" ");
  } else {
    throw new KnoxCallError(`unsupported bootstrap type: ${(bootstrap as { type: string }).type}`);
  }

  const { status, bodyJson, headers } = await postForm(tokenEndpoint, formBody, {
    auth,
    dpopProof,
    fetchImpl,
  });

  return tokenFromResponse(status, bodyJson, headers, dpop, scope ?? []);
}

export interface RefreshTokenInput {
  tokenEndpoint: string;
  clientId: string;
  clientSecret: string;
  refreshToken: Redacted<string>;
  dpop?: DpopKeyPair;
  fetchImpl?: typeof fetch;
}

export async function refreshTokenGrant(input: RefreshTokenInput): Promise<CachedToken> {
  const dpopProof = input.dpop?.sign({ method: "POST", url: input.tokenEndpoint });
  const { status, bodyJson, headers } = await postForm(
    input.tokenEndpoint,
    {
      grant_type: "refresh_token",
      refresh_token: input.refreshToken.expose(),
    },
    {
      auth: { user: input.clientId, pass: input.clientSecret },
      dpopProof,
      fetchImpl: input.fetchImpl,
    },
  );

  return tokenFromResponse(status, bodyJson, headers, input.dpop, []);
}
