// Shared CLI plumbing — errors, token-endpoint POSTs, profile persistence.
//
// Mirrors knoxcall-python/src/knoxcall/cli/_common.py (the reference
// implementation — PARITY §13): same flows, messages, and persistence shape.

import {
  CredentialsFileLock,
  formatExpiry,
  writeProfile,
  type ProfileRecord,
} from "../auth/credentials-file.js";

// Reserved alias accepted by /oauth/authorize and the device endpoints; the
// server lazily provisions the tenant's real CLI client and returns its id
// as the `client_id` extension member on the token response.
export const CLI_CLIENT_ID = "knoxcall-cli";

/** Expected CLI failure — printed as a one-line message, never a stack trace. */
export class CLIError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CLIError";
  }
}

export type TokenBody = Record<string, unknown>;

function nonEmptyString(v: unknown): string {
  return typeof v === "string" && v ? v : "";
}

/**
 * POST a urlencoded form; return [status, parsed-JSON-or-empty-object].
 *
 * Connection failures throw CLIError with a human message. HTTP error
 * statuses are returned, not thrown — device polling needs the error codes.
 */
export async function postForm(
  url: string,
  form: Record<string, string>,
  fetchImpl: typeof fetch = fetch,
): Promise<[number, TokenBody]> {
  let res: Response;
  try {
    res = await fetchImpl(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
      },
      body: new URLSearchParams(form).toString(),
    });
  } catch (e) {
    const detail = e instanceof Error ? e.message : String(e);
    throw new CLIError(`could not reach ${url}: ${detail}`);
  }
  let body: unknown = null;
  try {
    body = await res.json();
  } catch {
    body = null;
  }
  const parsed =
    body && typeof body === "object" && !Array.isArray(body) ? (body as TokenBody) : {};
  return [res.status, parsed];
}

export function tokenErrorMessage(status: number, body: TokenBody): string {
  const detail =
    nonEmptyString(body.error_description) || nonEmptyString(body.error) || `HTTP ${status}`;
  return `sign-in failed: ${detail}`;
}

export interface PersistLoginInput {
  path: string;
  profile: string;
  baseUrl: string;
  tokenBody: TokenBody;
  fallbackTenant?: string;
}

/**
 * Store a successful token response as a credentials-file profile.
 *
 * Persists the `tenant` and `client_id` extension members — refreshes must
 * use the REAL per-tenant client id, not the `knoxcall-cli` alias. The write
 * happens UNDER the cross-process file lock: a login racing a concurrent
 * refresh must not lose a rotation.
 */
export async function persistLogin(input: PersistLoginInput): Promise<ProfileRecord> {
  const raw = input.tokenBody.expires_in;
  let expiresIn = typeof raw === "number" ? raw : Number.parseFloat(String(raw ?? ""));
  if (!Number.isFinite(expiresIn)) expiresIn = 3600;
  const record: ProfileRecord = {
    tenant: nonEmptyString(input.tokenBody.tenant) || input.fallbackTenant || null,
    base_url: input.baseUrl,
    client_id: nonEmptyString(input.tokenBody.client_id) || CLI_CLIENT_ID,
    refresh_token: nonEmptyString(input.tokenBody.refresh_token) || null,
    access_token: nonEmptyString(input.tokenBody.access_token) || null,
    access_token_expires_at: formatExpiry(Date.now() + expiresIn * 1000),
    scope: typeof input.tokenBody.scope === "string" ? input.tokenBody.scope : "",
  };
  const lock = new CredentialsFileLock(input.path);
  await lock.acquire();
  try {
    writeProfile(input.path, input.profile, record);
  } finally {
    lock.release();
  }
  return record;
}
