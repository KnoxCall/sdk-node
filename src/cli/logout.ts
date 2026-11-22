// `knoxcall logout` — best-effort revoke, then remove the stored profile.
//
// Mirrors knoxcall-python/src/knoxcall/cli/logout.py (PARITY §13).

import {
  CredentialsFileLock,
  readProfile,
  removeProfile,
  resolveCredentialsPath,
  resolveProfile,
} from "../auth/credentials-file.js";
import { CLI_CLIENT_ID, CLIError, postForm } from "./common.js";

export interface LogoutArgs {
  profile?: string;
}

export interface LogoutDeps {
  fetchImpl?: typeof fetch;
}

export async function runLogout(args: LogoutArgs, deps: LogoutDeps = {}): Promise<number> {
  const path = resolveCredentialsPath();
  const profile = resolveProfile(args.profile);
  const record = readProfile(path, profile);
  if (record === null) {
    console.log(`No stored credentials for profile '${profile}' — nothing to do.`);
    return 0;
  }

  const refreshToken = typeof record.refresh_token === "string" ? record.refresh_token : "";
  const baseUrl = String(record.base_url ?? "").replace(/\/+$/, "");
  if (refreshToken && baseUrl) {
    try {
      await postForm(
        `${baseUrl}/oauth/revoke`,
        {
          token: refreshToken,
          token_type_hint: "refresh_token",
          client_id:
            (typeof record.client_id === "string" && record.client_id) || CLI_CLIENT_ID,
        },
        deps.fetchImpl,
      );
    } catch (e) {
      // Best-effort: removal proceeds even when revocation is unreachable.
      if (!(e instanceof CLIError)) throw e;
    }
  }

  const lock = new CredentialsFileLock(path);
  await lock.acquire();
  try {
    removeProfile(path, profile);
  } finally {
    lock.release();
  }
  console.log(`Logged out — removed profile '${profile}' from ${path}.`);
  return 0;
}
