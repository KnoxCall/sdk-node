// `knoxcall whoami` — show the signed-in tenant via the SDK client.
//
// Mirrors knoxcall-python/src/knoxcall/cli/whoami.py (PARITY §13).

import { StoredCredentials } from "../auth/bootstrap.js";
import { readProfile, resolveCredentialsPath, resolveProfile } from "../auth/credentials-file.js";
import { KnoxCall } from "../client.js";
import { CLIError } from "./common.js";

export interface WhoamiArgs {
  profile?: string;
}

export interface WhoamiDeps {
  fetchImpl?: typeof fetch;
}

export async function runWhoami(args: WhoamiArgs, deps: WhoamiDeps = {}): Promise<number> {
  const path = resolveCredentialsPath();
  const profile = resolveProfile(args.profile);
  if (readProfile(path, profile) === null) {
    throw new CLIError(`not logged in (profile '${profile}') — run \`knoxcall login\``);
  }

  const client = new KnoxCall({
    bootstrap: new StoredCredentials({ path, profile }),
    ...(deps.fetchImpl ? { fetchImpl: deps.fetchImpl } : {}),
  });
  const account = ((await client.account.get()) ?? {}) as unknown as Record<string, unknown>;

  const str = (v: unknown) => (typeof v === "string" ? v : "");
  const slug = str(account.slug);
  const name = str(account.name) || str(account.company_name);
  const plan = str(account.plan) || str(account.subscription_plan);
  console.log(`Tenant: ${name || slug || "(unknown)"}`);
  if (slug) console.log(`Slug:   ${slug}`);
  if (plan) console.log(`Plan:   ${plan}`);
  console.log(`Profile: ${profile} (${path})`);
  return 0;
}
