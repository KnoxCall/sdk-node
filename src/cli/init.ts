// `knoxcall init` — get started wrapping a provider SDK through KnoxCall
// (sdk-wrapping #17.4).
//
// SAFE BY DESIGN — this does NOT provision a tenant. It works against the tenant
// you are already signed in to (`knoxcall login`). Two modes:
//
//   knoxcall init
//       Scaffold mode: confirm who you're signed in as and print a two-step
//       wrap quickstart. No writes.
//
//   knoxcall init --provider stripe --secret-name wrap-stripe --host api.stripe.com
//       One-shot escrow: move a provider key into KnoxCall custody and print the
//       gateway base_url to point your SDK at. The KEY is read from the
//       KNOXCALL_WRAP_SECRET env var (never a flag) so it stays out of your shell
//       history/argv. Escrow is idempotent-ish server-side (409 on a dup name).
//
// Tenant provisioning + a fully headless one-shot flow (phantom kind 'o') are a
// deliberate follow-up — a CLI that mints tenants is a bigger, riskier surface.
// Mirrors will follow in the Python reference (PARITY §13) + the other SDKs.

import { StoredCredentials } from "../auth/bootstrap.js";
import { readProfile, resolveCredentialsPath, resolveProfile } from "../auth/credentials-file.js";
import { KnoxCall } from "../client.js";
import { CLIError } from "./common.js";

export interface InitArgs {
  profile?: string;
  baseUrl?: string;
  sandbox?: boolean;
  provider?: string;
  secretName?: string;
  host?: string;
}

export interface InitDeps {
  fetchImpl?: typeof fetch;
  env?: Record<string, string | undefined>;
  log?: (line: string) => void;
}

export async function runInit(args: InitArgs, deps: InitDeps = {}): Promise<number> {
  const log = deps.log ?? ((s: string) => console.log(s));
  const env = deps.env ?? process.env;

  // Auth: reuse the stored login. Never provision.
  const path = resolveCredentialsPath();
  const profile = resolveProfile(args.profile);
  if (readProfile(path, profile) === null) {
    throw new CLIError(`not logged in (profile '${profile}') — run \`knoxcall login\` first`);
  }
  const client = new KnoxCall({
    bootstrap: new StoredCredentials({ path, profile }),
    ...(deps.fetchImpl ? { fetchImpl: deps.fetchImpl } : {}),
    ...(args.baseUrl ? { baseUrl: args.baseUrl } : {}),
    ...(args.sandbox ? { sandbox: true } : {}),
  });

  const account = ((await client.account.get()) ?? {}) as unknown as Record<string, unknown>;
  const str = (v: unknown) => (typeof v === "string" ? v : "");
  const tenant = str(account.name) || str(account.company_name) || str(account.slug) || "(unknown)";
  log(`Signed in as ${tenant}.`);

  // One-shot escrow mode: --provider selects it; the other bits are then required.
  if (args.provider) {
    const name = (args.secretName ?? "").trim();
    const host = (args.host ?? "").trim().toLowerCase();
    const value = env.KNOXCALL_WRAP_SECRET;
    if (!name) throw new CLIError("--secret-name is required with --provider");
    if (!host) throw new CLIError("--host is required with --provider");
    if (!value) throw new CLIError("set the provider key in the KNOXCALL_WRAP_SECRET env var (not a flag)");

    await client.wrap.escrow({ provider: args.provider, name, value, hosts: [host] });
    const res = await client.wrap.gatewayUrl({ secret: name, host });
    log("");
    log(`Escrowed '${name}' for ${host} — your provider key is now in KnoxCall custody.`);
    log("Point a base-URL-only SDK at:");
    log(`  ${res.base_url}`);
    log("");
    log("…or transport-wrap an SDK that takes a fetch/HttpClient:");
    log(`  const knox = new KnoxCall({ /* your KnoxCall key */ });`);
    log(`  const sdk  = new SomeSDK("placeholder", { fetch: knox.wrap.fetch() });`);
    return 0;
  }

  // Scaffold mode: print the two-step quickstart, no writes.
  log("");
  log("Wrap a provider SDK through KnoxCall in two steps:");
  log("");
  log("1) Move the provider key into custody (key via KNOXCALL_WRAP_SECRET):");
  log("   KNOXCALL_WRAP_SECRET=sk_live_… \\");
  log("   knoxcall init --provider stripe --secret-name wrap-stripe --host api.stripe.com");
  log("");
  log("2) Route your SDK through KnoxCall (the key never re-enters your process):");
  log("   const knox = new KnoxCall({ /* your KnoxCall key */ });");
  log("   const sdk  = new SomeSDK(\"placeholder\", { fetch: knox.wrap.fetch() });");
  log("   // …or point a base-URL-only SDK at the base_url that step 1 prints.");
  return 0;
}
