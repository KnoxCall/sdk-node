// `knoxcall ai` — the AI-gateway CONTROL plane from a terminal (AIGW-162).
//
// `ai exchange` (ai.ts) is the data-plane door: it needs no login, because the
// CI workload's OIDC token is the credential. Everything here is the opposite —
// it acts as the signed-in tenant, through the same `~/.knoxcall/credentials.json`
// profile `login` writes and `whoami` reads.
//
// WHY THIS EXISTS. Until now the five SDK CLIs shipped exactly one `ai`
// subcommand, `exchange`. A capable `knoxcall ai gateways|agents|mint|usage`
// lived in a standalone `cli/` package that was never published, never tested,
// never in CI and not in the workspaces — and it could not create a secret, a
// gateway or an agent, so it could not get you to a first call either. So there
// was no CLI golden path at all: the only way from "I have an API key" to "my
// app is calling an LLM through KnoxCall" was the browser or hand-written HTTP.
//
// The golden path these commands exist to make true, from a tenant with
// nothing in it:
//
//     export ANTHROPIC_API_KEY=sk-ant-...
//     knoxcall ai create-agent --name copilot --slug copilot \
//         --provider anthropic --secret-from-env ANTHROPIC_API_KEY
//     knoxcall ai mint --agent <id>
//     curl "$AGENT_URL/v1/messages" -H "Authorization: Bearer $TOKEN" ...
//
// Two commands, then a real streamed call. `create-agent` prints the agent id,
// the `agent_url` and the exact next command, so the path is discoverable
// without re-reading the docs.
//
// THREE RULES, each one a bug this shape invites:
//
//   1. A PROVIDER KEY IS NEVER AN ARGV VALUE. `--secret-from-env NAME` names
//      the environment variable to read; there is deliberately no
//      `--secret-value`. An argv value lands in shell history, in `ps` output
//      and in the CI log line that echoes the command. Same rule
//      `ai exchange` applies to KNOXCALL_SUBJECT_TOKEN and `init` to
//      KNOXCALL_WRAP_SECRET.
//
//   2. NO POSITIONAL ARGUMENTS. Four of the five SDK CLIs hand-roll their
//      parser and reject positionals outright; only python gets them free from
//      argparse. Ids are flags (`--gateway`, `--agent`) so the surface is the
//      same in all five rather than "the same except in Go".
//
//   3. AN AGENT WITHOUT AN UPSTREAM IS REFUSED HERE, not at its first call.
//      The API accepts `createAgent` with no `provider`/`upstream_secret_id`
//      and stores an agent whose first data-plane request 502s (AIGW-161).
//      A command whose entire purpose is "get me to a working call" must not
//      be able to produce that, so `--provider` and one of `--secret` /
//      `--secret-from-env` are required together.

import { readProfile, resolveCredentialsPath, resolveProfile } from "../auth/credentials-file.js";
import { StoredCredentials } from "../auth/bootstrap.js";
import { KnoxCall } from "../client.js";
import { CLIError } from "./common.js";

export interface AiControlArgs {
  profile?: string;
  baseUrl?: string;
  sandbox?: boolean;
  gateway?: string;
  agent?: string;
  name?: string;
  slug?: string;
  provider?: string;
  secret?: string;
  secretFromEnv?: string;
  upstream?: string;
  model?: string;
  kind?: string;
  period?: string;
}

export interface AiControlDeps {
  fetchImpl?: typeof fetch;
}

/** A client acting as the signed-in tenant, or a message telling them to log in. */
function clientFor(args: AiControlArgs, deps: AiControlDeps): KnoxCall {
  const path = resolveCredentialsPath();
  const profile = resolveProfile(args.profile);
  if (readProfile(path, profile) === null) {
    throw new CLIError(`not logged in (profile '${profile}') — run \`knoxcall login\``);
  }
  return new KnoxCall({
    bootstrap: new StoredCredentials({ path, profile }),
    // `--sandbox` selects the Test data space (sandbox.knoxcall.com). It was
    // accepted and then dropped on the floor here, which is precisely the
    // silently-ignored flag the per-subcommand tables exist to prevent -- and
    // the worse kind, because the help says it operates against Test while the
    // request went to Live. Ruby forwards it; so does this now.
    ...(args.sandbox === true ? { sandbox: true } : {}),
    ...(args.baseUrl ? { baseUrl: args.baseUrl } : {}),
    ...(deps.fetchImpl ? { fetchImpl: deps.fetchImpl } : {}),
  });
}

function required(value: string | undefined, flag: string): string {
  if (!value) throw new CLIError(`${flag} is required`);
  return value;
}

// ── knoxcall ai gateways ────────────────────────────────────────────────────

export async function runAiGateways(args: AiControlArgs, deps: AiControlDeps = {}): Promise<number> {
  const client = clientFor(args, deps);
  const page = await client.aiGateway.listGateways({ per_page: 100 });
  if (page.data.length === 0) {
    console.error("No AI gateways. `knoxcall ai create-agent` will create one for you.");
    return 0;
  }
  for (const g of page.data) console.log(`${g.id}  ${g.slug}  ${g.name}`);
  return 0;
}

// ── knoxcall ai agents --gateway ID ─────────────────────────────────────────

export async function runAiAgents(args: AiControlArgs, deps: AiControlDeps = {}): Promise<number> {
  const gatewayId = required(args.gateway, "--gateway");
  const client = clientFor(args, deps);
  const page = await client.aiGateway.listAgents(gatewayId, { per_page: 100 });
  if (page.data.length === 0) {
    console.error("No agents in that gateway.");
    return 0;
  }
  // agent_url is on every projection since AIGW-161, so a list is enough to
  // point an SDK at an existing agent — no follow-up GET.
  for (const a of page.data) console.log(`${a.id}  ${a.slug}  ${a.agent_url}`);
  return 0;
}

// ── knoxcall ai create-agent ────────────────────────────────────────────────

/**
 * Resolve the gateway to create under.
 *
 * `--gateway` takes an id OR a slug. With no `--gateway`: use the tenant's only
 * gateway, or create one when they have none — that is what makes the command
 * work on a fresh tenant, which is the whole point. With SEVERAL and no flag it
 * refuses and lists them rather than picking: "whichever sorts first" is how
 * the quickstart wizard silently landed a second agent in the wrong gateway.
 */
async function resolveGateway(client: KnoxCall, wanted: string | undefined): Promise<string> {
  const page = await client.aiGateway.listGateways({ per_page: 100 });
  if (wanted) {
    const hit = page.data.find((g) => g.id === wanted || g.slug === wanted);
    if (!hit) {
      const known = page.data.map((g) => `${g.slug} (${g.id})`).join(", ") || "none";
      throw new CLIError(`no gateway '${wanted}' — this tenant has: ${known}`);
    }
    return hit.id;
  }
  if (page.data.length === 1) return page.data[0].id;
  if (page.data.length === 0) {
    const created = await client.aiGateway.createGateway({ name: "Default", slug: "default" });
    console.error(`created gateway ${created.slug} (${created.id})`);
    return created.id;
  }
  const known = page.data.map((g) => `${g.slug} (${g.id})`).join(", ");
  throw new CLIError(
    `--gateway is required: this tenant has ${page.data.length} gateways (${known}). ` +
      "Picking one for you would put the agent somewhere you did not choose.",
  );
}

/**
 * Resolve the upstream secret, escrowing one from the environment if asked.
 *
 * The key is read from `process.env[NAME]`, never from a flag — see rule 1.
 * Re-running with the same `--secret-from-env` reuses the existing secret by
 * name rather than creating a second copy of the same credential.
 */
async function resolveSecret(client: KnoxCall, args: AiControlArgs): Promise<string> {
  if (args.secret) return args.secret;
  const envName = required(args.secretFromEnv, "--secret or --secret-from-env");
  const value = (process.env[envName] ?? "").trim();
  if (!value) {
    throw new CLIError(
      `${envName} is not set — put your provider key there. There is deliberately no ` +
        "--secret-value flag: an argv value lands in shell history, ps output and the CI log.",
    );
  }
  const name = `ai-gateway-${args.slug ?? "agent"}-key`;
  const existing = await client.secrets.list({ per_page: 100 });
  const hit = existing.data.find((s) => s.name === name);
  if (hit) {
    console.error(`reusing secret '${name}' (${hit.id})`);
    return hit.id;
  }
  const created = await client.secrets.create({ name, value });
  console.error(`escrowed secret '${name}' (${created.id}) — the key is now in KnoxCall custody`);
  return created.id;
}

export async function runAiCreateAgent(args: AiControlArgs, deps: AiControlDeps = {}): Promise<number> {
  const slug = required(args.slug, "--slug");
  // Rule 3: refuse here rather than let the API store an agent with no upstream
  // whose first data-plane call 502s.
  const provider = required(args.provider, "--provider");
  if (!args.secret && !args.secretFromEnv) {
    throw new CLIError(
      "one of --secret or --secret-from-env is required: an agent created without an " +
        "upstream credential is accepted by the API and 502s on its first call.",
    );
  }

  const client = clientFor(args, deps);
  const gatewayId = await resolveGateway(client, args.gateway);
  const secretId = await resolveSecret(client, args);

  const agent = await client.aiGateway.createAgent(gatewayId, {
    name: args.name ?? slug,
    slug,
    provider,
    upstream_secret_id: secretId,
    ...(args.upstream ? { upstream: args.upstream } : {}),
    ...(args.model ? { default_model: args.model } : {}),
  });

  // stdout: the agent id, so `$(...)` captures exactly that. Everything a human
  // needs next goes to stderr, including the command that follows.
  console.log(agent.id);
  console.error(`\n  agent:     ${agent.slug} (${agent.id})`);
  console.error(`  gateway:   ${gatewayId}`);
  console.error(`  provider:  ${provider}`);
  if (agent.agent_url) console.error(`  base_url:  ${agent.agent_url}`);
  console.error(`\n  Next:  knoxcall ai mint --agent ${agent.id}`);
  return 0;
}

// ── knoxcall ai mint --agent ID ─────────────────────────────────────────────

export async function runAiMint(args: AiControlArgs, deps: AiControlDeps = {}): Promise<number> {
  const agentId = required(args.agent, "--agent");
  const client = clientFor(args, deps);
  const minted = await client.aiGateway.mintToken(agentId, {
    ...(args.kind ? { kind: args.kind as "agent" } : {}),
    ...(args.name ? { name: args.name } : {}),
  });
  // The plaintext is returned ONCE. stdout carries only the token so
  // `> token.txt` captures the token and nothing else; the metadata and the
  // warning go to stderr.
  console.log(minted.token);
  console.error(`\n  id:       ${minted.id}`);
  console.error(`  kind:     ${minted.kind}`);
  console.error(`  prefix:   ${minted.prefix}`);
  console.error(`  dpop:     ${minted.dpop_required}`);
  console.error(`  expires:  ${minted.expires_at ?? "never"}`);
  console.error("\n  Save this token now — it will not be shown again.");
  return 0;
}

// ── knoxcall ai usage ───────────────────────────────────────────────────────

export async function runAiUsage(args: AiControlArgs, deps: AiControlDeps = {}): Promise<number> {
  const client = clientFor(args, deps);
  const usage = await client.aiGateway.usage({
    period: (args.period ?? "30d") as "7d" | "30d" | "90d",
    ...(args.agent ? { agent_id: args.agent } : {}),
  });
  console.log(`Usage — last ${usage.period_days} days${args.agent ? ` (agent ${args.agent})` : ""}`);
  console.log(`  requests:      ${usage.totals.requests}`);
  console.log(`  input tokens:  ${usage.totals.input_tokens}`);
  console.log(`  output tokens: ${usage.totals.output_tokens}`);
  console.log(`  cost (USD):    ${Number(usage.totals.cost_usd).toFixed(4)}`);
  console.log(`  unpriced:      ${usage.totals.unpriced_requests}`);
  if (usage.by_model.length === 0) {
    console.log("\nNo usage in this period.");
    return 0;
  }
  console.log("\nBy model:");
  for (const m of usage.by_model) {
    console.log(
      `  ${m.provider}/${m.model}  ${m.requests} req  in ${m.input_tokens}  ` +
        `out ${m.output_tokens}  $${Number(m.cost_usd).toFixed(4)}`,
    );
  }
  return 0;
}
