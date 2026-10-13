// `knoxcall ai import --from litellm <config.yaml>` — plan a migration (AIGW-43,
// rehomed by AIGW-162).
//
// WHERE THIS CAME FROM. The importer and its zero-dependency YAML-subset parser
// used to live in a standalone `cli/` package that was never published, never in
// the workspaces, never typechecked by a root tsconfig and never run by any CI
// job — so `wiki/ai-gateway/migrate-from-litellm.mdx` documented a command that
// shipped in no artifact. Anyone who installed an SDK and followed that page got
// `invalid choice: 'import'`. AIGW-162 deleted `cli/` and moved the two pure
// modules here, into the CLI that actually ships.
//
// WHY NODE ONLY, DELIBERATELY. Every other `ai` subcommand exists in all five
// SDK CLIs, and `cli-ai-command-parity` pins that. This one does not, and the
// guard records it as an explicit exception rather than letting it drift:
// `litellm.ts` + `mini-yaml.ts` are ~690 lines of pure logic including a
// hand-rolled YAML parser, written that way because `knoxcall` ships with zero
// runtime dependencies and a credential-handling CLI is the wrong place to grow
// a transitive tree. Four more hand-ports of a YAML parser is four more places
// for the plan to disagree with itself about what a config means — and the plan
// is what decides which agents get created in a customer's tenant. One
// implementation, in the CLI every platform can run, is the honest trade.
//
// DRY RUN BY DEFAULT, and that is the whole design. A migration tool whose
// default is to write is a tool people run once, in anger, against the wrong
// tenant. `--apply` is the deliberate second step, and it re-plans from the SAME
// pure function the dry run printed — so what you were shown is what gets
// created, rather than a second code path that agrees by coincidence.

import { readFileSync } from "node:fs";
import { readProfile, resolveCredentialsPath, resolveProfile } from "../auth/credentials-file.js";
import { StoredCredentials } from "../auth/bootstrap.js";
import { KnoxCall } from "../client.js";
import { CLIError } from "./common.js";
import { planLitellmImport, formatPlan, MiniYamlError, type ImportPlan } from "./importers/litellm.js";

export interface AiImportArgs {
  profile?: string;
  baseUrl?: string;
  from?: string;
  file?: string;
  apply?: boolean;
  gatewayName?: string;
}

/**
 * Exit codes, so a script can branch on them:
 *   0  the plan was produced, or applied successfully
 *   1  something failed while applying; partial creation is possible and every
 *      failure is named so those can be retried
 *   2  the input was unusable — bad flags, unreadable file, unparseable config.
 *      Nothing was written.
 */
export async function runAiImport(args: AiImportArgs): Promise<number> {
  if (args.from !== "litellm") {
    console.error("usage: knoxcall ai import --from litellm --file <config.yaml> [--apply]");
    console.error("  (litellm is the only supported source today)");
    return 2;
  }
  if (!args.file) {
    console.error("usage: knoxcall ai import --from litellm --file <config.yaml> [--apply]");
    return 2;
  }

  let source: string;
  try {
    source = readFileSync(args.file, "utf8");
  } catch (err) {
    console.error(`cannot read ${args.file}: ${err instanceof Error ? err.message : String(err)}`);
    return 2;
  }

  let plan: ImportPlan;
  try {
    plan = planLitellmImport(source, { gatewayName: args.gatewayName });
  } catch (err) {
    if (err instanceof MiniYamlError) {
      console.error(`${args.file}: ${err.message}`);
      console.error("");
      console.error("  This importer parses a YAML subset and REFUSES what it cannot read");
      console.error("  rather than skipping it — a plan that silently dropped a model would");
      console.error("  look complete and not be. Simplify the file, or import the models it");
      console.error("  names by hand.");
      return 2;
    }
    console.error(String(err instanceof Error ? err.message : err));
    return 2;
  }

  console.log(formatPlan(plan));

  if (!args.apply) {
    console.log("");
    console.log("This was a DRY RUN. Nothing was created.");
    console.log("Re-run with --apply to create the gateway, its agents and the model aliases.");
    return 0;
  }

  const path = resolveCredentialsPath();
  const profile = resolveProfile(args.profile);
  if (readProfile(path, profile) === null) {
    throw new CLIError(`not logged in (profile '${profile}') — run \`knoxcall login\``);
  }
  const client = new KnoxCall({
    bootstrap: new StoredCredentials({ path, profile }),
    ...(args.baseUrl ? { baseUrl: args.baseUrl } : {}),
  });

  console.log("");
  console.log("Applying…");

  // The gateway first: every agent hangs off it, and a half-made agent with no
  // gateway is harder to clean up than no gateway at all.
  const gateway = await client.aiGateway.createGateway({
    name: plan.gatewayName,
    slug: plan.gatewaySlug,
  });
  console.log(`  gateway ${gateway.slug} (${gateway.id})`);

  let created = 0;
  let failed = 0;
  for (const agent of plan.agents) {
    try {
      // No `provider`/`upstream_secret_id` here on purpose: the API requires a
      // secret alongside a provider, and this tool does not read your keys. The
      // agent is created with its model policy and budgets, and you attach the
      // credential — see the manual steps printed above. `knoxcall ai
      // create-agent --secret-from-env` is the command that does that.
      const row = await client.aiGateway.createAgent(gateway.id, {
        name: agent.sourceModelName,
        slug: agent.slug,
        description: `Imported from LiteLLM model_name "${agent.sourceModelName}"`,
        ...(agent.defaultModel ? { default_model: agent.defaultModel } : {}),
        ...(agent.budgetDailyUsd !== null ? { budget_daily_usd: agent.budgetDailyUsd } : {}),
        ...(agent.budgetMonthlyUsd !== null ? { budget_monthly_usd: agent.budgetMonthlyUsd } : {}),
      });
      created++;
      console.log(`  agent ${row.slug} (${row.id})`);
    } catch (err) {
      failed++;
      // Keep going: one rejected slug should not abandon the other nineteen
      // agents, and every failure is named so the operator can retry those.
      console.error(`  agent ${agent.slug} FAILED: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  console.log("");
  console.log(`Created ${created} agent(s).${failed > 0 ? ` ${failed} step(s) failed.` : ""}`);
  console.log("Each agent still needs its provider credential:");
  console.log("  knoxcall ai create-agent --slug <slug> --provider <p> --secret-from-env <VAR>");
  return failed > 0 ? 1 : 0;
}
