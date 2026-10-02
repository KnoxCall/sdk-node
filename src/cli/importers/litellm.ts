// LiteLLM `config.yaml` → a KnoxCall import plan (AIGW-43).
//
// PURE ON PURPOSE. Nothing here touches the network or the filesystem: it takes
// the config text and returns a plan plus a list of warnings. That is what makes
// `--dry-run` trustworthy — the dry run and the real run compute the SAME plan
// from the SAME function, so what you were shown is what gets created. A dry run
// that walks a different code path from the apply is a dry run that lies.
//
// WHAT MAPS ONTO WHAT
//
//   model_list[].litellm_params.model  "openai/gpt-4o"  -> provider + default_model
//   model_list[].litellm_params.api_base                -> upstream (tenant-hosted)
//   several entries sharing one model_name              -> route_weights (AIGW-42)
//   model_list[].model_name (the client-facing alias)   -> gateway model_aliases
//   router_settings.num_retries                         -> routing_policy retries
//   litellm_settings.max_budget + budget_duration       -> budget_daily/monthly_usd
//
// The load-balancing case is the one worth noticing. In LiteLLM, listing the
// same `model_name` twice IS the load balancer. KnoxCall expresses that as
// weighted route selection on one agent, so the import collapses N deployments
// into one agent with N weighted routes rather than N agents that would each
// need their own token.
//
// WHAT IT REFUSES TO GUESS
//
// Credentials. LiteLLM configs carry `api_key: os.environ/OPENAI_API_KEY` or, in
// the configs people actually have, the key itself. The importer NEVER reads a
// literal key out of the file and never sends one anywhere: it records that the
// agent needs a secret and leaves the operator to create it. A migration tool
// that quietly ingests a plaintext key from a checked-in config, and thereby
// copies it into a second system, would be an odd thing for a credential-custody
// product to ship.

import { parseMiniYaml, MiniYamlError, type YamlValue } from "./mini-yaml.js";

export { MiniYamlError };

/** Provider ids the KnoxCall control plane accepts (PROVIDER_IDS, AIGW-41). */
export const KNOXCALL_PROVIDERS = [
  "anthropic", "openai", "gemini", "cohere", "azure-openai", "ollama",
  "groq", "together", "mistral", "deepseek", "fireworks", "xai",
  "bedrock", "openai-compatible",
] as const;

export type KnoxcallProvider = (typeof KNOXCALL_PROVIDERS)[number];

/**
 * LiteLLM's provider prefix → ours.
 *
 * Anything not in here becomes `openai-compatible` IF the entry supplies an
 * `api_base`, and is otherwise reported as unmapped rather than guessed at.
 */
const PROVIDER_PREFIX: Record<string, KnoxcallProvider> = {
  openai: "openai",
  azure: "azure-openai",
  azure_ai: "azure-openai",
  anthropic: "anthropic",
  gemini: "gemini",
  vertex_ai: "gemini",
  cohere: "cohere",
  cohere_chat: "cohere",
  ollama: "ollama",
  ollama_chat: "ollama",
  groq: "groq",
  together_ai: "together",
  togethercomputer: "together",
  mistral: "mistral",
  deepseek: "deepseek",
  fireworks_ai: "fireworks",
  xai: "xai",
  bedrock: "bedrock",
  bedrock_converse: "bedrock",
  openrouter: "openai-compatible",
  hosted_vllm: "openai-compatible",
  vllm: "openai-compatible",
  lm_studio: "openai-compatible",
  openai_like: "openai-compatible",
};

export interface PlannedRoute {
  /** The upstream model id, after the provider prefix is stripped. */
  model: string;
  provider: KnoxcallProvider;
  /** Tenant-supplied base URL, when the config gave one. */
  upstream: string | null;
  /** Relative weight, from LiteLLM `weight` or `rpm`; 1 when unspecified. */
  weight: number;
  /** How the config referenced its credential — recorded, never resolved. */
  credentialHint: string | null;
}

export interface PlannedAgent {
  /** Slug derived from the LiteLLM `model_name`. */
  slug: string;
  /** The LiteLLM `model_name` clients currently ask for. */
  sourceModelName: string;
  provider: KnoxcallProvider;
  defaultModel: string;
  upstream: string | null;
  /** More than one → weighted load balancing (AIGW-42 route_weights). */
  routes: PlannedRoute[];
  budgetDailyUsd: number | null;
  budgetMonthlyUsd: number | null;
  routingPolicy: Record<string, unknown> | null;
}

export interface ImportPlan {
  gatewayName: string;
  gatewaySlug: string;
  agents: PlannedAgent[];
  /** Gateway-level aliases so existing clients keep their model names working. */
  modelAliases: Record<string, string>;
  warnings: string[];
  /** Things the operator must do by hand afterwards. Never done for them. */
  manualSteps: string[];
}

function slugify(input: string): string {
  const slug = input
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 63);
  return slug || "imported-agent";
}

function asRecord(value: YamlValue | undefined): Record<string, YamlValue> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return value as Record<string, YamlValue>;
}

function asNumber(value: YamlValue | undefined): number | null {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && /^-?\d+(\.\d+)?$/.test(value)) return Number(value);
  return null;
}

/**
 * Split LiteLLM's `provider/model` into ours.
 *
 * A bare model with no prefix is left unmapped rather than assumed to be
 * OpenAI: "no prefix means OpenAI" is a LiteLLM default we would be inheriting
 * silently, and the cost of getting it wrong is an agent pointed at the wrong
 * provider with the wrong key.
 */
export function mapProvider(
  litellmModel: string,
  hasApiBase: boolean,
): { provider: KnoxcallProvider; model: string } | { provider: null; reason: string } {
  const slash = litellmModel.indexOf("/");
  if (slash < 0) {
    return {
      provider: null,
      reason:
        `"${litellmModel}" has no provider prefix. LiteLLM treats an unprefixed model as ` +
        `OpenAI; this importer will not assume that for you — set the agent's provider ` +
        `explicitly after import.`,
    };
  }
  const prefix = litellmModel.slice(0, slash);
  const rest = litellmModel.slice(slash + 1);
  const mapped = PROVIDER_PREFIX[prefix];
  if (mapped) {
    // vertex_ai and bedrock keep their full model path; the rest drop the prefix.
    return { provider: mapped, model: rest };
  }
  if (hasApiBase) {
    return { provider: "openai-compatible", model: rest };
  }
  return {
    provider: null,
    reason:
      `provider prefix "${prefix}" has no KnoxCall equivalent, and the entry gives no ` +
      `api_base to treat it as an OpenAI-compatible endpoint.`,
  };
}

/**
 * Translate `litellm_settings.max_budget` + `budget_duration` into ours.
 *
 * KnoxCall has a daily and a monthly cap; LiteLLM has one number and a duration
 * string. Anything that is not clearly a day or a month is reported rather than
 * converted — dividing a 7-day budget by seven to fake a daily one would be
 * inventing a number the operator never chose.
 */
export function mapBudget(
  maxBudget: number | null,
  duration: string | null,
): { daily: number | null; monthly: number | null; warning: string | null } {
  if (maxBudget === null) return { daily: null, monthly: null, warning: null };
  const d = (duration ?? "").trim().toLowerCase();
  if (d === "" || d === "1d" || d === "24h" || d === "1day" || d === "daily") {
    return { daily: maxBudget, monthly: null, warning: null };
  }
  if (d === "30d" || d === "1mo" || d === "1month" || d === "monthly") {
    return { daily: null, monthly: maxBudget, warning: null };
  }
  return {
    daily: null,
    monthly: null,
    warning:
      `budget_duration "${duration}" has no exact KnoxCall equivalent (we have a daily and a ` +
      `monthly cap). The $${maxBudget} budget was NOT imported — set it by hand rather than ` +
      `have this tool invent a rate.`,
  };
}

/** LiteLLM router settings → a KnoxCall routing_policy (AIGW-42). */
export function mapRoutingPolicy(router: Record<string, YamlValue> | null): Record<string, unknown> | null {
  if (!router) return null;
  const retries = asNumber(router.num_retries);
  if (retries === null || retries <= 0) return null;
  return {
    // LiteLLM counts RETRIES; KnoxCall counts ATTEMPTS including the first.
    max_attempts: Math.min(5, retries + 1),
    retry_on: ["429", "5xx", "timeout"],
    backoff_ms: 250,
    backoff_multiplier: 2,
    respect_retry_after: true,
  };
}

export interface ParseOptions {
  /** Name for the gateway the plan creates or targets. */
  gatewayName?: string;
}

/**
 * Build the import plan. Throws `MiniYamlError` on a config this cannot parse —
 * deliberately, rather than importing part of it.
 */
export function planLitellmImport(source: string, opts: ParseOptions = {}): ImportPlan {
  const doc = asRecord(parseMiniYaml(source));
  const warnings: string[] = [];
  const manualSteps: string[] = [];

  if (!doc) {
    throw new MiniYamlError("expected a top-level mapping (this does not look like a LiteLLM config)", 1);
  }
  const modelList = doc.model_list;
  if (!Array.isArray(modelList) || modelList.length === 0) {
    throw new MiniYamlError("no `model_list:` entries found — nothing to import", 1);
  }

  const routerSettings = asRecord(doc.router_settings);
  const litellmSettings = asRecord(doc.litellm_settings);
  const budget = mapBudget(
    asNumber(litellmSettings?.max_budget),
    typeof litellmSettings?.budget_duration === "string" ? litellmSettings.budget_duration : null,
  );
  if (budget.warning) warnings.push(budget.warning);
  const routingPolicy = mapRoutingPolicy(routerSettings);

  // Group by model_name: several entries under one name IS LiteLLM's load
  // balancer, and becomes one agent with weighted routes rather than N agents.
  const grouped = new Map<string, PlannedRoute[]>();
  const order: string[] = [];

  for (const raw of modelList) {
    const entry = asRecord(raw);
    if (!entry) {
      warnings.push("a model_list entry was not a mapping and was skipped");
      continue;
    }
    const modelName = typeof entry.model_name === "string" ? entry.model_name : null;
    const params = asRecord(entry.litellm_params);
    if (!modelName || !params) {
      warnings.push(
        `a model_list entry is missing model_name or litellm_params and was skipped: ` +
        `${JSON.stringify(raw).slice(0, 120)}`,
      );
      continue;
    }
    const litellmModel = typeof params.model === "string" ? params.model : null;
    if (!litellmModel) {
      warnings.push(`"${modelName}" has no litellm_params.model and was skipped`);
      continue;
    }
    const apiBase = typeof params.api_base === "string" && params.api_base.trim()
      ? params.api_base.trim()
      : null;
    const mapped = mapProvider(litellmModel, apiBase !== null);
    if (mapped.provider === null) {
      warnings.push(`"${modelName}": ${mapped.reason}`);
      continue;
    }

    // The credential is RECORDED, never read. `os.environ/X` is a reference we
    // can name; anything else is reported as a literal we deliberately did not
    // look at — this tool does not copy keys between systems.
    const rawKey = typeof params.api_key === "string" ? params.api_key : null;
    const credentialHint = rawKey === null
      ? null
      : rawKey.startsWith("os.environ/")
        ? rawKey
        : "a literal value in the config file (not read)";
    if (rawKey && !rawKey.startsWith("os.environ/")) {
      manualSteps.push(
        `"${modelName}" carries a literal api_key in your config. This importer did not read ` +
        `it. Treat that key as exposed — it is in a file — and rotate it at the provider when ` +
        `you create the KnoxCall secret.`,
      );
    }

    const weight = asNumber(params.weight) ?? asNumber(params.rpm) ?? 1;
    if (!grouped.has(modelName)) {
      grouped.set(modelName, []);
      order.push(modelName);
    }
    grouped.get(modelName)!.push({
      model: mapped.model,
      provider: mapped.provider,
      upstream: apiBase,
      weight: Math.max(1, Math.min(1000, Math.round(weight))),
      credentialHint,
    });
  }

  const agents: PlannedAgent[] = [];
  const modelAliases: Record<string, string> = {};
  const usedSlugs = new Set<string>();

  for (const modelName of order) {
    const routes = grouped.get(modelName)!;
    if (routes.length === 0) continue;
    let slug = slugify(modelName);
    let n = 2;
    while (usedSlugs.has(slug)) slug = `${slugify(modelName).slice(0, 58)}-${n++}`;
    usedSlugs.add(slug);

    const primary = routes[0];
    // Existing clients ask for the LiteLLM `model_name`. A gateway-level alias
    // keeps that working against the real upstream id, so the migration does not
    // require touching every call site on day one (AIGW-42).
    if (modelName !== primary.model) modelAliases[modelName] = primary.model;

    if (routes.length > 1) {
      const providers = new Set(routes.map((r) => r.provider));
      warnings.push(
        `"${modelName}" has ${routes.length} deployments — LiteLLM's load balancer. Imported as ` +
        `ONE agent with ${routes.length} weighted routes` +
        (providers.size > 1 ? ` across ${providers.size} providers` : "") +
        `, so it keeps one token instead of ${routes.length}.`,
      );
    }

    agents.push({
      slug,
      sourceModelName: modelName,
      provider: primary.provider,
      defaultModel: primary.model,
      upstream: primary.upstream,
      routes,
      budgetDailyUsd: budget.daily,
      budgetMonthlyUsd: budget.monthly,
      routingPolicy,
    });
  }

  if (agents.length === 0) {
    throw new MiniYamlError(
      "every model_list entry was unmappable — see the warnings above; nothing would be created",
      1,
    );
  }

  // Every agent needs a credential, and this tool will not create one.
  manualSteps.push(
    `Create a KnoxCall secret holding each provider key, then set it on the agent ` +
    `(\`upstream_secret_id\`). This importer never reads a key out of your config and never ` +
    `transmits one.`,
  );
  if (routesHave(agents, (r) => r.upstream !== null)) {
    manualSteps.push(
      `Some entries carry an api_base. Those upstreams are resolved and SSRF-checked when the ` +
      `agent is created — a private or link-local address is refused, because the request would ` +
      `carry your decrypted provider key there.`,
    );
  }
  if (budget.daily === null && budget.monthly === null) {
    manualSteps.push(
      `No importable budget was found. KnoxCall budgets are per agent, so set ` +
      `budget_daily_usd / budget_monthly_usd on the agents that need one.`,
    );
  }

  const gatewayName = opts.gatewayName ?? "Imported from LiteLLM";
  return {
    gatewayName,
    gatewaySlug: slugify(gatewayName),
    agents,
    modelAliases,
    warnings,
    manualSteps,
  };
}

function routesHave(agents: PlannedAgent[], pred: (r: PlannedRoute) => boolean): boolean {
  return agents.some((a) => a.routes.some(pred));
}

/** Render the plan as the human-readable dry-run report. */
export function formatPlan(plan: ImportPlan): string {
  const out: string[] = [];
  out.push(`Gateway:  ${plan.gatewayName}  (slug: ${plan.gatewaySlug})`);
  out.push(`Agents:   ${plan.agents.length}`);
  out.push("");
  for (const a of plan.agents) {
    out.push(`  ${a.slug}`);
    out.push(`    from model_name:  ${a.sourceModelName}`);
    out.push(`    provider:         ${a.provider}`);
    out.push(`    default_model:    ${a.defaultModel}`);
    if (a.upstream) out.push(`    upstream:         ${a.upstream}`);
    if (a.routes.length > 1) {
      out.push(`    routes:           ${a.routes.length} (weighted load balancing)`);
      for (const r of a.routes) {
        out.push(`      - ${r.provider}/${r.model}  weight ${r.weight}` +
          (r.upstream ? `  @ ${r.upstream}` : ""));
      }
    }
    if (a.budgetDailyUsd !== null) out.push(`    budget_daily_usd: ${a.budgetDailyUsd}`);
    if (a.budgetMonthlyUsd !== null) out.push(`    budget_monthly:   ${a.budgetMonthlyUsd}`);
    if (a.routingPolicy) out.push(`    routing_policy:   ${JSON.stringify(a.routingPolicy)}`);
    const creds = [...new Set(a.routes.map((r) => r.credentialHint).filter(Boolean))];
    if (creds.length) out.push(`    credential (yours to create): ${creds.join(", ")}`);
    out.push("");
  }
  if (Object.keys(plan.modelAliases).length > 0) {
    out.push("Gateway model aliases (so your existing clients keep working):");
    for (const [alias, target] of Object.entries(plan.modelAliases)) {
      out.push(`  ${alias}  ->  ${target}`);
    }
    out.push("");
  }
  if (plan.warnings.length > 0) {
    out.push("Warnings:");
    for (const w of plan.warnings) out.push(`  ! ${w}`);
    out.push("");
  }
  out.push("You will still need to:");
  for (const m of plan.manualSteps) out.push(`  - ${m}`);
  return out.join("\n");
}
