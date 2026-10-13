// KnoxCall CLI — `knoxcall login` / `logout` / `whoami`.
//
// Mirrors knoxcall-python/src/knoxcall/cli/__init__.py (the reference
// implementation — PARITY §13): same command surface, flags, messages, and
// exit codes. Arg parsing is hand-rolled (zero runtime dependencies) but
// keeps argparse semantics: `--help` exits 0, usage errors print the usage
// line + `<prog>: error: <message>` and exit 2, expected runtime failures
// print `error: <message>` and exit 1.

import { KnoxCallError } from "../error.js";
import { CLIError } from "./common.js";
import { runLogin, type LoginArgs } from "./login.js";
import { runLogout, type LogoutArgs } from "./logout.js";
import { runWhoami, type WhoamiArgs } from "./whoami.js";
import { runInit, type InitArgs } from "./init.js";
import { runAiExchange, type AiExchangeArgs } from "./ai.js";
import {
  runAiGateways,
  runAiAgents,
  runAiCreateAgent,
  runAiMint,
  runAiUsage,
  type AiControlArgs,
} from "./ai-control.js";
import { runAiImport, type AiImportArgs } from "./ai-import.js";

const PROG = "knoxcall";
const COMMANDS = ["login", "logout", "whoami", "init", "ai"] as const;
type Command = (typeof COMMANDS)[number];

// `ai` is the only command with a SUB-command of its own. Rather than
// generalise the parser (python gets nesting free from argparse; the other
// four hand-roll), the sub-command is consumed here and the rest of argv is
// parsed by the same table-driven loop as everything else.
// AIGW-162. `exchange` is the data-plane door and needs no login; the rest
// are the control plane and act as the signed-in tenant. Both live under
// `ai` because they are one surface to a user, and the golden path crosses
// between them: create-agent -> mint -> a real call.
//
// Every one of these takes FLAGS ONLY, no positionals. Four of the five SDK
// CLIs hand-roll their parser and reject positionals outright (only python
// gets them free from argparse), so an id as a positional would be a surface
// that is the same in all five except in shape.
// `import` is NODE-ONLY, deliberately, and cli-ai-command-parity records it as
// an explicit exception: it carries a hand-rolled YAML-subset parser (the CLI
// ships zero runtime dependencies), and four more hand-ports of that parser is
// four more places for the migration plan to disagree with itself about what a
// config means. See ai-import.ts.
const AI_COMMANDS = ["exchange", "gateways", "agents", "create-agent", "mint", "usage", "import"] as const;
type AiCommand = (typeof AI_COMMANDS)[number];
const AI_CHOICES = AI_COMMANDS.join(",");

const TOP_USAGE = "usage: knoxcall [-h] {login,logout,whoami,init,ai} ...";

const TOP_HELP = `${TOP_USAGE}

KnoxCall command-line interface — sign in once, every SDK on this machine picks it up.

positional arguments:
  {login,logout,whoami,init,ai}
    login               sign in with your browser and store credentials locally
    logout              revoke and remove stored credentials
    whoami              show the signed-in tenant
    init                get started wrapping a provider SDK (escrow a key)
    ai                  AI gateway operations

options:
  -h, --help            show this help message and exit`;

const LOGIN_USAGE = `usage: knoxcall login [-h] [--tenant TENANT] [--base-url BASE_URL] [--sandbox]
                      [--profile PROFILE] [--device] [--no-browser]`;

const LOGIN_HELP = `${LOGIN_USAGE}

options:
  -h, --help           show this help message and exit
  --tenant TENANT      tenant slug hint for the sign-in page
  --base-url BASE_URL  management API base URL (default
                       https://api.knoxcall.com, or KNOXCALL_BASE_URL)
  --sandbox            log in against the sandbox environment
  --profile PROFILE    credentials profile name (default: KNOXCALL_PROFILE or
                       'default')
  --device             use the device-code flow (headless/SSH machines)
  --no-browser         never open a browser (implies the device-code flow)`;

const LOGOUT_USAGE = "usage: knoxcall logout [-h] [--profile PROFILE]";

const LOGOUT_HELP = `${LOGOUT_USAGE}

options:
  -h, --help         show this help message and exit
  --profile PROFILE  credentials profile name (default: KNOXCALL_PROFILE or
                     'default')`;

const WHOAMI_USAGE = "usage: knoxcall whoami [-h] [--profile PROFILE]";

const WHOAMI_HELP = `${WHOAMI_USAGE}

options:
  -h, --help         show this help message and exit
  --profile PROFILE  credentials profile name (default: KNOXCALL_PROFILE or
                     'default')`;

const INIT_USAGE = `usage: knoxcall init [-h] [--profile PROFILE] [--base-url BASE_URL] [--sandbox]
                     [--provider PROVIDER] [--secret-name NAME] [--host HOST]`;

const INIT_HELP = `${INIT_USAGE}

Get started wrapping a provider SDK through KnoxCall. Works against the tenant you
are already signed in to — it does NOT provision a tenant. With no --provider it
prints a quickstart; with --provider it escrows a key (read from the
KNOXCALL_WRAP_SECRET env var, never a flag) and prints the gateway base_url.

options:
  -h, --help           show this help message and exit
  --profile PROFILE    credentials profile name (default: KNOXCALL_PROFILE or 'default')
  --base-url BASE_URL  management API base URL (default https://api.knoxcall.com)
  --sandbox            operate against the sandbox environment
  --provider PROVIDER  provider to escrow a key for (e.g. stripe); enables escrow mode
  --secret-name NAME   name for the escrowed credential (required with --provider)
  --host HOST          upstream host to pin the credential to (required with --provider)`;

const AI_USAGE = `usage: knoxcall ai [-h] {${AI_CHOICES}} ...`;

const AI_HELP = `${AI_USAGE}

AI-gateway operations.

From a tenant with nothing in it to a real streamed call, in two commands:

    export ANTHROPIC_API_KEY=sk-ant-...
    knoxcall ai create-agent --name copilot --slug copilot \\
        --provider anthropic --secret-from-env ANTHROPIC_API_KEY
    knoxcall ai mint --agent <id>

positional arguments:
  {${AI_CHOICES}}
    exchange            exchange a CI OIDC token for a capability token (no login needed)
    gateways            list AI gateways
    agents              list a gateway’s agents
    create-agent        create an agent with its upstream credential
    mint                mint a capability token (shown once)
    usage               cost + token usage by model
    import              plan a migration from a LiteLLM config (dry run by default)

options:
  -h, --help            show this help message and exit`;

const AI_EXCHANGE_USAGE = `usage: knoxcall ai exchange [-h] [--tenant TENANT] [--sandbox]
                            [--base-url BASE_URL] [--resource RESOURCE]
                            [--audience AUDIENCE]`;

const AI_EXCHANGE_HELP = `${AI_EXCHANGE_USAGE}

Exchange a CI workload's OIDC id_token for a short-lived AI-gateway capability
token (RFC 8693). Needs no KnoxCall credential and no \`knoxcall login\`: the
subject token IS the credential.

The subject token is read from the KNOXCALL_SUBJECT_TOKEN environment variable,
never a flag — an argv value lands in shell history, ps output and the CI log.

Only the token is printed to stdout, so it can be captured:
    export KC_TOKEN="$(knoxcall ai exchange --tenant acme)"

options:
  -h, --help           show this help message and exit
  --tenant TENANT      tenant slug; the data-plane host is
                       https://{tenant}.knoxcall.com
  --sandbox            use the Test data space (sandbox-{tenant}.knoxcall.com)
  --base-url BASE_URL  full data-plane origin; overrides --tenant
  --resource RESOURCE  RFC 8707 resource indicator (an MCP server's
                       \`resource\`); narrows the token to that one MCP server
  --audience AUDIENCE  defaults to knoxcall:gateway`;

// Every control-plane subcommand accepts these; they select WHICH tenant and
// WHICH stored login is acting.
const AI_COMMON_HELP = `
  -h, --help           show this help message and exit
  --profile PROFILE    credentials profile name (default: KNOXCALL_PROFILE or
                       'default')
  --base-url BASE_URL  management API base URL (default https://api.knoxcall.com)
  --sandbox            operate against the Test data space`;

const AI_GATEWAYS_USAGE = "usage: knoxcall ai gateways [-h] [--profile PROFILE] [--base-url BASE_URL] [--sandbox]";
const AI_GATEWAYS_HELP = `${AI_GATEWAYS_USAGE}

List this tenant’s AI gateways as \`id  slug  name\`.

options:${AI_COMMON_HELP}`;

const AI_AGENTS_USAGE = "usage: knoxcall ai agents [-h] --gateway GATEWAY [--profile PROFILE] [--base-url BASE_URL] [--sandbox]";
const AI_AGENTS_HELP = `${AI_AGENTS_USAGE}

List a gateway’s agents as \`id  slug  agent_url\`. The third column is the
base_url to point an AI SDK at, so this is enough to wire up an existing
agent without a second call.

options:
  --gateway GATEWAY    gateway id${AI_COMMON_HELP}`;

const AI_CREATE_AGENT_USAGE = `usage: knoxcall ai create-agent [-h] --slug SLUG --provider PROVIDER
                                (--secret SECRET | --secret-from-env VAR)
                                [--name NAME] [--gateway GATEWAY] [--model MODEL]
                                [--upstream URL] [--profile PROFILE]
                                [--base-url BASE_URL] [--sandbox]`;
const AI_CREATE_AGENT_HELP = `${AI_CREATE_AGENT_USAGE}

Create an agent wired to a provider credential, and print the command that
follows. Works on a tenant with nothing in it: with no --gateway it uses your
only gateway, or creates one when you have none. With several it refuses and
lists them rather than picking one for you.

The provider key is read from the environment named by --secret-from-env,
never from a flag — an argv value lands in shell history, ps output and the CI
log. There is deliberately no --secret-value.

--provider and a credential are both required: the API accepts an agent with
neither and stores one whose first data-plane call 502s.

Only the agent id goes to stdout, so it can be captured:
    AGENT="$(knoxcall ai create-agent --slug copilot --provider anthropic \\
        --secret-from-env ANTHROPIC_API_KEY)"

options:
  --slug SLUG          url slug; the agent is served at /v1/ai/{slug}
  --provider PROVIDER  provider id (anthropic, openai, groq, bedrock, …). The
                       catalog is server-side; an unknown value is a 400 that
                       names the valid set.
  --secret SECRET      id of an existing KnoxCall secret holding the key
  --secret-from-env VAR  environment variable holding the key; escrows it as a
                       new secret, reusing one of the same name if present
  --name NAME          display name (defaults to --slug)
  --gateway GATEWAY    gateway id or slug to create under
  --model MODEL        default model (required for openai-compatible)
  --upstream URL       upstream base URL; required for azure-openai, ollama,
                       bedrock and openai-compatible${AI_COMMON_HELP}`;

const AI_MINT_USAGE = "usage: knoxcall ai mint [-h] --agent AGENT [--kind KIND] [--name NAME] [--profile PROFILE] [--base-url BASE_URL] [--sandbox]";
const AI_MINT_HELP = `${AI_MINT_USAGE}

Mint a capability token for an agent. The plaintext is returned ONCE and is
the only thing on stdout, so it can be captured:
    TOKEN="$(knoxcall ai mint --agent ag_123)"

options:
  --agent AGENT        agent id
  --kind KIND          agent | read | tool | oneshot (default agent)
  --name NAME          label for the token${AI_COMMON_HELP}`;

const AI_IMPORT_USAGE = "usage: knoxcall ai import [-h] --from litellm --file FILE [--apply] [--gateway-name NAME] [--profile PROFILE] [--base-url BASE_URL]";
const AI_IMPORT_HELP = `${AI_IMPORT_USAGE}

Read a LiteLLM config.yaml and print exactly what it would create. DRY RUN
unless you pass --apply, which re-plans from the same function the dry run
printed — what you were shown is what gets created.

It never reads an API key out of your config and never transmits one. Attach
credentials afterwards with \`knoxcall ai create-agent --secret-from-env\`.

Exit codes: 0 planned or applied, 1 a step failed while applying (partial
creation is possible; every failure is named), 2 the input was unusable and
nothing was written.

options:
  --from SOURCE        only \`litellm\` today
  --file FILE          path to the config
  --apply              actually create the gateway, agents and aliases
  --gateway-name NAME  name for the gateway it creates${AI_COMMON_HELP}`;

const AI_USAGE_USAGE = "usage: knoxcall ai usage [-h] [--period PERIOD] [--agent AGENT] [--profile PROFILE] [--base-url BASE_URL] [--sandbox]";
const AI_USAGE_HELP = `${AI_USAGE_USAGE}

Cost and token usage by model.

options:
  --period PERIOD      7d | 30d | 90d (default 30d)
  --agent AGENT        scope to one agent${AI_COMMON_HELP}`;

interface OptionSpec {
  takesValue: boolean;
  dest: string;
}

const LOGIN_OPTIONS: Record<string, OptionSpec> = {
  "--tenant": { takesValue: true, dest: "tenant" },
  "--base-url": { takesValue: true, dest: "baseUrl" },
  "--sandbox": { takesValue: false, dest: "sandbox" },
  "--profile": { takesValue: true, dest: "profile" },
  "--device": { takesValue: false, dest: "device" },
  "--no-browser": { takesValue: false, dest: "noBrowser" },
};

const PROFILE_ONLY_OPTIONS: Record<string, OptionSpec> = {
  "--profile": { takesValue: true, dest: "profile" },
};

const INIT_OPTIONS: Record<string, OptionSpec> = {
  "--profile": { takesValue: true, dest: "profile" },
  "--base-url": { takesValue: true, dest: "baseUrl" },
  "--sandbox": { takesValue: false, dest: "sandbox" },
  "--provider": { takesValue: true, dest: "provider" },
  "--secret-name": { takesValue: true, dest: "secretName" },
  "--host": { takesValue: true, dest: "host" },
};

const AI_EXCHANGE_OPTIONS: Record<string, OptionSpec> = {
  "--tenant": { takesValue: true, dest: "tenant" },
  "--sandbox": { takesValue: false, dest: "sandbox" },
  "--base-url": { takesValue: true, dest: "baseUrl" },
  "--resource": { takesValue: true, dest: "resource" },
  "--audience": { takesValue: true, dest: "audience" },
};

const AI_COMMON_OPTIONS: Record<string, OptionSpec> = {
  "--profile": { takesValue: true, dest: "profile" },
  "--base-url": { takesValue: true, dest: "baseUrl" },
  "--sandbox": { takesValue: false, dest: "sandbox" },
};

// Keyed by SUB-command, not by `ai`. A single flat table would accept
// `ai exchange --period 30d` and silently ignore it, which is the opposite of
// what every other command here does with an unknown flag (usage error, exit 2).
const AI_COMMAND_TABLE: Record<AiCommand, { options: Record<string, OptionSpec>; usage: string; help: string }> = {
  exchange: { options: AI_EXCHANGE_OPTIONS, usage: AI_EXCHANGE_USAGE, help: AI_EXCHANGE_HELP },
  gateways: { options: AI_COMMON_OPTIONS, usage: AI_GATEWAYS_USAGE, help: AI_GATEWAYS_HELP },
  agents: {
    options: { ...AI_COMMON_OPTIONS, "--gateway": { takesValue: true, dest: "gateway" } },
    usage: AI_AGENTS_USAGE,
    help: AI_AGENTS_HELP,
  },
  "create-agent": {
    options: {
      ...AI_COMMON_OPTIONS,
      "--gateway": { takesValue: true, dest: "gateway" },
      "--name": { takesValue: true, dest: "name" },
      "--slug": { takesValue: true, dest: "slug" },
      "--provider": { takesValue: true, dest: "provider" },
      "--secret": { takesValue: true, dest: "secret" },
      "--secret-from-env": { takesValue: true, dest: "secretFromEnv" },
      "--upstream": { takesValue: true, dest: "upstream" },
      "--model": { takesValue: true, dest: "model" },
    },
    usage: AI_CREATE_AGENT_USAGE,
    help: AI_CREATE_AGENT_HELP,
  },
  mint: {
    options: {
      ...AI_COMMON_OPTIONS,
      "--agent": { takesValue: true, dest: "agent" },
      "--kind": { takesValue: true, dest: "kind" },
      "--name": { takesValue: true, dest: "name" },
    },
    usage: AI_MINT_USAGE,
    help: AI_MINT_HELP,
  },
  usage: {
    options: {
      ...AI_COMMON_OPTIONS,
      "--period": { takesValue: true, dest: "period" },
      "--agent": { takesValue: true, dest: "agent" },
    },
    usage: AI_USAGE_USAGE,
    help: AI_USAGE_HELP,
  },
  import: {
    options: {
      "--profile": { takesValue: true, dest: "profile" },
      "--base-url": { takesValue: true, dest: "baseUrl" },
      "--from": { takesValue: true, dest: "from" },
      "--file": { takesValue: true, dest: "file" },
      "--apply": { takesValue: false, dest: "apply" },
      "--gateway-name": { takesValue: true, dest: "gatewayName" },
    },
    usage: AI_IMPORT_USAGE,
    help: AI_IMPORT_HELP,
  },
};

const COMMAND_TABLE: Record<Command, { options: Record<string, OptionSpec>; usage: string; help: string }> = {
  login: { options: LOGIN_OPTIONS, usage: LOGIN_USAGE, help: LOGIN_HELP },
  logout: { options: PROFILE_ONLY_OPTIONS, usage: LOGOUT_USAGE, help: LOGOUT_HELP },
  whoami: { options: PROFILE_ONLY_OPTIONS, usage: WHOAMI_USAGE, help: WHOAMI_HELP },
  init: { options: INIT_OPTIONS, usage: INIT_USAGE, help: INIT_HELP },
  ai: { options: AI_EXCHANGE_OPTIONS, usage: AI_EXCHANGE_USAGE, help: AI_EXCHANGE_HELP },
};

/** Argument-parse failure — usage line + `<prog>: error: <message>`, exit 2. */
export class UsageError extends Error {
  constructor(
    message: string,
    readonly usage: string,
    readonly prog: string,
  ) {
    super(message);
    this.name = "UsageError";
  }
}

export type ParsedArgs =
  | ({ command: "login" } & LoginArgs)
  | ({ command: "logout" } & LogoutArgs)
  | ({ command: "whoami" } & WhoamiArgs)
  | ({ command: "init" } & InitArgs)
  | ({ command: "ai"; aiCommand: "exchange" } & AiExchangeArgs)
  | ({ command: "ai"; aiCommand: "import" } & AiImportArgs)
  | ({
      command: "ai";
      aiCommand: Exclude<AiCommand, "exchange" | "import">;
    } & AiControlArgs);

export type ParseResult = ParsedArgs | { help: string };

export function parseArgs(argv: string[]): ParseResult {
  const first = argv[0];
  if (first === undefined) {
    throw new UsageError(
      "the following arguments are required: {login,logout,whoami,init,ai}",
      TOP_USAGE,
      PROG,
    );
  }
  if (first === "-h" || first === "--help") return { help: TOP_HELP };
  if (!(COMMANDS as readonly string[]).includes(first)) {
    if (first.startsWith("-")) {
      throw new UsageError(`unrecognized arguments: ${argv.join(" ")}`, TOP_USAGE, PROG);
    }
    throw new UsageError(
      `argument {login,logout,whoami,init,ai}: invalid choice: '${first}' (choose from 'login', 'logout', 'whoami', 'init', 'ai')`,
      TOP_USAGE,
      PROG,
    );
  }
  const command = first as Command;
  let { options, usage, help } = COMMAND_TABLE[command];
  let subProg = `${PROG} ${command}`;

  // `ai` carries a sub-command. Consume it here, then fall through to the
  // same option loop with `argv` advanced past it — one parser, not two.
  let aiCommand: AiCommand | undefined;
  let optionStart = 1;
  if (command === "ai") {
    const second = argv[1];
    if (second === undefined) {
      throw new UsageError(`the following arguments are required: {${AI_CHOICES}}`, AI_USAGE, subProg);
    }
    if (second === "-h" || second === "--help") return { help: AI_HELP };
    if (!(AI_COMMANDS as readonly string[]).includes(second)) {
      throw new UsageError(
        `argument {${AI_CHOICES}}: invalid choice: '${second}' ` +
          `(choose from ${AI_COMMANDS.map((c) => `'${c}'`).join(", ")})`,
        AI_USAGE,
        subProg,
      );
    }
    aiCommand = second as AiCommand;
    // Each ai sub-command has its own flags, so the option table is
    // re-bound here. Sharing one table across all six would make
    // `ai exchange --period 30d` parse and be ignored.
    ({ options, usage, help } = AI_COMMAND_TABLE[aiCommand]);
    subProg = `${PROG} ai ${aiCommand}`;
    optionStart = 2;
  }

  const values: Record<string, string | boolean> = {};
  const extras: string[] = [];
  for (let i = optionStart; i < argv.length; i++) {
    const token = argv[i];
    if (token === "-h" || token === "--help") return { help };
    let name = token;
    let inlineValue: string | undefined;
    if (token.startsWith("--")) {
      const eq = token.indexOf("=");
      if (eq !== -1) {
        name = token.slice(0, eq);
        inlineValue = token.slice(eq + 1);
      }
    }
    const spec = options[name];
    if (!spec) {
      extras.push(token);
      continue;
    }
    if (spec.takesValue) {
      let value = inlineValue;
      if (value === undefined) {
        const next = argv[i + 1];
        if (next === undefined || (next.startsWith("-") && next.length > 1)) {
          throw new UsageError(`argument ${name}: expected one argument`, usage, subProg);
        }
        value = next;
        i++;
      }
      values[spec.dest] = value;
    } else {
      if (inlineValue !== undefined) {
        throw new UsageError(
          `argument ${name}: ignored explicit argument '${inlineValue}'`,
          usage,
          subProg,
        );
      }
      values[spec.dest] = true;
    }
  }
  if (extras.length > 0) {
    throw new UsageError(`unrecognized arguments: ${extras.join(" ")}`, TOP_USAGE, PROG);
  }

  if (command === "login") {
    return {
      command,
      tenant: values.tenant as string | undefined,
      baseUrl: values.baseUrl as string | undefined,
      sandbox: values.sandbox === true,
      profile: values.profile as string | undefined,
      device: values.device === true,
      noBrowser: values.noBrowser === true,
    };
  }
  if (command === "init") {
    return {
      command,
      profile: values.profile as string | undefined,
      baseUrl: values.baseUrl as string | undefined,
      sandbox: values.sandbox === true,
      provider: values.provider as string | undefined,
      secretName: values.secretName as string | undefined,
      host: values.host as string | undefined,
    };
  }
  if (command === "ai" && aiCommand === "import") {
    return {
      command,
      aiCommand: "import",
      profile: values.profile as string | undefined,
      baseUrl: values.baseUrl as string | undefined,
      from: values.from as string | undefined,
      file: values.file as string | undefined,
      apply: values.apply === true,
      gatewayName: values.gatewayName as string | undefined,
    };
  }
  if (command === "ai" && aiCommand !== "exchange") {
    return {
      command,
      aiCommand: aiCommand as Exclude<AiCommand, "exchange" | "import">,
      profile: values.profile as string | undefined,
      baseUrl: values.baseUrl as string | undefined,
      sandbox: values.sandbox === true,
      gateway: values.gateway as string | undefined,
      agent: values.agent as string | undefined,
      name: values.name as string | undefined,
      slug: values.slug as string | undefined,
      provider: values.provider as string | undefined,
      secret: values.secret as string | undefined,
      secretFromEnv: values.secretFromEnv as string | undefined,
      upstream: values.upstream as string | undefined,
      model: values.model as string | undefined,
      kind: values.kind as string | undefined,
      period: values.period as string | undefined,
    };
  }
  if (command === "ai") {
    return {
      command,
      aiCommand: "exchange",
      tenant: values.tenant as string | undefined,
      sandbox: values.sandbox === true,
      baseUrl: values.baseUrl as string | undefined,
      // `resource` stays undefined unless the flag was given: the SDK
      // distinguishes absent from empty, and an empty one is a server
      // refusal rather than "no resource".
      resource: values.resource as string | undefined,
      audience: values.audience as string | undefined,
    };
  }
  return { command, profile: values.profile as string | undefined };
}

/**
 * CLI entry point. Returns the process exit code: 0 on success, 1 for
 * expected failures (printed as `error: <message>`, no stack trace), 2 for
 * argument errors (argparse semantics, matching the python reference).
 */
export async function main(argv: string[]): Promise<number> {
  let parsed: ParseResult;
  try {
    parsed = parseArgs(argv);
  } catch (e) {
    if (e instanceof UsageError) {
      console.error(e.usage);
      console.error(`${e.prog}: error: ${e.message}`);
      return 2;
    }
    throw e;
  }
  if ("help" in parsed) {
    console.log(parsed.help);
    return 0;
  }

  try {
    switch (parsed.command) {
      case "login":
        return await runLogin(parsed);
      case "logout":
        return await runLogout(parsed);
      case "whoami":
        return await runWhoami(parsed);
      case "init":
        return await runInit(parsed);
      case "ai":
        switch (parsed.aiCommand) {
          case "exchange":
            return await runAiExchange(parsed);
          case "gateways":
            return await runAiGateways(parsed);
          case "agents":
            return await runAiAgents(parsed);
          case "create-agent":
            return await runAiCreateAgent(parsed);
          case "mint":
            return await runAiMint(parsed);
          case "usage":
            return await runAiUsage(parsed);
          case "import":
            return await runAiImport(parsed);
        }
    }
  } catch (e) {
    if (e instanceof CLIError || e instanceof KnoxCallError) {
      console.error(`error: ${e.message}`);
      return 1;
    }
    throw e;
  }
}
