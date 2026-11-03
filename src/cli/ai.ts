// `knoxcall ai exchange` — RFC 8693 workload federation from a terminal.
//
// Mirrors knoxcall-python's `knoxcall/cli/ai.py` (the PARITY §13 reference):
// same flags, same messages, same exit codes.
//
// The one KnoxCall command that needs no `knoxcall login` and no KnoxCall
// credential at all: the CI workload's own OIDC id_token IS the credential, and
// the server verifies it against the issuer's published JWKS.
//
//     export KC_TOKEN="$(knoxcall ai exchange --tenant acme)"
//
// Two rules this command exists to enforce, because both are easy to get wrong
// in a CI script and neither fails in a way that names itself:
//
//   1. The subject token is read from the environment, NEVER a flag. An argv
//      value lands in shell history, in `ps` output, and in the CI log line
//      that echoes the command. Same rule `knoxcall init` applies to
//      KNOXCALL_WRAP_SECRET.
//   2. The host is the tenant data plane, and there is no default. On
//      api.knoxcall.com this endpoint answers 401, which reads as "my CI token
//      was rejected" and sends people hunting through their issuer's JWKS.
//
// Only the token goes to stdout, so `$(...)` captures exactly the token.

import { exchangeToken } from "../resources/token-exchange.js";
import { CLIError } from "./common.js";

/** The subject token is read from here, never from argv. See rule 1 above. */
export const SUBJECT_TOKEN_ENV = "KNOXCALL_SUBJECT_TOKEN";

export interface AiExchangeArgs {
  tenant?: string;
  sandbox?: boolean;
  baseUrl?: string;
  resource?: string;
  audience?: string;
}

export async function runAiExchange(args: AiExchangeArgs): Promise<number> {
  const subjectToken = (process.env[SUBJECT_TOKEN_ENV] ?? "").trim();
  if (!subjectToken) {
    throw new CLIError(
      `${SUBJECT_TOKEN_ENV} is not set — put your CI provider's OIDC id_token there ` +
        "(a flag would land in shell history, ps output and the CI log). GitHub Actions: " +
        "request one with `id-token: write` and the ACTIONS_ID_TOKEN_REQUEST_URL endpoint, " +
        'audience "knoxcall:gateway".',
    );
  }

  if (!args.tenant && !args.baseUrl) {
    throw new CLIError(
      "one of --tenant or --base-url is required: POST /v1/oauth/token is served only on " +
        "the tenant data-plane host (https://{tenant}.knoxcall.com). Pointing it at " +
        "api.knoxcall.com answers 401, which reads like a rejected subject_token but means " +
        "the endpoint is not there.",
    );
  }

  const result = await exchangeToken(
    {
      subject_token: subjectToken,
      // Only pass `resource` when the caller asked for one: the SDK
      // distinguishes "absent" from an empty string, and an empty one is a
      // server refusal rather than "no resource".
      ...(args.resource !== undefined ? { resource: args.resource } : {}),
      ...(args.audience ? { audience: args.audience } : {}),
    },
    { tenant: args.tenant, sandbox: args.sandbox === true, baseUrl: args.baseUrl },
  );

  if (!result.access_token) throw new CLIError("the exchange returned no access_token");

  // stdout: the token, nothing else. stderr: everything a human wants.
  console.log(result.access_token);
  const kind = args.resource !== undefined ? "tool (MCP, resource-bound)" : "agent";
  const ttl = typeof result.expires_in === "number" ? `, valid ${result.expires_in}s` : "";
  console.error(`exchanged for a ${kind} token${ttl}`);
  return 0;
}
