// Interactive first-run authentication — OPT-IN, and NEVER on the request path.
//
// The persistent credential (`knoxcall login` → ~/.knoxcall/credentials.json,
// rotating refresh token) already survives restarts; these helpers just let the
// SDK *initiate* that login programmatically. Because an SDK is embedded in
// someone else's process (production servers, CI, background agents, serverless),
// a browser/device flow must be an explicit, TTY-gated call — never a silent
// side effect of a normal API call. `KnoxCall()` construction and `.call()` never
// trigger this; they throw `NotAuthenticatedError` when no credential is found.

import { KnoxCall } from "./client.js";
import { StoredCredentials } from "./auth/bootstrap.js";
import { NotAuthenticatedError } from "./error.js";
import { defaultBaseUrl, type KnoxCallOptions } from "./core.js";
import {
  profileAvailable,
  resolveCredentialsPath,
  resolveProfile,
} from "./auth/credentials-file.js";
import { authCodeFlow, deviceFlow } from "./cli/login.js";
import { persistLogin } from "./cli/common.js";

export interface LoginOptions {
  /** Tenant hint for the authorize URL (optional; discovered otherwise). */
  tenant?: string;
  /** Target the sandbox host / Test data plane. */
  sandbox?: boolean;
  /** Management base URL override (defaults to prod/sandbox). */
  baseUrl?: string;
  /** Credentials-file profile to write/read (default `default`). */
  profile?: string;
  /** `auto` (browser on a desktop TTY, else device) | `browser` | `device`. */
  mode?: "auto" | "browser" | "device";
  /** Custom browser launcher (defaults to the OS opener). */
  openBrowser?: (url: string) => unknown;
  /** Loopback wait timeout for the browser flow (ms). */
  timeoutMs?: number;
  /** Bypass the TTY / CI / KNOXCALL_NO_INTERACTIVE guard. Default false. */
  allowNonInteractive?: boolean;
  /** Extra options forwarded to the returned client. */
  clientOptions?: Partial<KnoxCallOptions>;
}

/**
 * Refuse to pop a browser or block on a device code where doing so is unsafe:
 * a non-interactive process (no TTY), CI, or an explicit opt-out. The caller
 * can override with `allowNonInteractive` when they know it is safe.
 */
function interactiveGuard(opts: LoginOptions): void {
  if (opts.allowNonInteractive) return;
  if (process.env.KNOXCALL_NO_INTERACTIVE || process.env.CI) {
    throw new NotAuthenticatedError(
      "interactive login is disabled here (KNOXCALL_NO_INTERACTIVE or CI is set). " +
        "Provision a non-interactive credential (client_id/secret or workload OIDC) instead.",
    );
  }
  if (!process.stdout.isTTY || !process.stdin.isTTY) {
    throw new NotAuthenticatedError(
      "no interactive terminal detected — run `knoxcall login` in a terminal, " +
        "or provision a non-interactive credential (client_id/secret or workload OIDC).",
    );
  }
}

function hasDesktopBrowser(): boolean {
  // Headless CI is already blocked by interactiveGuard, so this only chooses
  // browser-vs-device on a real TTY. On Linux, require a display server.
  if (process.platform === "linux") {
    return Boolean(process.env.DISPLAY || process.env.WAYLAND_DISPLAY);
  }
  return true;
}

function clientFromProfile(profile: string, opts: LoginOptions): KnoxCall {
  return new KnoxCall({
    ...opts.clientOptions,
    bootstrap: new StoredCredentials({ profile }),
    sandbox: opts.sandbox ?? false,
  });
}

/**
 * Run the interactive browser (loopback) or device-code login, persist the
 * credential to `~/.knoxcall/credentials.json`, and return a ready client.
 * The caller explicitly asked to log in, so blocking + browser is expected.
 */
export async function login(opts: LoginOptions = {}): Promise<KnoxCall> {
  interactiveGuard(opts);
  const baseUrl = (opts.baseUrl ?? defaultBaseUrl(opts.sandbox)).replace(/\/+$/, "");
  const profile = resolveProfile(opts.profile);
  const mode = opts.mode ?? "auto";
  const useDevice = mode === "device" || (mode === "auto" && !hasDesktopBrowser());

  const tokenBody = useDevice
    ? await deviceFlow(baseUrl, {})
    : await authCodeFlow(baseUrl, {
        tenant: opts.tenant,
        openBrowser: opts.openBrowser,
        timeoutMs: opts.timeoutMs,
      });

  await persistLogin({
    path: resolveCredentialsPath(),
    profile,
    baseUrl,
    tokenBody,
    fallbackTenant: opts.tenant,
  });

  return clientFromProfile(profile, opts);
}

/**
 * Return a client from an already-stored credential for the profile if one
 * exists (no prompt), otherwise run the interactive {@link login} once. The
 * ergonomic "make sure I'm authenticated, then give me a client" entry point.
 */
export async function ensureLogin(opts: LoginOptions = {}): Promise<KnoxCall> {
  const profile = resolveProfile(opts.profile);
  if (profileAvailable(resolveCredentialsPath(), profile)) {
    return clientFromProfile(profile, opts);
  }
  return login(opts);
}
