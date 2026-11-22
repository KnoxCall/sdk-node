// `knoxcall login` — auth-code+PKCE via loopback redirect, or device flow.
//
// Mirrors knoxcall-python/src/knoxcall/cli/login.py (PARITY §13). Zero
// runtime dependencies: node:http for the loopback listener, node:crypto for
// PKCE S256 + constant-time state compare, node:child_process for the
// browser open (start/open/xdg-open — and the URL is ALWAYS printed).

import { spawn } from "node:child_process";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { resolveCredentialsPath, resolveProfile } from "../auth/credentials-file.js";
import { defaultBaseUrl } from "../core.js";
import {
  CLI_CLIENT_ID,
  CLIError,
  persistLogin,
  postForm,
  tokenErrorMessage,
  type TokenBody,
} from "./common.js";

const DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";

/** `sleep(seconds)` — injectable so tests can assert the poll cadence. */
export type SleepFn = (seconds: number) => void | Promise<void>;

const defaultSleep: SleepFn = (seconds) => new Promise((r) => setTimeout(r, seconds * 1000));

// ── PKCE (RFC 7636, S256 only) ───────────────────────────────────────────────

/** Return { verifier, challenge } — S256, unpadded base64url. */
export function generatePkcePair(): { verifier: string; challenge: string } {
  const verifier = randomBytes(48).toString("base64url");
  const challenge = createHash("sha256").update(verifier, "ascii").digest("base64url");
  return { verifier, challenge };
}

export function buildAuthorizeUrl(
  baseUrl: string,
  opts: { redirectUri: string; state: string; codeChallenge: string; tenant?: string },
): string {
  const params = new URLSearchParams({
    response_type: "code",
    client_id: CLI_CLIENT_ID,
    redirect_uri: opts.redirectUri,
    state: opts.state,
    code_challenge: opts.codeChallenge,
    code_challenge_method: "S256",
  });
  if (opts.tenant) params.set("tenant", opts.tenant);
  return `${baseUrl}/oauth/authorize?${params.toString()}`;
}

// ── Browser opener ───────────────────────────────────────────────────────────

/** Best-effort platform browser launch. The caller has already printed the URL. */
export function openBrowser(url: string): void {
  try {
    let child;
    if (process.platform === "win32") {
      // `start` is a cmd built-in; the URL sits inside its own quotes (the
      // first quoted arg is the window title) so `&` in the query survives.
      child = spawn("cmd.exe", ["/d", "/s", "/c", `start "" "${url.replace(/"/g, "")}"`], {
        windowsVerbatimArguments: true,
        stdio: "ignore",
        detached: true,
      });
    } else if (process.platform === "darwin") {
      child = spawn("open", [url], { stdio: "ignore", detached: true });
    } else {
      child = spawn("xdg-open", [url], { stdio: "ignore", detached: true });
    }
    child.on("error", () => {
      // URL is printed; a broken browser launcher is not fatal.
    });
    child.unref();
  } catch {
    // URL is printed; a broken browser launcher is not fatal.
  }
}

// ── Loopback redirect receiver (RFC 8252 §7.3) ───────────────────────────────

function constantTimeEqual(a: string, b: string): boolean {
  // Hash both sides to equal length, then timingSafeEqual — the standard
  // trick for constant-time comparison of unequal-length strings.
  const da = createHash("sha256").update(a, "utf8").digest();
  const db = createHash("sha256").update(b, "utf8").digest();
  return timingSafeEqual(da, db);
}

/** One-shot loopback HTTP server on 127.0.0.1:0 for the authorize redirect. */
export class LoopbackServer {
  readonly port: number;
  readonly #server: Server;
  readonly #result: Promise<Record<string, string>>;

  private constructor(server: Server, port: number, result: Promise<Record<string, string>>) {
    this.#server = server;
    this.port = port;
    this.#result = result;
  }

  static start(host = "127.0.0.1"): Promise<LoopbackServer> {
    let resolveResult!: (r: Record<string, string>) => void;
    const result = new Promise<Record<string, string>>((resolve) => {
      resolveResult = resolve;
    });
    const server = createServer((req, res) => {
      const url = new URL(req.url ?? "/", "http://127.0.0.1");
      if (url.pathname !== "/callback") {
        res.statusCode = 404;
        res.end();
        return;
      }
      const query: Record<string, string> = {};
      for (const [k, v] of url.searchParams) {
        if (v && !(k in query)) query[k] = v; // first value wins (reference parity)
      }
      const failed = "error" in query || !query.code;
      const page =
        "<!doctype html><meta charset='utf-8'><title>KnoxCall CLI</title>" +
        "<body style='font-family:system-ui;margin:4rem auto;max-width:28rem'>" +
        (failed
          ? "<h1>Sign-in failed</h1><p>Return to your terminal for details.</p>"
          : "<h1>Signed in</h1><p>You can close this window and return to your terminal.</p>") +
        "</body>";
      const body = Buffer.from(page, "utf8");
      res.statusCode = 200;
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.setHeader("Content-Length", body.length);
      res.end(body);
      resolveResult(query);
    });
    return new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, host, () => {
        const address = server.address() as AddressInfo;
        resolve(new LoopbackServer(server, address.port, result));
      });
    });
  }

  /** Wait until the browser hits /callback; validate state, return the code. */
  async waitForCode(opts: { expectedState: string; timeoutMs?: number }): Promise<string> {
    const timeoutMs = opts.timeoutMs ?? 300_000;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let result: Record<string, string>;
    try {
      result = await Promise.race([
        this.#result,
        new Promise<never>((_, reject) => {
          timer = setTimeout(
            () => reject(new CLIError("timed out waiting for the browser sign-in to complete")),
            timeoutMs,
          );
          timer.unref?.();
        }),
      ]);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
    if (result.error) {
      const detail = result.error_description || result.error;
      throw new CLIError(`authorization failed: ${detail}`);
    }
    if (!constantTimeEqual(result.state ?? "", opts.expectedState)) {
      throw new CLIError("state mismatch in the OAuth callback — possible CSRF, aborting");
    }
    const code = result.code;
    if (!code) throw new CLIError("no authorization code in the OAuth callback");
    return code;
  }

  async close(): Promise<void> {
    await new Promise<void>((resolve) => {
      this.#server.close(() => resolve());
      // Keep-alive connections (browsers, fetch) would otherwise stall close.
      this.#server.closeAllConnections?.();
    });
  }
}

// ── Flows ────────────────────────────────────────────────────────────────────

export interface AuthCodeFlowOptions {
  tenant?: string;
  fetchImpl?: typeof fetch;
  openBrowser?: (url: string) => unknown;
  timeoutMs?: number;
}

export async function authCodeFlow(
  baseUrl: string,
  opts: AuthCodeFlowOptions = {},
): Promise<TokenBody> {
  const { verifier, challenge } = generatePkcePair();
  const state = randomBytes(24).toString("base64url");
  const server = await LoopbackServer.start();
  let code: string;
  let redirectUri: string;
  try {
    redirectUri = `http://127.0.0.1:${server.port}/callback`;
    const url = buildAuthorizeUrl(baseUrl, {
      redirectUri,
      state,
      codeChallenge: challenge,
      tenant: opts.tenant,
    });
    console.log(`Opening your browser to sign in. If it does not open, visit:\n\n  ${url}\n`);
    try {
      (opts.openBrowser ?? openBrowser)(url);
    } catch {
      // URL is printed; a broken browser launcher is not fatal.
    }
    code = await server.waitForCode({ expectedState: state, timeoutMs: opts.timeoutMs });
  } finally {
    await server.close();
  }

  const [status, body] = await postForm(
    `${baseUrl}/oauth/token`,
    {
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      client_id: CLI_CLIENT_ID,
      code_verifier: verifier,
    },
    opts.fetchImpl,
  );
  if (status >= 400 || !body.access_token) {
    throw new CLIError(tokenErrorMessage(status, body));
  }
  return body;
}

export interface DevicePollOptions {
  clientId?: string;
  interval?: number;
  expiresIn?: number;
  fetchImpl?: typeof fetch;
  sleep?: SleepFn;
}

/** Poll the token endpoint per RFC 8628 §3.5, honoring interval + slow_down. */
export async function pollDeviceToken(
  baseUrl: string,
  deviceCode: string,
  opts: DevicePollOptions = {},
): Promise<TokenBody> {
  const clientId = opts.clientId ?? CLI_CLIENT_ID;
  let interval = opts.interval ?? 5;
  const expiresIn = opts.expiresIn ?? 900;
  const sleep = opts.sleep ?? defaultSleep;
  const deadline = Date.now() + expiresIn * 1000;
  while (true) {
    if (Date.now() > deadline) {
      throw new CLIError("device authorization expired — run `knoxcall login` again");
    }
    await sleep(interval); // sleep BEFORE the first poll (RFC 8628 §3.5)
    const [status, body] = await postForm(
      `${baseUrl}/oauth/token`,
      { grant_type: DEVICE_GRANT, device_code: deviceCode, client_id: clientId },
      opts.fetchImpl,
    );
    if (status < 400 && body.access_token) return body;
    const error = body.error;
    if (error === "authorization_pending") continue;
    if (error === "slow_down") {
      interval += 5;
      continue;
    }
    if (error === "expired_token") {
      throw new CLIError("the device code expired — run `knoxcall login` again");
    }
    if (error === "access_denied") {
      throw new CLIError("sign-in was denied");
    }
    throw new CLIError(tokenErrorMessage(status, body));
  }
}

export async function deviceFlow(
  baseUrl: string,
  opts: { fetchImpl?: typeof fetch; sleep?: SleepFn } = {},
): Promise<TokenBody> {
  const [status, body] = await postForm(
    `${baseUrl}/oauth/device_authorization`,
    { client_id: CLI_CLIENT_ID },
    opts.fetchImpl,
  );
  if (status >= 400 || typeof body.device_code !== "string" || !body.device_code) {
    throw new CLIError(tokenErrorMessage(status, body));
  }

  const verificationUri = typeof body.verification_uri === "string" ? body.verification_uri : "";
  const userCode = typeof body.user_code === "string" ? body.user_code : "";
  console.log(
    `To sign in, open:\n\n  ${verificationUri}\n\nand enter the code:\n\n  ${userCode}\n`,
  );
  const complete = body.verification_uri_complete;
  if (typeof complete === "string" && complete) {
    console.log(`(or open ${complete} directly)\n`);
  }
  console.log("Waiting for approval…");

  let interval = Number.parseInt(String(body.interval ?? ""), 10);
  if (!Number.isFinite(interval) || interval <= 0) interval = 5;
  let expiresIn = Number.parseFloat(String(body.expires_in ?? ""));
  if (!Number.isFinite(expiresIn) || expiresIn <= 0) expiresIn = 900;
  return pollDeviceToken(baseUrl, body.device_code, {
    interval,
    expiresIn,
    fetchImpl: opts.fetchImpl,
    sleep: opts.sleep,
  });
}

// ── Command entry ────────────────────────────────────────────────────────────

export interface LoginArgs {
  tenant?: string;
  baseUrl?: string;
  sandbox: boolean;
  profile?: string;
  device: boolean;
  noBrowser: boolean;
}

export interface LoginDeps {
  fetchImpl?: typeof fetch;
  sleep?: SleepFn;
  openBrowser?: (url: string) => unknown;
}

export async function runLogin(args: LoginArgs, deps: LoginDeps = {}): Promise<number> {
  const baseUrl = (args.baseUrl || defaultBaseUrl(args.sandbox)).replace(/\/+$/, "");
  const path = resolveCredentialsPath();
  const profile = resolveProfile(args.profile);

  const tokenBody =
    args.device || args.noBrowser
      ? await deviceFlow(baseUrl, { fetchImpl: deps.fetchImpl, sleep: deps.sleep })
      : await authCodeFlow(baseUrl, {
          tenant: args.tenant,
          fetchImpl: deps.fetchImpl,
          openBrowser: deps.openBrowser,
        });

  const record = await persistLogin({
    path,
    profile,
    baseUrl,
    tokenBody,
    fallbackTenant: args.tenant,
  });
  const tenant =
    typeof record.tenant === "string" && record.tenant ? record.tenant : "(tenant not reported)";
  console.log(`\nLogged in to ${tenant} (${baseUrl})`);
  if (record.scope) console.log(`Scopes: ${record.scope}`);
  console.log(`Credentials written to ${path} (profile '${profile}')`);
  if (!record.refresh_token) {
    console.log("Warning: no refresh token was issued — access will expire without renewal.");
  }
  return 0;
}
