// Default-on route-aware interception for Node — `import "@knoxcall/sdk/autostart"`.
//
// GOAL, as far as Node allows it: outbound calls to hosts an intercept-enabled
// Route covers go through KnoxCall, with no `knox.wrap.intercept()` call and no
// other change in the application.
//
// ┌─ WHERE THIS FALLS SHORT OF THE PYTHON SDK — READ THIS FIRST ─────────────┐
// │ Python's wheel ships a `.pth` file, which `site.py` executes at the start │
// │ of EVERY interpreter in the environment. Node has no equivalent: a        │
// │ package cannot load itself into a process that does not import it. So     │
// │ Node's default is one line of CONFIGURATION, not zero:                    │
// │                                                                          │
// │   node --import @knoxcall/sdk/autostart server.js                        │
// │   NODE_OPTIONS="--import @knoxcall/sdk/autostart"   (per project)        │
// │   import "@knoxcall/sdk/autostart";                 (first line of entry)│
// │                                                                          │
// │ NEVER set that NODE_OPTIONS globally in a shell profile. `--import` is    │
// │ FATAL when the specifier does not resolve, so a global setting breaks     │
// │ every `node` invocation outside a project that has this package           │
// │ installed — including `npm`, `tsc` and `npx`. Scope it to the project:    │
// │ an npm script, a Dockerfile `ENV`, a systemd unit, a CI job env.         │
// │                                                                          │
// │ `postinstall` is not an answer either: it is commonly disabled            │
// │ (`--ignore-scripts`, most CI images), has no terminal, and writing to a   │
// │ user's shell profile from a package install is not something this SDK     │
// │ will do.                                                                 │
// └──────────────────────────────────────────────────────────────────────────┘
//
// OFF SWITCHES, the same names as every other SDK (PARITY §21.4):
//   KNOXCALL_AUTOSTART=off        the hook does not install at all
//   KNOXCALL_INTERCEPT=off        the existing per-request kill switch
//   KNOXCALL_AUTOSTART_VERBOSE=1  print what the hook decided and why
//
// THE HOOK IS SILENT BY DEFAULT (operator decision, 2026-10-08). It never
// announces that you are not signed in and never reports its own failure: an
// unprompted line costs every customer's CI log one copy per process, forever,
// and the documentation is what tells people to run `knoxcall login`. The one
// exception is the interactive login itself (the line before the browser opens
// and the outcome afterwards), which needs a TTY and so can never reach CI.
// The rule is: the hook is silent unless you asked it something.
//   KNOXCALL_AUTOSTART_HOSTS=a,b  also cover hosts NO Route covers (ephemeral)
//
// TWO STAGES, and the asymmetry between them is a real Node constraint rather
// than a choice:
//
//   1. On import — install a thin shim on `globalThis.fetch`, and, when a
//      credential is already available locally, start promotion in the
//      background. No prompt, no blocking.
//   2. Promotion — resolve the credential, build the client, and hand the
//      seams to `wrap.intercept()`, which patches `fetch` AND node:http /
//      node:https. The shim removes itself first so the real interceptor
//      captures the true original.
//
// The `fetch` shim can await promotion, because patched `fetch` returns a
// promise. `http.request` CANNOT: it returns a `ClientRequest` synchronously, so
// the reroute decision must be made with a manifest that is ALREADY loaded.
// Until promotion finishes, requests on the http/https stack therefore go
// DIRECT. That is why promotion starts eagerly on import when a credential is
// present: for a server the window closes long before the first request, but a
// one-shot script whose very first act is an `axios` call may make that one call
// direct. `await (await import("@knoxcall/sdk/autostart")).ready()` closes the
// window deterministically.
//
// NOT A SECURITY BOUNDARY. This changes which code path installs the
// interceptor, not what it is: a convenience that patches process globals,
// composes with APM agents in install order, and is no defence against hostile
// in-process code. KnoxCall's own hosts are never intercepted, route-around
// rules still go direct, host matching is still exact. See egress-interceptor.ts.

// STATIC imports, and the reason is worth stating because python's hook does
// the opposite. There, a .pth runs in EVERY interpreter, so a module-scope
// import is a tax on `pip` itself and the hook imports `os` and `sys` alone.
// Here the hook is loaded only by a process that asked for it (`--import`), so
// the two things it needs on SYNCHRONOUS paths — the host contract, and the
// local credential probe — are imported properly rather than reached through
// `createRequire`, which resolves against the filesystem and therefore only
// works against a built `dist/`.
import { profileAvailable, resolveCredentialsPath, resolveProfile } from "./auth/credentials-file.js";
import { normaliseHost } from "./intercept-resolver.js";

import type { InterceptHandle } from "./resources/wrap.js";

type State = "pending" | "ready" | "disabled";

type FetchFn = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

let state: State = "pending";
let handle: InterceptHandle | null = null;
let client: unknown = null;
let promotion: Promise<State> | null = null;
let restoreShim: (() => void) | null = null;
let hinted = false;

// ── environment ─────────────────────────────────────────────────────────────

// The SAME off-spellings as `interceptKillSwitch` (PARITY §21.1), character for
// character and deliberately not a superset: a switch that accepted `no` where
// the kill switch beside it did not would be a difference nobody could predict
// from the documentation. Pinned by a test that drives both.
const OFF_VALUES = ["off", "0", "false"];

function isOff(name: string): boolean {
  const v = process.env[name];
  return typeof v === "string" && OFF_VALUES.includes(v.trim().toLowerCase());
}

/** `KNOXCALL_AUTOSTART=off` — do not install the hook at all.
 *
 *  `KNOXCALL_INTERCEPT` is deliberately NOT read here: it is documented as a
 *  per-REQUEST kill switch, and reading it at import would quietly make it a
 *  per-process one. The shim and the interceptor both read it per request. */
export function disabledByEnv(): boolean {
  return isOff("KNOXCALL_AUTOSTART");
}

export function verbose(): boolean {
  const v = process.env.KNOXCALL_AUTOSTART_VERBOSE;
  return typeof v === "string" && !["", "0", "false", "no", "off"].includes(v.trim().toLowerCase());
}

/** `KNOXCALL_AUTOSTART_HOSTS` — hosts to cover that no Route covers (they go
 *  through the ephemeral proxy). The only way to list a host without code, and
 *  empty by default: there is no built-in host list. */
export function extraHosts(): string[] {
  return (process.env.KNOXCALL_AUTOSTART_HOSTS ?? "")
    .split(/[,;]/)
    .map((h) => h.trim())
    .filter((h) => h.length > 0);
}

/** One line to stderr, ALWAYS. Reserved for output coupled to an interactive
 *  login the user is watching happen: the reason a browser is about to open,
 *  and what came of it. Both require a TTY, so neither reaches a CI log. Never
 *  stdout — a program's stdout is its output, and this is not part of it. */
function tell(message: string): void {
  try {
    process.stderr.write(`KnoxCall: ${message}\n`);
  } catch {
    // best-effort: a closed stderr must never fail a request
  }
}

/** One line to stderr, only under `KNOXCALL_AUTOSTART_VERBOSE`. EVERYTHING the
 *  hook might say on its own initiative goes through here. */
function diag(message: string): void {
  if (verbose()) tell(message);
}

function diagOnce(message: string): void {
  if (hinted) return;
  hinted = true;
  diag(message);
}


// ── stage 1 ─────────────────────────────────────────────────────────────────

/** Install the hook. Called on import, and safe to call by hand. Returns
 *  whether the hook is now armed. */
export function install(): boolean {
  if (disabledByEnv() || state !== "pending" || restoreShim !== null) return false;
  const target = globalThis as unknown as { fetch?: FetchFn };
  const original = target.fetch;
  if (typeof original !== "function") return false; // Node < 18

  const shim: FetchFn = async (input, init) => {
    if (worthPromoting(hostOf(input))) {
      const replacement = await promote();
      // After promotion the real interceptor owns `globalThis.fetch`; this shim
      // is no longer it, so re-dispatching cannot loop.
      if (replacement !== null) return replacement(input, init);
    }
    return original(input, init);
  };
  target.fetch = shim;
  restoreShim = () => {
    // Anti-clobber: only restore where WE are still the active fetch.
    if (target.fetch === shim) target.fetch = original;
  };

  // The http/https stack cannot await, so give promotion a head start whenever
  // it can finish without asking anybody anything.
  if (credentialProbablyPresent()) void promote();
  return true;
}

function hostOf(input: string | URL | Request): string {
  try {
    const url =
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.href
          : (input as Request).url;
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

/** Whether a local credential exists WITHOUT any network I/O. Deliberately a
 *  cheap superset of `autoDetectBootstrap`'s locally-decidable slots: a false
 *  positive only costs an eager promotion that then disables itself, and a
 *  false negative only costs the http/https stack its head start. The
 *  authoritative answer is still `autoDetectBootstrap`, which promotion runs. */
function credentialProbablyPresent(): boolean {
  const env = process.env;
  if (env.KNOXCALL_ACCESS_TOKEN || env.KNOXCALL_API_KEY) return true;
  if (env.KNOXCALL_CLIENT_ID && env.KNOXCALL_CLIENT_SECRET) return true;
  try {
    if (profileAvailable(resolveCredentialsPath(), resolveProfile())) return true;
  } catch {
    // no credentials file, or it could not be read — not a credential
  }
  return Boolean(
    (env.ACTIONS_ID_TOKEN_REQUEST_URL && env.ACTIONS_ID_TOKEN_REQUEST_TOKEN) ||
      env.AWS_WEB_IDENTITY_TOKEN_FILE ||
      (env.IDENTITY_ENDPOINT && env.IDENTITY_HEADER) ||
      env.VERCEL_OIDC_TOKEN ||
      env.CIRCLE_OIDC_TOKEN_V2,
  );
}

function worthPromoting(host: string): boolean {
  if (state !== "pending") return false;
  const h = normalise(host);
  if (!h || isPlatformHost(h)) return false; // anti-recursion: never our own hosts
  return !isOff("KNOXCALL_INTERCEPT");
}

// From the resolver, so this module never re-implements the host contract —
// "a control that is correct on one path and simply absent on the parallel one"
// is exactly what a local copy of normaliseHost would be.
function normalise(host: string): string {
  return normaliseHost(host);
}

function isPlatformHost(host: string): boolean {
  return host === "knoxcall.com" || host.endsWith(".knoxcall.com");
}

// ── stage 2 ─────────────────────────────────────────────────────────────────

/** Promote once. Resolves to the `fetch` the caller should use, or `null` to
 *  pass the request through untouched. Concurrent callers share one promotion. */
async function promote(): Promise<FetchFn | null> {
  if (state === "disabled") return null;
  if (state === "ready") return currentFetch();
  promotion ??= build();
  const settled = await promotion;
  return settled === "ready" ? currentFetch() : null;
}

function currentFetch(): FetchFn {
  return (globalThis as unknown as { fetch: FetchFn }).fetch;
}

async function build(): Promise<State> {
  try {
    const { noCredentialRecorded, recordNoCredential } = await import("./local-state.js");
    const { KnoxCall } = await import("./client.js");
    const { NotAuthenticatedError, AuthenticationError } = await import("./error.js");

    const profile = resolveProfile();
    if (noCredentialRecorded(profile)) {
      // A recent process already proved there is nothing to find.
      state = "disabled";
      teardownShim();
      return state;
    }
    const storedPresent = profileAvailable(resolveCredentialsPath(), profile);

    let knox: any = new KnoxCall({});
    try {
      // The ONLY credential enumeration is `auth/bootstrap.ts`'s. Letting it
      // throw is how this hook learns "nothing is configured" without keeping a
      // second copy of the chain that would go stale the day a slot is added.
      await knox.authenticate();
    } catch (err) {
      abandon(knox);
      knox = null;
      const nothingFound = err instanceof NotAuthenticatedError;
      const staleLogin = err instanceof AuthenticationError && storedPresent;
      if (!nothingFound && !staleLogin) throw err;
      knox = await loginAndBuild(profile);
      if (knox === null) {
        if (nothingFound) recordNoCredential(profile);
        state = "disabled";
        teardownShim();
        return state;
      }
    }

    // The shim comes off BEFORE the real patch goes on, so `intercept()`
    // captures the true original `fetch` and this module leaves the path.
    teardownShim();
    const installed: InterceptHandle = knox.wrap.intercept({ hosts: extraHosts(), autostart: true });
    await installed.ready;
    handle = installed;
    client = knox;
    state = "ready";
    registerExitFlush(installed);
    return state;
  } catch (err) {
    state = "disabled";
    teardownShim();
    diagOnce(
      `interception is off for this process (${(err as Error)?.name ?? "Error"}: ${(err as Error)?.message ?? err}). ` +
        "Set KNOXCALL_AUTOSTART=off to stop trying.",
    );
    return state;
  }
}

function teardownShim(): void {
  const restore = restoreShim;
  restoreShim = null;
  if (restore !== null) restore();
}

/** The one-time login prompt, under `login.ts`'s own guards. Returns a ready
 *  client, or `null` (no prompt was possible, or it was not completed). */
async function loginAndBuild(profile: string): Promise<any> {
  const { clearLoginDeclined, loginDeclined, recordLoginDeclined } = await import("./local-state.js");
  const { ensureLogin } = await import("./login.js");

  if (loginDeclined(profile)) return null; // asked once already

  if (!process.stdin.isTTY || !process.stdout.isTTY || process.env.CI || process.env.KNOXCALL_NO_INTERACTIVE) {
    // The same three conditions `login.ts`'s interactiveGuard refuses on. One
    // line, then carry on with no interception — never a prompt, never a hang.
    diagOnce(
      "not signed in, so outbound calls are not going through KnoxCall. " +
        "Run `knoxcall login` to enable it, or set KNOXCALL_AUTOSTART=off.",
    );
    return null;
  }

  // Said before the browser opens, and deliberately NOT behind the verbose
  // switch: a window appearing unbidden needs a reason on screen. It can only
  // happen on a TTY, so it never reaches a CI log.
  tell(
    "signing you in once so outbound calls can go through KnoxCall " +
      "(KNOXCALL_AUTOSTART=off disables this).",
  );


  try {
    const knox = await ensureLogin({ timeoutMs: LOGIN_TIMEOUT_MS });
    clearLoginDeclined(profile);
    tell("signed in. Outbound calls to hosts an intercept-enabled Route covers now go through KnoxCall.");
    return knox;
  } catch (err) {
    recordLoginDeclined(profile, (err as Error)?.name ?? "Error");
    tell(
      `sign-in did not complete (${(err as Error)?.name ?? "Error"}). Continuing without interception; ` +
        "run `knoxcall login` when you are ready — you will not be asked again.",
    );
    return null;
  }
}

/** Deliberately shorter than `login.ts`'s 300 s default: this prompt interrupts
 *  an application's request rather than a command the user just typed. */
const LOGIN_TIMEOUT_MS = 120_000;

/** Flush the uncovered-egress buffer at exit. `beforeExit` does not fire on an
 *  explicit `process.exit()` or a signal, which is accepted: this is
 *  at-most-once telemetry, and the reporter's own timer is about a minute. */
function registerExitFlush(installed: InterceptHandle): void {
  process.once("beforeExit", () => {
    try {
      installed.uninstall();
    } catch {
      // best-effort: telemetry at shutdown
    }
  });
}

// The node client holds no event-loop resources of its own (no background loop
// thread, unlike the python sync facade), so an abandoned one needs no close —
// there is no `close()` on it to call. Named rather than silently omitted,
// because the python hook DOES close its client and the asymmetry is real.
function abandon(_knox: unknown): void {
  /* nothing to release */
}

// ── introspection (tests, and debugging a quiet hook) ───────────────────────

/** `"pending"` | `"ready"` | `"disabled"` — what stage this process is at. */
export function autostartState(): State {
  return state;
}

/** The installed handle, or `null`. */
export function autostartHandle(): InterceptHandle | null {
  return handle;
}

/** Resolve once the hook has finished promoting (or given up). Use this to
 *  close the window in which the synchronous http/https stack is not yet
 *  covered: `await ready()` before the process's first outbound request. */
export async function ready(): Promise<State> {
  if (state !== "pending") return state;
  promotion ??= build();
  return promotion;
}

/** Undo everything this module did. Not part of the public API — for tests. */
export async function resetForTests(): Promise<void> {
  if (handle !== null) {
    try {
      handle.uninstall();
    } catch {
      // best-effort
    }
  }
  abandon(client);
  teardownShim();
  state = "pending";
  handle = null;
  client = null;
  promotion = null;
  hinted = false;
}

// Stage 1 runs on import: the whole point is that `--import` needs no call.
try {
  install();
} catch {
  // An interpreter that cannot arm the hook is an interpreter with no
  // interception, never a broken one.
}
