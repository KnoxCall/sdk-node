// Shared credentials file (~/.knoxcall/credentials.json) — read, write, lock, refresh.
//
// The file is written by `knoxcall login` and consumed by every SDK through
// the StoredCredentials bootstrap. Format, lock protocol, and refresh rules
// are cross-SDK identical (PARITY §2). The server's refresh tokens are
// SINGLE-USE with family revocation on reuse, so any refresh MUST:
//
//   1. hold the sibling `credentials.json.lock` file (exclusive-create, 100ms
//      retry up to 10s; a lock older than the stale window is broken by atomic
//      rename and retried once — ownership-aware so a peer's live lock is never
//      deleted, and the window stays above the bounded refresh timeout),
//   2. RE-READ the file after acquiring the lock (another process may have
//      already refreshed), and
//   3. atomically (temp file + rename) write back the rotated refresh token
//      before releasing the lock.
//
// File I/O is deliberately synchronous: the file is tiny, reads happen only
// on token fetch (the in-process store caches between), and the constructor
// seeding path (core.ts) cannot await. The lock retry loop still sleeps
// asynchronously so it never blocks the event loop.

import { homedir } from "os";
import { dirname, join } from "path";
import { randomBytes } from "crypto";
import {
  closeSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  statSync,
  unlinkSync,
  writeSync,
} from "fs";

import { redact } from "../redacted.js";
import { warnOnce } from "../warn.js";
import { AuthenticationError, errorFromResponse, KnoxCallError } from "../error.js";
import type { CachedToken } from "./token-store.js";

export const DEFAULT_PROFILE = "default";

// A stored access token is "fresh" while it has more than this much validity
// left; below the threshold the provider refreshes under the file lock.
const FRESH_WINDOW_MS = 60_000;

// The locked refresh HTTP call is bounded so the lock is provably released
// well within the lock's stale window (CredentialsFileLock staleAfterMs) —
// otherwise a slow token endpoint could hold the lock long enough for a peer
// to break it and double-refresh the single-use token.
const REFRESH_TIMEOUT_MS = 30_000;

export const RELOGIN_MESSAGE =
  "stored CLI credentials are no longer valid — run `knoxcall login` again";

export type ProfileRecord = Record<string, unknown>;

// ── Path / profile resolution ────────────────────────────────────────────────

/** Credentials file path: explicit override > KNOXCALL_CREDENTIALS_FILE > default. */
export function resolveCredentialsPath(override?: string): string {
  if (override) return override;
  const env = process.env.KNOXCALL_CREDENTIALS_FILE;
  if (env) return env;
  return join(homedir(), ".knoxcall", "credentials.json");
}

/** Profile name: explicit override > KNOXCALL_PROFILE > `default`. */
export function resolveProfile(override?: string): string {
  return override || process.env.KNOXCALL_PROFILE || DEFAULT_PROFILE;
}

// ── File primitives (atomic writes, tolerant reads) ─────────────────────────

interface CredentialsDocument {
  version?: unknown;
  profiles: Record<string, unknown>;
}

/** Parse the whole file; null on missing/malformed/unexpected shape. */
/**
 * Warn (once) if the credentials file — which holds a refresh token — is
 * readable by group/other. POSIX only; on Windows the mode bits are advisory
 * and confidentiality rests on the %USERPROFILE% ACL, so we skip the check.
 */
function warnIfLoosePermissions(path: string): void {
  if (process.platform === "win32") return;
  let mode: number;
  try {
    mode = statSync(path).mode;
  } catch {
    return; // missing/unreadable — nothing to warn about
  }
  if (mode & 0o077) {
    warnOnce(
      "KNOXCALL_CREDENTIALS_FILE_PERMS",
      `KnoxCall credentials file ${path} is accessible to group/other ` +
        `(mode ${(mode & 0o777).toString(8)}) and holds a refresh token. Restrict it: chmod 600 ${path}`,
    );
  }
}

function readDocument(path: string): CredentialsDocument | null {
  warnIfLoosePermissions(path);
  let doc: unknown;
  try {
    doc = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return null;
  }
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) return null;
  const profiles = (doc as { profiles?: unknown }).profiles;
  if (!profiles || typeof profiles !== "object" || Array.isArray(profiles)) return null;
  return doc as unknown as CredentialsDocument;
}

/** One profile's record, or null (missing file, malformed JSON, unknown profile). */
export function readProfile(path: string, profile: string): ProfileRecord | null {
  const doc = readDocument(path);
  if (!doc) return null;
  const record = doc.profiles[profile];
  if (!record || typeof record !== "object" || Array.isArray(record)) return null;
  return { ...(record as ProfileRecord) };
}

/**
 * Atomic write: temp file in the same directory → fsync → rename over target.
 *
 * Directory is created 0700 and the file 0600 (best-effort — the mode bits
 * are advisory on Windows).
 */
function writeDocument(path: string, doc: CredentialsDocument): void {
  const directory = dirname(path) || ".";
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const tmpPath = join(
    directory,
    `.credentials-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}.tmp`,
  );
  try {
    const fd = openSync(tmpPath, "wx", 0o600);
    try {
      writeSync(fd, JSON.stringify(doc, null, 2) + "\n");
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(tmpPath, path);
  } catch (err) {
    try {
      unlinkSync(tmpPath);
    } catch {
      // best-effort cleanup
    }
    throw err;
  }
}

/** Merge one profile into the file (other profiles untouched), atomically. */
export function writeProfile(path: string, profile: string, record: ProfileRecord): void {
  const doc = readDocument(path) ?? { version: 1, profiles: {} };
  doc.version ??= 1;
  const clean: ProfileRecord = {};
  for (const [k, v] of Object.entries(record)) {
    if (v !== null && v !== undefined) clean[k] = v;
  }
  doc.profiles[profile] = clean;
  writeDocument(path, doc);
}

/**
 * Remove one profile; delete the file when it was the last one. Returns
 * whether the profile existed. Callers mutating a shared file must hold the
 * {@link CredentialsFileLock} (the CLI's `logout` does).
 */
export function removeProfile(path: string, profile: string): boolean {
  const doc = readDocument(path);
  if (!doc || !(profile in doc.profiles)) return false;
  delete doc.profiles[profile];
  if (Object.keys(doc.profiles).length > 0) {
    writeDocument(path, doc);
  } else {
    try {
      unlinkSync(path);
    } catch {
      // already gone
    }
  }
  return true;
}

/** Auto-detect presence check: file exists AND the selected profile parses. */
export function profileAvailable(path: string, profile: string): boolean {
  return readProfile(path, profile) !== null;
}

// ── Expiry formatting ────────────────────────────────────────────────────────

/** Epoch ms → `2026-07-04T10:00:00Z` (seconds precision, cross-SDK identical). */
export function formatExpiry(epochMs: number): string {
  return new Date(epochMs).toISOString().replace(/\.\d{3}Z$/, "Z");
}

function parseExpiry(value: unknown): number | null {
  if (typeof value !== "string" || !value) return null;
  // A timestamp without timezone info is treated as UTC (matches every other
  // SDK; JS Date.parse would otherwise assume local time).
  const normalized = /(?:[zZ]|[+-]\d{2}:?\d{2})$/.test(value) ? value : `${value}Z`;
  const ms = Date.parse(normalized);
  return Number.isFinite(ms) ? ms : null;
}

// ── Cross-process lock ───────────────────────────────────────────────────────

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/**
 * Sibling `.lock` file held by exclusive-create (O_CREAT|O_EXCL).
 *
 * Protocol (identical in every SDK): retry every 100ms up to 10s; a lock
 * file older than the stale window is broken and retried once.
 *
 * Ownership-aware break/release: the lock file carries a unique owner tag
 * (`pid time nonce`) written at acquire. A stale lock is broken by ATOMIC
 * RENAME (only one racer wins the rename, so a competitor's freshly-created
 * lock can never be deleted by path), and release only unlinks a lock whose
 * on-disk content still matches what this instance wrote. This closes the
 * double-acquire → double-refresh race that would replay the single-use
 * refresh token and trip server-side family revocation. The stale window is
 * also kept safely above the bounded refresh HTTP timeout so a live-but-slow
 * refresh is never mistaken for a dead holder.
 */
export class CredentialsFileLock {
  readonly lockPath: string;
  readonly #timeoutMs: number;
  readonly #retryIntervalMs: number;
  readonly #staleAfterMs: number;
  #held = false;
  #ownContent: string | null = null;

  constructor(
    target: string,
    opts: { timeoutMs?: number; retryIntervalMs?: number; staleAfterMs?: number } = {},
  ) {
    this.lockPath = `${target}.lock`;
    this.#timeoutMs = opts.timeoutMs ?? 10_000;
    this.#retryIntervalMs = opts.retryIntervalMs ?? 100;
    // Must exceed the bounded refresh HTTP timeout (REFRESH_TIMEOUT_MS) so a
    // legitimately in-flight refresh is never broken as "stale".
    this.#staleAfterMs = opts.staleAfterMs ?? 60_000;
  }

  #tryAcquire(): boolean {
    const content = `${process.pid} ${(Date.now() / 1000).toFixed(3)} ${randomBytes(8).toString("hex")}\n`;
    let fd: number;
    try {
      fd = openSync(this.lockPath, "wx");
    } catch {
      return false;
    }
    try {
      writeSync(fd, content);
    } finally {
      closeSync(fd);
    }
    this.#ownContent = content;
    this.#held = true;
    return true;
  }

  /**
   * Break a stale lock via atomic rename, so a competing process's fresh lock
   * is never removed by path. Returns true when a retry is worthwhile now.
   */
  #breakStale(): boolean {
    let age: number;
    try {
      age = Date.now() - statSync(this.lockPath).mtimeMs;
    } catch {
      return true; // lock vanished between attempts — retry immediately
    }
    if (age <= this.#staleAfterMs) return false;
    // Claim the break atomically: rename() has exactly one winner, so if a
    // competitor already broke-and-recreated the lock, our rename fails
    // (source gone) and we never touch their live lock.
    const graveyard = `${this.lockPath}.stale-${process.pid}-${randomBytes(6).toString("hex")}`;
    try {
      renameSync(this.lockPath, graveyard);
      unlinkSync(graveyard);
    } catch {
      // someone else already broke it (or it vanished) — just retry
    }
    return true;
  }

  async acquire(): Promise<void> {
    // First-ever login: ~/.knoxcall/ may not exist yet, and "wx" on the lock
    // path would throw ENOENT — which #tryAcquire treats as contention,
    // spinning until the timeout. Create the parent up front.
    const parent = dirname(this.lockPath);
    if (parent) mkdirSync(parent, { recursive: true, mode: 0o700 });
    const deadline = Date.now() + this.#timeoutMs;
    let staleBroken = false;
    while (true) {
      if (this.#tryAcquire()) return;
      if (!staleBroken && this.#breakStale()) {
        staleBroken = true;
        if (this.#tryAcquire()) return;
      }
      if (Date.now() >= deadline) {
        throw new KnoxCallError(
          `timed out waiting for the credentials file lock (${this.lockPath})`,
        );
      }
      await sleep(this.#retryIntervalMs);
    }
  }

  release(): void {
    if (!this.#held) return;
    this.#held = false;
    const own = this.#ownContent;
    this.#ownContent = null;
    try {
      // Only remove the lock if it is still OURS — if our lock was broken as
      // stale and re-taken by another process while we were suspended, unlink
      // by path would delete their live lock.
      if (own !== null && readFileSync(this.lockPath, "utf8") === own) {
        unlinkSync(this.lockPath);
      }
    } catch {
      // already gone or unreadable
    }
  }
}

// ── Token fetch (fast path + locked refresh) ─────────────────────────────────

function scopeList(scope: unknown): string[] {
  if (typeof scope === "string") return scope.split(/\s+/).filter(Boolean);
  if (Array.isArray(scope)) return scope.map(String);
  return [];
}

/** The fresh-token fast path: use the stored access token while >60s valid. */
function cachedFromProfile(record: ProfileRecord): CachedToken | null {
  const token = record.access_token;
  const expiresAt = parseExpiry(record.access_token_expires_at);
  if (typeof token !== "string" || !token || expiresAt === null) return null;
  if (expiresAt - Date.now() <= FRESH_WINDOW_MS) return null;
  return {
    accessToken: redact(token),
    expiresAt,
    scope: scopeList(record.scope),
    tokenType: "Bearer",
    tenant: typeof record.tenant === "string" && record.tenant ? record.tenant : undefined,
    // No refreshToken on purpose: the file is the sole refresh authority,
    // so no in-process fallback can ever replay a consumed (rotated) token.
  };
}

interface StoredTokenInput {
  path: string;
  profile: string;
  tokenEndpoint: string;
  fetchImpl?: typeof fetch;
}

async function refreshAndWriteBack(record: ProfileRecord, input: StoredTokenInput): Promise<CachedToken> {
  const refreshToken = record.refresh_token;
  const clientId = record.client_id;
  if (typeof refreshToken !== "string" || !refreshToken || typeof clientId !== "string" || !clientId) {
    throw new AuthenticationError(RELOGIN_MESSAGE);
  }

  const form = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: refreshToken,
    client_id: clientId, // the tenant's real CLI client (public, no secret)
  }).toString();
  const fetchImpl = input.fetchImpl ?? fetch;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REFRESH_TIMEOUT_MS);
  let res: Response;
  try {
    res = await fetchImpl(input.tokenEndpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
      },
      body: form,
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }

  const respHeaders: Record<string, string> = {};
  res.headers.forEach((v, k) => {
    respHeaders[k.toLowerCase()] = v;
  });
  let body: unknown = null;
  const text = await res.text();
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = text;
    }
  }

  if (res.status >= 400) {
    const err = errorFromResponse(res.status, body, respHeaders);
    if (err.code === "invalid_grant") {
      // Revoked family or expired refresh token — unrecoverable here.
      throw new AuthenticationError(RELOGIN_MESSAGE, {
        status: err.status,
        code: err.code,
        requestId: err.requestId,
        headers: respHeaders,
        body,
      });
    }
    throw err;
  }
  const parsed = (body && typeof body === "object" ? body : {}) as Record<string, unknown>;
  if (typeof parsed.access_token !== "string" || !parsed.access_token) {
    throw new KnoxCallError(
      `token endpoint returned an unexpected response (status ${res.status})`,
      { status: res.status, headers: respHeaders, body },
    );
  }

  const rawExpiresIn =
    typeof parsed.expires_in === "number" ? parsed.expires_in : Number.parseFloat(String(parsed.expires_in ?? ""));
  const lifetimeMs = (Number.isFinite(rawExpiresIn) ? rawExpiresIn : 3600) * 1000;
  const now = Date.now();

  // Write back the rotated refresh token BEFORE releasing the lock (caller
  // holds it) — the old one is already consumed server-side.
  const updated: ProfileRecord = { ...record };
  updated.access_token = parsed.access_token;
  updated.access_token_expires_at = formatExpiry(now + lifetimeMs);
  if (typeof parsed.refresh_token === "string" && parsed.refresh_token) {
    updated.refresh_token = parsed.refresh_token;
  }
  if (typeof parsed.scope === "string" && parsed.scope) updated.scope = parsed.scope;
  if (typeof parsed.tenant === "string" && parsed.tenant) {
    updated.tenant = parsed.tenant; // extension member (RFC 6749 §5.1)
  }
  if (typeof parsed.client_id === "string" && parsed.client_id) {
    updated.client_id = parsed.client_id; // extension member: the real per-tenant client id
  }
  writeProfile(input.path, input.profile, updated);

  return {
    accessToken: redact(parsed.access_token),
    expiresAt: now + lifetimeMs,
    lifetime: lifetimeMs,
    scope: scopeList(updated.scope),
    tokenType: "Bearer",
    tenant: typeof updated.tenant === "string" && updated.tenant ? updated.tenant : undefined,
  };
}

/**
 * Produce a usable access token from the credentials file.
 *
 * Fast path: stored access token with >60s validity, no HTTP. Otherwise
 * lock → re-read → re-check → refresh-token grant → atomic write-back.
 */
export async function fetchStoredToken(input: StoredTokenInput): Promise<CachedToken> {
  let record = readProfile(input.path, input.profile);
  if (!record) {
    // Detection saw the profile but it has since vanished/corrupted.
    throw new AuthenticationError(RELOGIN_MESSAGE);
  }
  const cached = cachedFromProfile(record);
  if (cached) return cached;

  const lock = new CredentialsFileLock(input.path);
  await lock.acquire();
  try {
    record = readProfile(input.path, input.profile);
    if (!record) throw new AuthenticationError(RELOGIN_MESSAGE);
    const fresh = cachedFromProfile(record);
    if (fresh) return fresh; // another process refreshed while we waited
    return await refreshAndWriteBack(record, input);
  } finally {
    lock.release();
  }
}
