// The default-on hook's own on-disk state, in ~/.knoxcall/ beside the
// credentials file. Mirrors knoxcall-python's `_local_state.py` (PARITY §21.4).
//
// It records that a user DECLINED or timed out of the one-time login prompt, so
// the hook asks ONCE rather than on every process start, and that a recent
// process found no credential at all, so an unconfigured machine does not repeat
// the detection (one leg of `autoDetectBootstrap` — GCP instance metadata — is
// an ungated network probe, so proving "nothing is configured" costs a DNS
// failure every time).
//
// Every operation is BEST-EFFORT and silent. A missing file, a corrupt file, an
// unwritable home directory and a permission error are all "no state": nothing
// here throws, because the caller has no recovery to perform — the file is a
// courtesy, not a source of truth. It holds NO credential material; tokens live
// in credentials.json and `auth/credentials-file.ts` is their only writer.

import { closeSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

/** How long a "nothing is configured" verdict stands before it is re-checked.
 *  Short on purpose: it exists to stop every process in a loop repeating the
 *  detection, not to remember a decision. It self-heals, and a successful
 *  `knoxcall login` clears it outright. */
export const NO_CREDENTIAL_TTL_MS = 600_000;

interface AutostartRecord {
  loginDeclinedAt?: string;
  reason?: string;
  noCredentialUntil?: number;
}

/** `~/.knoxcall` — or the directory of `KNOXCALL_CREDENTIALS_FILE` when set, so
 *  a caller that relocated its credentials keeps all of its KnoxCall state
 *  together (and a test pointing at a temp dir gets both). */
function stateDir(): string {
  const override = process.env.KNOXCALL_CREDENTIALS_FILE;
  if (override) {
    const parent = dirname(override);
    if (parent) return parent;
  }
  return join(homedir(), ".knoxcall");
}

export function autostartStatePath(): string {
  return join(stateDir(), "autostart.json");
}

function readDocument(path: string): Record<string, unknown> | null {
  try {
    const parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
    return parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null; // missing, unreadable or not JSON — all "no state"
  }
}

/** Temp file in the same directory, then rename over the target; 0700 on the
 *  directory and 0600 on the file (advisory on Windows). */
function writeDocument(path: string, doc: unknown): boolean {
  const dir = dirname(path);
  const tmp = `${path}.${process.pid}.${Date.now()}.tmp`;
  let fd: number | undefined;
  try {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    fd = openSync(tmp, "wx", 0o600);
    writeSync(fd, JSON.stringify(doc));
    closeSync(fd);
    fd = undefined;
    renameSync(tmp, path);
    return true;
  } catch {
    if (fd !== undefined) {
      try {
        closeSync(fd);
      } catch {
        // best-effort: the write already failed; a close error adds nothing
      }
    }
    try {
      unlinkSync(tmp);
    } catch {
      // best-effort: the temp file may never have been created
    }
    return false;
  }
}

export function readAutostartState(profile: string, path = autostartStatePath()): AutostartRecord {
  const doc = readDocument(path);
  const profiles = doc?.profiles;
  if (profiles === null || typeof profiles !== "object" || Array.isArray(profiles)) return {};
  const record = (profiles as Record<string, unknown>)[profile];
  return record !== null && typeof record === "object" && !Array.isArray(record)
    ? (record as AutostartRecord)
    : {};
}

export function writeAutostartState(profile: string, record: AutostartRecord, path = autostartStatePath()): boolean {
  const doc = readDocument(path) ?? {};
  const existing = doc.profiles;
  const profiles: Record<string, unknown> =
    existing !== null && typeof existing === "object" && !Array.isArray(existing)
      ? { ...(existing as Record<string, unknown>) }
      : {};
  profiles[profile] = record;
  return writeDocument(path, { version: 1, profiles });
}

/** Whether this profile already declined (or timed out of) the one-time login
 *  prompt. Cleared by a successful `knoxcall login`, or by deleting the file. */
export function loginDeclined(profile: string, path = autostartStatePath()): boolean {
  return Boolean(readAutostartState(profile, path).loginDeclinedAt);
}

export function recordLoginDeclined(profile: string, reason: string, path = autostartStatePath()): boolean {
  return writeAutostartState(
    profile,
    { loginDeclinedAt: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"), reason },
    path,
  );
}

export function noCredentialRecorded(profile: string, path = autostartStatePath()): boolean {
  const until = readAutostartState(profile, path).noCredentialUntil;
  return typeof until === "number" && Date.now() < until;
}

export function recordNoCredential(profile: string, path = autostartStatePath()): boolean {
  const record = readAutostartState(profile, path);
  return writeAutostartState(profile, { ...record, noCredentialUntil: Date.now() + NO_CREDENTIAL_TTL_MS }, path);
}

/** Forget the decline AND the no-credential verdict — called after a successful
 *  login so the hook starts working again without the user having to find a
 *  state file. */
export function clearLoginDeclined(profile: string, path = autostartStatePath()): boolean {
  const record = readAutostartState(profile, path);
  if (Object.keys(record).length === 0) return true;
  const { loginDeclinedAt: _a, reason: _b, noCredentialUntil: _c, ...rest } = record;
  return writeAutostartState(profile, rest, path);
}
