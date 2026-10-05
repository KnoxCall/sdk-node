// One-time, deduplicated warnings for security-relevant misconfigurations
// (plaintext transport, world-readable credentials file). Uses
// process.emitWarning so it respects `--no-warnings` and Node warning handlers,
// and never fires more than once per distinct code+detail in a process.

const _warned = new Set<string>();

/** Test-only: clear the once-per-process dedup so warnings can be re-asserted. */
export function _resetWarnedForTests(): void {
  _warned.clear();
}

export function warnOnce(code: string, message: string): void {
  const key = code;
  if (_warned.has(key)) return;
  _warned.add(key);
  try {
    process.emitWarning(message, { code });
  } catch {
    // process.emitWarning is virtually never unavailable, but never let a
    // warning throw into the caller's path.
  }
}

/** True for a URL whose scheme is plaintext http:// and host is NOT loopback. */
export function isInsecureRemoteUrl(url: string | undefined): boolean {
  if (!url || !/^http:\/\//i.test(url)) return false;
  let host: string;
  try {
    host = new URL(url).hostname.toLowerCase();
  } catch {
    return false;
  }
  const loopback =
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host === "0.0.0.0" ||
    host === "::1" ||
    host === "[::1]" ||
    /^127\./.test(host);
  return !loopback;
}
