/**
 * The route-mode REFUSAL predicate (PARITY §21.1, "Refusal-driven refresh").
 *
 * A KnoxCall-origin refusal on the route data plane is the one response an
 * interceptor answers by refreshing its manifest ONCE and re-deciding ONCE.
 * Two shapes qualify, and `sdk/fixtures/route-refusal.json` is the
 * cross-language contract for both:
 *
 *   - `401` with no upstream stamp — the credential was refused, or the
 *     caller is not (or no longer) authenticated for the route it named.
 *     `call()` has already spent its one re-mint by the time we see this.
 *   - `404` whose envelope `error.type` is `route_not_found` — since the
 *     founder's 2026-09-26 decision an AUTHENTICATED key gets a real 404 for a
 *     route that does not resolve, and a stale manifest naming a Route that
 *     has since been deleted or disabled is exactly this. The
 *     `environment_not_configured` / `environment_disabled` types are refused
 *     as-is: a refresh cannot fix an environment.
 *
 * Any response carrying `X-Knox-Upstream-Status` (the route data plane's
 * response block) or `X-Knox-Destination-Status` (the ephemeral proxy's older
 * spelling) is the UPSTREAM's answer, whatever its status or body, and is never
 * a refusal — an upstream 404 with a body that imitates the envelope included.
 */
export async function isRouteRefusal(res: Response): Promise<boolean> {
  if (res.headers.get("x-knox-upstream-status") || res.headers.get("x-knox-destination-status")) return false;
  if (res.status === 401) return true;
  if (res.status !== 404) return false;
  return (await routeRefusalType(res)) === "route_not_found";
}

/**
 * The envelope's `error.type` on a 404, read from a CLONE so the caller's
 * body stream is untouched; `null` for anything that is not the Shape-A
 * envelope (`{ error: { type, message, request_id } }`).
 */
async function routeRefusalType(res: Response): Promise<string | null> {
  let parsed: unknown;
  try {
    parsed = await res.clone().json();
  } catch {
    return null; // not JSON, or the body is not readable — not the envelope
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return null;
  const error = (parsed as { error?: unknown }).error;
  if (typeof error !== "object" || error === null || Array.isArray(error)) return null;
  const type = (error as { type?: unknown }).type;
  return typeof type === "string" ? type : null;
}
