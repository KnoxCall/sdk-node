// The route-aware interception decision table — pure, no I/O
// (docs/internal/sdk-wrapping/route-aware-interception-plan.md §2.2, PARITY §21).
//
// One request in, one decision out: send it DIRECT (untouched, via the original
// transport), through a ROUTE (the manifest says an intercept-enabled Route
// covers this host + path; the Route injects the stored secret), or through the
// EPHEMERAL proxy (the caller listed the host, no Route covers it; the SDK's own
// credential is lifted out-of-band). The order of the rules is the feature: a
// listed host silently upgrades from ephemeral to route the moment a Route
// covers it, and downgrades back when the Route is disabled.
//
// Every SDK's resolver passes the SAME fixtures — sdk/fixtures/intercept-resolver.json
// — so this file is the Node REFERENCE of a contract, not a private heuristic.
// Keep it boring: no async, no globals, no client access.

import type { InterceptManifest, InterceptManifestRoute } from "./resources/wrap.js";
import { matchRouteAround, type RouteAroundRule } from "./wrap-transport.js";

export type InterceptMode = "direct" | "route" | "ephemeral";

/** Stable reason codes, mirrored by every SDK (observability hooks report them). */
export type InterceptReason =
  | "kill_switch"
  | "unparseable"
  | "own_host"
  | "route_around"
  | "outside_context"
  | "manifest"
  | "no_base_path_match"
  | "no_route"
  | "unlisted";

export interface InterceptDecision {
  mode: InterceptMode;
  reason: InterceptReason;
  /** Normalised request host ("" when unparseable). */
  host: string;
  /** Route mode: the slug to send as `x-knoxcall-route`. */
  slug?: string;
  /** Route mode: the rebased path + query to forward. */
  path?: string;
  /** Route mode: the manifest entry that matched (carries requires_clients / ambiguous). */
  entry?: InterceptManifestRoute;
  /** Route-around: the rule's human reason. */
  routeAroundReason?: string;
}

export interface ResolveInput {
  url: string;
  method: string;
  /**
   * The caller's explicit host list (normalised), or `"all"` for the explicit
   * transport form (`wrap.fetch()`), where every request the wrapped SDK makes
   * is by definition one the caller chose to send through KnoxCall.
   */
  hosts: ReadonlySet<string> | "all";
  manifest: InterceptManifest | null;
  /** The client's own hosts (management + data plane), never intercepted. */
  ownHosts: ReadonlySet<string>;
  routeAround: readonly RouteAroundRule[];
  killSwitch: boolean;
  requireContext: boolean;
  inContext: boolean;
}

/** Lower-case, trailing dot stripped, IPv6 brackets stripped — PARITY §21's host contract. */
export function normaliseHost(hostname: string): string {
  return String(hostname ?? "")
    .trim()
    .toLowerCase()
    .replace(/^\[|\]$/g, "")
    .replace(/\.$/, "");
}

/** KnoxCall's own domains are never intercepted, whatever a manifest or a host list says. */
export function isPlatformHost(host: string): boolean {
  return host === "knoxcall.com" || host.endsWith(".knoxcall.com");
}

/**
 * The request path with the route's base prefix removed (leading slash kept),
 * or null when the request is not under the base. `/crm/v3` covers `/crm/v3`
 * and `/crm/v3/x`, never `/crm/v30` — the boundary is a path segment. Mirrors
 * the server's `rebasePath` (src/lib/route-target-host.ts).
 */
export function rebasePath(requestPath: string, basePath: string): string | null {
  const reqPath = requestPath || "/";
  if (basePath === "/" || basePath === "") return reqPath.startsWith("/") ? reqPath : `/${reqPath}`;
  if (reqPath === basePath) return "/";
  if (!reqPath.startsWith(`${basePath}/`)) return null;
  return reqPath.slice(basePath.length) || "/";
}

/**
 * Manifest entries for a host, in the order the server sorts them: longest
 * base_path first, then slug — so the first entry whose base covers the path
 * is the longest-prefix, lowest-slug match.
 */
export function entriesForHost(manifest: InterceptManifest | null, host: string): InterceptManifestRoute[] {
  if (!manifest) return [];
  return manifest.routes
    .filter((e) => normaliseHost(e.host) === host)
    .sort((a, b) => b.base_path.length - a.base_path.length || a.base_path.localeCompare(b.base_path) || a.slug.localeCompare(b.slug));
}

export function resolveIntercept(input: ResolveInput): InterceptDecision {
  if (input.killSwitch) return { mode: "direct", reason: "kill_switch", host: "" };

  let url: URL;
  try {
    url = new URL(input.url);
  } catch {
    return { mode: "direct", reason: "unparseable", host: "" };
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    return { mode: "direct", reason: "unparseable", host: "" };
  }
  const host = normaliseHost(url.hostname);
  if (!host) return { mode: "direct", reason: "unparseable", host: "" };

  if (isPlatformHost(host) || input.ownHosts.has(host)) {
    return { mode: "direct", reason: "own_host", host };
  }

  const around = matchRouteAround(url.toString(), input.routeAround as RouteAroundRule[]);
  if (around) return { mode: "direct", reason: "route_around", host, routeAroundReason: around.reason };

  if (input.requireContext && !input.inContext) return { mode: "direct", reason: "outside_context", host };

  const entries = entriesForHost(input.manifest, host);
  for (const entry of entries) {
    const rebased = rebasePath(url.pathname, entry.base_path);
    if (rebased !== null) {
      return { mode: "route", reason: "manifest", host, slug: entry.slug, path: rebased + url.search, entry };
    }
  }

  const listed = input.hosts === "all" || input.hosts.has(host);
  if (listed) return { mode: "ephemeral", reason: entries.length > 0 ? "no_base_path_match" : "no_route", host };

  return { mode: "direct", reason: "unlisted", host };
}
