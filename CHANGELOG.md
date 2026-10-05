# Changelog

All notable changes to this package are documented here. This project adheres
to [Semantic Versioning](https://semver.org/) and
[Keep a Changelog](https://keepachangelog.com/).

**First release: 1.0.0, 2026-09-27** — published to npm as `@knoxcall/sdk` (monorepo tag `knoxcall-node-v1.0.0`).

## [Unreleased]

### Changed
- **1.1.0 — registry install instructions.** A registry renders the README that was inside the version it published and never lets it be edited, so the README inside the previous release still showed pre-release install instructions (build from a source checkout) after the package was live; the corrected README reaches a registry only as a new version. The ad-hoc CLI command is now `npx -p @knoxcall/sdk knoxcall login`: the bare `npx` form resolved the unscoped `knoxcall` npm package, a placeholder with no CLI in it. `SDK_VERSION` (the `knoxcall-sdk-node/<v>` User-Agent) is `1.1.0`. The version is a minor, not a patch: the `Retry-After` change below adds `ServerError.retryAfter`, which is new public API.
- **`Retry-After` is honoured on a 503, not only on a 429.** KnoxCall now answers a request it could not serve because one of its own dependencies did not answer in time with `503 { error: { type: "dependency_unavailable", … } }` + `Retry-After` (on the data plane this used to surface as an opaque `401 Unauthorized`; on `/v1` as `500 internal_error`). `ServerError` exposes the header as `retryAfter` (absent when none was sent), and the retry loop waits it — capped at 30 s — before the next attempt, exactly as it does for a 429; a plain 5xx with no header keeps the jittered backoff. Nothing to change in calling code: it is a retryable server error, never an authentication failure, and never a manifest-refresh trigger. (PARITY §4, §16.)

## [1.0.0] — 2026-09-27

### Changed
- **Refusal-driven refresh learns the 404.** The route data plane now answers an AUTHENTICATED credential's call to a Route that does not resolve with `404 { error: { type: "route_not_found" | "environment_not_configured" | "environment_disabled", message, request_id } }` plus the KnoxCall response block, instead of the opaque `401 Unauthorized` (which callers the tenant has not authenticated keep — founder decision 2026-09-26, PARITY §21). `wrap.intercept()` and `wrap.fetch({ routes: "auto" })` now treat a KnoxCall-origin `404` whose envelope `error.type` is `route_not_found` as a refresh trigger alongside the 401 — a stale manifest naming a deleted Route is exactly that — refreshing once and re-deciding once, never looping. The `environment_*` types are surfaced as-is (a refresh cannot fix an environment); an UPSTREAM 404 (`X-Knox-Upstream-Status` present) never triggers it, whatever its body says; the decision reads the body from a clone, so the caller's response is intact. `onRefused` reports `status: 404` for that case. `call()` is unchanged: it returns the 404 raw (PARITY §5) and spends no re-mint on it, so a 404 refusal costs one route call. Cross-language contract: `sdk/fixtures/route-refusal.json`.

### Added
- **Uncovered-egress observations (PARITY §21.3), on by default.** `wrap.intercept()` (and `wrap.fetch({ routes: "auto" })`) now counts calls it sends direct because their host is `unlisted` while they carry a credential-bearing header — host, first path segment, method and the header NAME; never the value, the query string or the body — and reports them to `POST /v1/wrap/egress-observations` about once a minute (at 200 distinct keys at once; once more on `uninstall()`). Opt out with `observeUncovered: false` or `KNOXCALL_OBSERVE_UNCOVERED=off`; nothing is reported while `KNOXCALL_INTERCEPT=off`; a 403 stops reporting with one warning. New `onObservationFlush` hook, `wrap.reportEgressObservations(observations)`, the `EgressObservation` / `EgressObservationsReport` types, and the exported classifier (`observationFor`, `credentialHeaderName`, `EgressObservationReporter`). The global-fetch seam now also bypasses egress made inside the SDK's own suppressed scope, as the http seam always did. (Founder decision 2026-09-26: default-on with an opt-out.)
- **A credential in the path is never reported.** Before an uncovered-egress observation is sent, a first path segment that looks like a credential (Telegram's `/bot<id>:<secret>`, a Stripe/GitHub/AWS/Google/Slack/JWT token, any segment over 64 characters, or a 24+ character mixed-class run — raw or percent-decoded) is reported as `/`; the server's identical rule (#1022) counts it under the receipt's new `redacted` field, now on the report type. (PARITY §21.3.)
- `wrap.interceptManifest({ ifNoneMatch })` — the conditional poll. Pass the manifest `version` you hold and the SDK sends `If-None-Match: W/"<version>"` (`manifestEtag()`, exported); the server's `304` resolves to `null` — keep what you hold. The route-aware store (`wrap.intercept()`, `wrap.fetch({ routes: "auto" })`) now polls this way on every refresh after the first, scheduled or forced: a `304` keeps the manifest, restarts the TTL clock, clears backoff and fires no `onRefresh`, so a steady-state poll costs no body bytes. Auth, the one re-auth on 401 and retries are unchanged; the unconditional call never returns `null`. (PARITY §21.1 "Conditional poll"; fixture `sdk/fixtures/intercept-store-conditional.json`.)
- **Origin marker on rerouted calls.** Every route-mode send from `wrap.intercept()` / `wrap.fetch({ routes: "auto" })` (and the legacy explicit `route:` form) now carries `x-knoxcall-origin: sdk-intercept`, so the API Log shows the call as **SDK intercept** rather than **Direct** (`client_origin` on `RequestLog` rows: `"direct" | "sdk_intercept"`). A direct `call()` / bound route sends nothing; an ephemeral hop sends nothing. A caller-supplied `x-knoxcall-origin` in `call()` / `ephemeral()` `headers` is stripped like the proxy-auth headers — the server treats the marker as informational either way. (PARITY §21.2.)
- **Route-aware interception.** `wrap.intercept(opts?)` — the process-wide interceptor (global `fetch` + `node:http`/`https`) now polls the intercept manifest by default and sends each request through the Route that covers its host + path (the Route injects the secret; no provider credential travels), through the ephemeral proxy for listed hosts no Route covers, and untouched otherwise. A Route created, enabled or disabled later takes effect on the next poll or refusal, with no re-install. `hosts` may be empty or a map with per-host `credential` / `unavailable`; the handle has `ready`, `refresh()`, `manifest()`. `wrap.fetch({ routes: "auto" })` gives an explicit transport the same behaviour (default stays `"off"`); it now returns a `WrappedFetch` with `ready` / `refresh()` / `manifest()` / `stop()`. New hooks: `onReroute`, `onRefresh`, `onManifestError`, `onUnmatchedPath`, `onRefused`, `onFallback`; `unavailable: "direct"` (transit only) opts out of fail-closed. `KNOXCALL_INTERCEPT=off` is the kill switch. `interceptEgress()` is now a deprecated alias for the static, ephemeral-only form. Exports `resolveIntercept`, `InterceptManifestStore`, `interceptKillSwitch` and the decision types. (route-aware-interception-plan.md PR2; PARITY §18 note 4 + §21.1.)
- `wrap.interceptManifest({ environment? })` — `GET /v1/wrap/intercept-manifest`, the per-environment list of upstream hosts an intercept-enabled Route covers (host, `base_path`, slug, `requires_clients`, `allowed_methods`; `version` doubles as the ETag). What a route-aware interceptor polls (route-aware-interception-plan.md PR1). Types `InterceptManifest`, `InterceptManifestRoute`, `InterceptManifestOptions`.
- `intercept_enabled` on `CreateRouteInput`, `UpdateRouteInput` and `RouteEnvironmentInput` — the per-environment opt-in the agent's intercept mode and `wrap.intercept()` share; echoed on route reads.

### Fixed
- `InterceptManifestStore` signalled `ready` one microtask before clearing its in-flight refresh, so `await ready; refresh()` was coalesced into the attempt that had just settled and fetched nothing. `ready` now resolves after the flight is cleared.
- `call()` / `ephemeral()` no longer spend their one token re-mint on an UPSTREAM 401 relayed by the route data plane: the response block's `X-Knox-Upstream-Status` is now recognised alongside the ephemeral proxy's `X-Knox-Destination-Status` as "the upstream answered".
- `call()` — and bound routes, the CLI and the interceptors' route mode, which delegate to it — now places the upstream path under the tenant host's `/api` data-plane entry point whenever the proxy base is a KnoxCall cloud tenant host with no path of its own (derived, or an explicit override naming one); any other base is used verbatim. Before, `call("r", { path: "/users" })` sent `https://{tenant}.knoxcall.com/users`, which a tenant host answers with the dashboard, not the proxy — every documented example was affected, and `path: "/api/…"` was the only form that worked. `path` is now always the upstream path (PARITY §5).

> **This section was headed `## [1.0.0] — 2026-08-04` and described it as a
> First public release until 2026-08-23. That release never happened**: `git tag --list` is
> empty, the package name was still unclaimed at the last check (2026-08-11,
> `docs/internal/runbooks/sdk-publish.md`), and no artifact was ever pushed to a
> registry. The same fabricated-release shape was removed from the Terraform
> provider's changelog on 2026-08-06; this is that correction applied to the
> remaining packages. The content below is accurate — it is the work that will
> ship in the first release — only the heading was a claim.
>
> `tests/coverage/sdk-changelog-honesty.test.ts` now refuses any release heading
> with no matching git tag, so this cannot recur silently.

### Added
- `WorkloadCredentialProvider` — caches a workload-identity capability token and
  refreshes it on a two-tier schedule (advisory at expiry−120s, mandatory at
  expiry−30s), calling a caller-supplied assertion SOURCE before every exchange.
  Because KnoxCall assertions are single-use, a source that returns bytes already
  spent is refused locally with `StaleAssertionError` rather than sent and refused
  as a replay. N concurrent callers cause one exchange. PARITY §20.
- Full `/v1` management surface (routes, secrets, vaults, PKI, crypto/transit,
  dynamic DB, clients, OAuth clients, environments, API keys, account, audit
  logs, agents, AI Gateway) with typed responses and `{data, meta}` pagination.
- Data-plane `call()`, bound routes, and one-shot `ephemeral()` proxying.
- OAuth 2.1 client-credentials, pre-acquired token, and OIDC token-exchange
  bootstraps; zero-config env + `~/.knoxcall/credentials.json` auto-detection;
  DPoP (RFC 9449) with `auto`/`always`/`never` modes.
- `constructEvent` webhook verification (legacy/stripe/github/slack/aws-sns/
  custom) and the `knoxcall` CLI (`login`/`logout`/`whoami`).

### Security
- The SDK credential is now the sole data-plane auth authority: `call()` and
  `ephemeral()` strip any caller-supplied proxy-auth headers
  (`Authorization`, `DPoP`, `x-knoxcall-key`, `x-knoxcall-agent-id`,
  `x-knoxcall-agent-token`) before setting their own.
- The credentials-file lock is now ownership-aware (unique owner tag, atomic
  rename to break a stale lock, content-matched release) and the stale window
  sits above a bounded refresh timeout — closing a double-refresh race that
  could trip server-side refresh-token family revocation.
- Tenant slugs are validated as bare DNS labels before becoming a data-plane
  hostname, preventing token misdirection from a hostile slug.
