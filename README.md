# @knoxcall/sdk

Official KnoxCall API client for Node.js and TypeScript. Standards-based OAuth 2.1 + DPoP (RFC 9449) under the hood — your code just calls methods.

```ts
import { KnoxCall } from "@knoxcall/sdk";

// Credentials inline — no extra imports
const client = new KnoxCall({ clientId: "tk_xxxxxxxx", clientSecret: "..." }); // tenant auto-discovered

// Or zero-arg with the environment configured
// (KNOXCALL_TENANT, KNOXCALL_CLIENT_ID, KNOXCALL_CLIENT_SECRET)
const client2 = new KnoxCall();

const routes = await client.routes.list(); // { data: Route[], meta: { total, page, ... } }
const resp = await client.call("orders-api", { path: "/v1/customers" }); // slug preferred; UUIDs also work
console.log(await resp.json());
```

With no explicit credentials, the SDK auto-detects your platform (GitHub Actions, GCP, AWS, Azure, Vercel) and uses workload identity federation — no stored secrets. On a laptop, run `knoxcall login` once or set `KNOXCALL_CLIENT_ID` + `KNOXCALL_CLIENT_SECRET` env vars.

## Install

```bash
npm install @knoxcall/sdk@^1.0.0
```

Requires Node 18 or newer.

## Authentication

Pass credentials as plain constructor options:

| Option | Use |
|---|---|
| `clientId` + `clientSecret` | OAuth client-credentials grant (recommended for servers) |
| `accessToken` / `apiKey` | a pre-acquired token or key — two spellings, one behavior; works with `kc_…` tokens and legacy `tk_…`/`AKE…` keys |
| `bootstrap` | advanced: `OidcTokenExchange` and friends |
| `sandbox: true` | target Test mode (sandbox host + test keys) |

> **A pre-acquired `accessToken`/`apiKey` is not auto-renewed.** It has no
> refresh token, so the SDK uses it until it expires server-side, then surfaces
> a 401 `AuthenticationError`. For long-lived processes that should re-auth on
> their own, use `clientId` + `clientSecret` (or `knoxcall login` /
> `ensureLogin()`), which mint and refresh tokens for you.
>
> **Transport & storage:** a plaintext `http://` base or proxy URL pointing at a
> non-loopback host emits a one-time warning — credentials would travel
> unencrypted; use `https://` (plain `http://` is only for localhost). On POSIX,
> the SDK also warns once if `~/.knoxcall/credentials.json` is group/other-readable
> (`chmod 600` it).

With no explicit credentials, the SDK auto-detects from the environment in priority order:

1. `KNOXCALL_ACCESS_TOKEN` (or `KNOXCALL_API_KEY`) env var — pre-acquired token
2. Credentials file written by `knoxcall login` (`~/.knoxcall/credentials.json`)
3. GitHub Actions OIDC (`ACTIONS_ID_TOKEN_REQUEST_URL`)
4. GCP metadata service
5. AWS IRSA (`AWS_WEB_IDENTITY_TOKEN_FILE`)
6. Azure Managed Identity
7. Vercel / CircleCI / Buildkite / GitLab CI OIDC
8. `KNOXCALL_CLIENT_ID` + `KNOXCALL_CLIENT_SECRET` env vars

### Log in once with the CLI

The [knoxcall CLI](https://docs.knoxcall.com/sdks/overview#log-in-once-with-the-cli) ships with this package — `npm install -g @knoxcall/sdk` puts `knoxcall` on your PATH, or run it ad hoc with `npx -p @knoxcall/sdk knoxcall login` (`-p` names the package the CLI ships in). Every other KnoxCall SDK (pip, gem, composer, `go install`) ships the same command with the same surface, and all of them write the same file, so it does not matter which one you use. Sign in once in your browser and every script and agent on the machine picks the credential up automatically — no env vars, no keys in code:

```bash
knoxcall login                    # opens your browser (PKCE); prints the URL too
knoxcall login --device           # headless\SSH machines: device-code flow
knoxcall login --sandbox          # log in against the sandbox environment
knoxcall login --profile staging  # keep multiple accounts side by side
knoxcall whoami                   # show the signed-in tenant
knoxcall logout                   # revoke + remove the stored credential
```

### From an empty tenant to a real call, in two commands

`knoxcall ai` is the AI-gateway golden path. The provider key is read from the
environment named by `--secret-from-env` — there is deliberately no
`--secret-value`, because an argv value lands in shell history, `ps` output and
the CI log line that echoes the command.

```bash
export ANTHROPIC_API_KEY=sk-ant-...
AGENT="$(knoxcall ai create-agent --name copilot --slug copilot     --provider anthropic --secret-from-env ANTHROPIC_API_KEY)"
TOKEN="$(knoxcall ai mint --agent "$AGENT")"
# create-agent prints the agent_url to stderr; point any AI SDK's base_url at it.
```

`create-agent` escrows the key, uses your only gateway (or creates one when you
have none, or lists them and stops when there are several), and refuses to make
an agent with no upstream — the API accepts that and stores one whose first call
fails.

```bash
knoxcall ai gateways              # id  slug  name
knoxcall ai agents --gateway ID   # id  slug  agent_url
knoxcall ai usage --period 30d    # cost + tokens by model
knoxcall ai exchange --tenant acme  # CI: swap an OIDC token for a capability token
knoxcall ai import --from litellm --file ./config.yaml  # migrate (dry run)
```

Every one of these is in all five KnoxCall SDK CLIs with the same flags, except
`import`, which is Node-only — see
[Migrating from LiteLLM](https://docs.knoxcall.com/ai-gateway/migrate-from-litellm).

```ts
import { KnoxCall } from "@knoxcall/sdk";

const client = new KnoxCall(); // zero config — tenant and base URL come from the login
const routes = await client.routes.list();
```

Credentials are stored in `~/.knoxcall/credentials.json` (file mode 0600).
The stored tenant and base URL seed the client automatically; explicit
constructor options or env vars always win. Access tokens refresh
themselves, and refreshes are cross-process safe (file lock + atomic
rotation of the single-use refresh token). If a refresh fails because the
credential was revoked or expired, the SDK throws `AuthenticationError`
telling you to run `knoxcall login` again. Select a non-default profile with
`KNOXCALL_PROFILE` (or `new StoredCredentials({ profile: "..." })`).

### Log in from your code

You don't have to shell out to the CLI — the SDK can run the same login flow
programmatically. This is **opt-in and never automatic**: construction and
`.call()` never pop a browser; they throw `NotAuthenticatedError` when no
credential is found, so a library embedded in your server or CI never blocks.

```ts
import { ensureLogin, login, NotAuthenticatedError } from "@knoxcall/sdk";

// Use the stored credential if present, otherwise run the browser/device flow once:
const client = await ensureLogin();               // { mode: "auto" | "browser" | "device", sandbox, profile, tenant }
const routes = await client.routes.list();

// Or handle "not logged in" yourself on the normal path:
try {
  const c = new KnoxCall();
  await c.routes.list();
} catch (e) {
  if (e instanceof NotAuthenticatedError) {
    const c = await login(); // explicit, interactive
  } else throw e;
}
```

`login()`/`ensureLogin()` refuse to prompt when it wouldn't be safe — no TTY,
`CI`, or `KNOXCALL_NO_INTERACTIVE` set — raising `NotAuthenticatedError` so
headless servers, CI, and agents provision a real credential
(`clientId`/`clientSecret` or workload OIDC) instead. Pass
`{ allowNonInteractive: true }` only when you know the flow can complete.

### Environment variables

| Variable | Meaning |
|---|---|
| `KNOXCALL_TENANT` | tenant slug (optional — auto-discovered from the credential when unset) |
| `KNOXCALL_ENVIRONMENT` | default environment for data-plane calls |
| `KNOXCALL_CLIENT_ID` / `KNOXCALL_CLIENT_SECRET` | client-credentials grant |
| `KNOXCALL_ACCESS_TOKEN` / `KNOXCALL_API_KEY` | pre-acquired token (ACCESS_TOKEN wins) |
| `KNOXCALL_BASE_URL` | management API base override |
| `KNOXCALL_PROXY_BASE_URL` | data-plane base override (a cloud tenant host still gets the `/api` entry point added unless the base already carries a path) |
| `KNOXCALL_CREDENTIALS_FILE` | credentials file path override (default `~/.knoxcall/credentials.json`) |
| `KNOXCALL_PROFILE` | credentials-file profile to use (default `default`) |

### Token stores

Minted OAuth tokens are cached in-memory by default. Swap the store for multi-process or multi-host reuse:

```ts
import { KnoxCall, FileTokenStore, RedisTokenStore, MemoryTokenStore } from "@knoxcall/sdk";

const client = new KnoxCall({ tokenStore: new FileTokenStore("~/.knoxcall/token-cache.json") });
// or share across hosts:
const shared = new KnoxCall({ tokenStore: new RedisTokenStore(redisClient) });
```

All stores implement the exported `TokenStore` interface (single-flight refresh, redacted at rest in memory).

## Calling routes

`client.call()` proxies a request through a KnoxCall route to your upstream and returns the raw `Response`. Reference routes by **slug** — the write-once machine handle set on the route. Slugs are immutable (rename-proof, unlike names) and portable across tenants (unlike UUIDs). UUIDs also work; bare names are legacy.

```ts
// GET
const resp = await client.call("orders-api", { path: "/users" });
const users = await resp.json();

// POST with body, targeting a specific environment
await client.call("orders-api", {
  method: "POST",
  path: "/v1/charges",
  body: { amount: 2000, currency: "usd" },
  environment: "staging",
});
```

By default the proxy URL is derived from your tenant slug (`https://{tenant}.knoxcall.com`), and `path` is the **upstream** path: on a KnoxCall cloud tenant host the data plane is served under `/api` (`https://{tenant}.knoxcall.com/api/<path>`), and the SDK adds that prefix itself. Override for local dev or self-hosting with `proxyBaseUrl` or the `KNOXCALL_PROXY_BASE_URL` env var — a base naming a cloud tenant host still gets `/api` unless it already carries a path; any other base is used verbatim. So `/api/v2/tickets` reaches an upstream path that itself begins with `/api`.

### Bound routes

State the route (and optional defaults) once with `client.route()`, then use plain HTTP verbs:

```ts
const printnode = client.route("printnode", { environment: "production" });

const computers = await (await printnode.get("/computers")).json();
await printnode.post("/printjobs", { body: { printerId: 1, title: "Invoice" } });
await printnode.request("DELETE", "/printjobs/42");
// per-call options still override the bound defaults:
await printnode.get("/computers", { environment: "staging" });
```

The handle holds no state beyond the defaults — retries, token refresh, and 401 re-mint behave exactly as on `call()`.

### Ephemeral proxy

One-shot proxying to any upstream without configuring a route first:

```ts
const resp = await client.ephemeral("https://api.example.com/v1/things", {
  method: "POST",
  body: { hello: "world" },
});
```

### Route-aware interception (preview)

Send an untouched third-party SDK's traffic through the Route that covers it —
and through the ephemeral proxy where no Route does — with no per-SDK wiring:

```ts
const knox = new KnoxCall({ apiKey });
const stop = knox.wrap.intercept({ hosts: ["api.resend.com"] }); // hosts with NO Route still covered (ephemeral)
await stop.ready;                                                  // first manifest loaded

const hubspot = new Client({ accessToken: "placeholder" });        // an untouched SDK
await hubspot.crm.contacts.basicApi.getPage();                     // via the Route that covers api.hubapi.com
stop.uninstall();
```

Per request: the kill switch (`KNOXCALL_INTERCEPT=off`), KnoxCall's own hosts
and route-around rules go direct; a Route in the manifest covering host + path
goes through that Route (the Route injects the stored secret — no provider
credential travels); a host in `hosts` with no Route goes through the ephemeral
proxy; everything else is untouched. Turn a Route's **Intercept** toggle on and
it takes effect on the next poll (60 s) or the next refusal, with no code change.
Per-host options: `hosts: { "api.resend.com": { credential: { secret: "resend-key" } } }`
(escrow) or `{ unavailable: "direct" }` (transit only: send direct when KnoxCall
is unreachable; the default is fail closed).

The same decisions are available to an explicit transport with
`knox.wrap.fetch({ routes: "auto" })`, which returns a `fetch` you can `await
wrapped.ready` on and `wrapped.refresh()` / `wrapped.manifest()` / `wrapped.stop()`.

This is a convenience, not a security boundary: it patches process globals
(global `fetch` and `node:http`/`https`), does not reach a captured reference or
a custom undici dispatcher, and composes with APM agents in install order.
Route mode is the custody path — the key never enters your process.

#### What the SDK reports about uncovered calls, and how to turn it off

**Reporting is on by default.** When the interceptor sends a call direct
because no Route covers its host and you did not list the host, and that call
carries a credential header (`Authorization`, `X-Api-Key`, or any name ending
in `-api-key`, `-token`, `-secret` or `-auth`), the SDK counts it. About once a
minute, the SDK reports the counts to KnoxCall
(`POST /v1/wrap/egress-observations`) with its own credential. The dashboard
uses the report to show which credentials still leave your process outside
KnoxCall custody.

**What is sent.** Each report carries the host, the first path segment, the
method, the credential header's **name**, a count, and first/last-seen times.
The header's **value** is never sent, and neither are the query string, the
body, or any deeper path.

**How to turn it off.** Pass `observeUncovered: false` when you install, or set
`KNOXCALL_OBSERVE_UNCOVERED=off` in the environment. Nothing is reported while
`KNOXCALL_INTERCEPT=off`. If your key lacks `routes:read`, the first report is
refused, you get one warning, and reporting stops. `onObservationFlush` receives the
server's `{accepted, dropped}` after each report.

## DPoP — sender-constrained tokens

For higher-security tenants, enable DPoP (RFC 9449):

```ts
const client = new KnoxCall({ tenant: "acme", dpop: "always" });
```

The SDK generates an ES256 keypair at startup, binds the access token to it via the `cnf.jkt` claim, and signs a fresh proof JWT per request. Stolen tokens become useless without the keypair.

## Response envelope & pagination

The server wraps every JSON response in `{ data, meta }`. The SDK unwraps for you:

- **Single objects** (`get`, `create`, `update`, `delete`, …) return the object directly.
- **Paginated lists** return the typed page as-is — `{ data: T[], meta: { total, page, per_page, total_pages, request_id } }` — and take `{ page?, per_page? }` params (server default 20, cap 100). `iterate()` walks all pages for you. There is no cursor pagination.
- **Bare-array lists** (environments, agents, crypto keys, PKI roots/roles, dyn-db connections/roles, client credentials, route environments) return a plain array, no page params.

```ts
const page = await client.routes.list({ page: 2, per_page: 50 });
console.log(page.meta.total_pages);

for await (const route of client.routes.iterate()) {
  console.log(route.slug ?? route.id);
}
```

## Resources

One example per resource — every method is fully typed against the live v1 response shapes.

### Routes

```ts
const route = await client.routes.create({ name: "Orders API", slug: "orders-api", target_base_url: "https://api.example.com" });
const detail = await client.routes.get("orders-api");           // slug, UUID also works
const logs = await client.routes.getLogs(route.id, { per_page: 50 }); // paginated
const envs = await client.routes.listEnvironments(route.id);   // plain array
await client.routes.upsertEnvironment(route.id, "staging", { target_base_url: "https://staging.example.com" });
// Field actions: declarative field-level encrypt/decrypt/tokenize on the relay
const actions = await client.routes.listActions(route.id);
```

### Secrets

```ts
const secret = await client.secrets.create({ name: "Stripe key", value: "sk_live_..." });
await client.secrets.setValue(secret.id, { value: "sk_live_rotated", environment: "production" });
const token = await client.secrets.getOAuthToken("secret-id"); // OAuth2 secrets: auto-refreshed access token
for await (const s of client.secrets.iterate()) console.log(s.name, s.secret_type);

// Structured secret types (the base create() can't carry these fields):
await client.secrets.createOAuth2({ name: "Salesforce", provider: "custom", client_id: "ci", client_secret: "cs", token_url: "https://login.example.com/oauth/token", scopes: ["api"] });
await client.secrets.createCertificate({ name: "mTLS client", certificate_content: "-----BEGIN CERTIFICATE-----\n...", certificate_type: "pem" });
```

### Webhooks

```ts
const wh = await client.webhooks.create({
  name: "orders",
  url: "https://hooks.example.com/knoxcall",
  event_types: ["request.completed"],
});
console.log(wh.secret_key); // shown ONCE — store it now
const types = await client.webhooks.listEventTypes();
const result = await client.webhooks.test(wh.id);
const deliveries = await client.webhooks.getLogs(wh.id, { per_page: 20 });
```

### Clients (data-plane callers)

```ts
const c = await client.clients.create({ name: "warehouse-server", type: "server", ip_address: "203.0.113.7" });
const creds = await client.clients.listCredentials(c.id); // plain array
await client.clients.createCredential(c.id, { kind: "ip", data: { ip: "203.0.113.8" } });
```

### OAuth clients

```ts
const oc = await client.oauthClients.create({ name: "backend-svc", grant_types: ["client_credentials"] });
console.log(oc.client_secret); // shown ONCE (null for public clients)
if (oc.warning) console.warn(oc.warning); // server advisory, when present
const rotated = await client.oauthClients.rotateSecret(oc.id);
```

### Environments

```ts
const envs = await client.environments.list(); // plain array
await client.environments.create({ name: "staging", display_name: "Staging", color: "#f59e0b" });
```

### API keys

```ts
const key = await client.apiKeys.create({ name: "ci" });
console.log(key.api_key); // shown ONCE
await client.apiKeys.revoke("key-id"); // → { revoked: true }
```

### Account

```ts
const account = await client.account.get();          // slug, plan, region, …
const usage = await client.account.getUsage();       // api_calls.used / limit, per-resource counters
```

### Audit logs

```ts
for await (const entry of client.auditLogs.iterate({ action: "secret.created" })) {
  console.log(entry.created_at, entry.action, entry.resource_id);
}
```

### Agents

```ts
const agent = await client.agents.create({ name: "dc1-agent" });
console.log(agent.agent_secret); // shown ONCE
const tamper = await client.agents.getTamperEvents(agent.id);
```

### Crypto / Transit (encryption-as-a-service)

```ts
await client.crypto.createKey({ name: "app-key", mode: "cloud-only" });
const { ciphertext } = await client.crypto.encrypt("app-key", { plaintext: "hello" });
const { plaintext_b64 } = await client.crypto.decrypt("app-key", { ciphertext });
const jwt = await client.crypto.signJwt("app-key", { claims: { sub: "user_1" } });

// Portable kc: encryption — structure-preserving over arbitrary JSON
const sealed = await client.crypto.encryptData({ ssn: "123-45-6789", name: "ok" });
const opened = await client.crypto.decryptData(sealed.data);
const meta = await client.crypto.inspect("kc:...");                    // ciphertext metadata, no decrypt
const bundle = await client.crypto.getSealingBundle();                 // public bits for browser-side sealing
const cap = await client.crypto.mintClientToken({ action: "decrypt", data: "kc:..." }); // one-shot browser reveal
```

### PKI (customer-facing CA)

```ts
const { root } = await client.pki.createRoot({ name: "internal", subject: { CN: "Acme Internal CA" } });
await client.pki.createRole("internal", { role_name: "servers", allowed_domains: ["internal.acme.com"] });
const cert = await client.pki.issueCert("internal", "servers", { subject: { CN: "api.internal.acme.com" } });
console.log(cert.private_key_pem); // shown ONCE
const pem = await client.pki.getRootCert("internal"); // raw PEM string
```

### Vaults (tokenization)

```ts
const vault = await client.vaults.create({ name: "pii", token_format: "uuid" });
const tok = await client.vaults.tokenize("pii", { value: "4111 1111 1111 1111" });
const plain = await client.vaults.detokenize("pii", tok.token); // .value
for await (const t of client.vaults.iterateTokens("pii")) console.log(t.id);
```

### Dynamic DB credentials

```ts
await client.dynamicDb.create({ name: "orders-db", engine: "postgres", host: "db.internal", admin_username: "postgres", admin_password: "..." });
await client.dynamicDb.createRole("orders-db", { name: "readonly", template: "postgres-readonly" });
const cred = await client.dynamicDb.mint("orders-db", "readonly", { ttl_seconds: 900 });
// cred.username / cred.password (shown ONCE) / cred.lease_id
const { leases, total } = await client.dynamicDb.listLeases({ limit: 100 });
await client.dynamicDb.revokeLease(cred.lease_id);
```

### AI Gateway (agents & capability tokens)

Control-plane for the AI egress gateway: gateways hold agents, agents mint capability tokens, and `usage()` rolls up spend by model.

An agent needs an upstream credential, so the first step is a Secret holding
your provider key. Pass `provider` + `upstream_secret_id` and KnoxCall composes
the upstream route for you — **an agent created without either has no upstream,
and its first data-plane call 502s.**

```ts
// 1. Escrow the provider key. It never leaves KnoxCall in plaintext again.
const secret = await client.secrets.create({
  name: "anthropic-key",
  value: process.env.ANTHROPIC_API_KEY!,
});

// 2. Gateway -> agent. `provider` is a plain string; the catalog is
//    server-side (anthropic, openai, gemini, groq, bedrock, … ) and a bad one
//    comes back as a 400 naming the valid set.
const gw = await client.aiGateway.createGateway({ name: "prod", slug: "prod", budget_daily_usd: 50 });
const agent = await client.aiGateway.createAgent(gw.id, {
  name: "copilot",
  slug: "copilot",
  provider: "anthropic",
  upstream_secret_id: secret.id,
  default_model: "claude-sonnet-5",
});

// 3. Mint a capability token and point any AI SDK at the agent.
const minted = await client.aiGateway.mintToken(agent.id, { kind: "agent", dpop_required: true });
// minted.token is the plaintext, shown ONCE — store it now.
console.log(agent.agent_url);  // https://<tenant>.knoxcall.com/v1/ai/copilot
// e.g. new Anthropic({ baseURL: agent.agent_url, apiKey: minted.token })

for await (const t of client.aiGateway.iterateTokens(agent.id)) console.log(t.prefix); // list rows never carry plaintext
await client.aiGateway.revokeToken(agent.id, minted.id);
const usage = await client.aiGateway.usage({ period: "30d", agent_id: agent.id }); // usage.by_model / usage.totals
```

`upstream` is required for the four providers whose endpoint is yours rather than
the vendor's: `azure-openai`, `ollama`, `bedrock` and `openai-compatible`. It is
not defaulted — creating an agent on one of those four without it is a 400 —
and `openai-compatible` additionally requires `default_model`. If you already
have a Route carrying the credential, pass `primary_route_id` instead of the
`provider` pair — never both.

### Workflows

```ts
const wf = await client.workflows.create({ name: "nightly-sync", definition: { /* nodes */ } });
const run = await client.workflows.execute(wf.id, { since: "2026-08-01" }); // queues a run
const page = await client.workflows.list({ per_page: 50 });                 // paginated
for await (const w of client.workflows.iterate()) console.log(w.name, w.version);

// Executions (runs)
const execs = await client.workflows.listExecutions(wf.id, { per_page: 20 });
const exec = await client.workflows.getExecution(run.id);
await client.workflows.cancelExecution(run.id);
```

### Signup (credential-less)

Create an account headlessly — the one surface that needs no client. Two steps:
`signup()` returns a claim handle and emails a sign-in link, and the starter key
is released once the account owner clicks it.

```ts
import { signup, claimSignup, SignupError } from "@knoxcall/sdk";

try {
  const { claim_handle, poll_after_seconds } = await signup({
    email: "dev@example.com",
    tenant_name: "Acme Inc",
  });
  // …the owner clicks the emailed sign-in link…
  let claim = await claimSignup({ claim_handle });
  while (claim.status === "pending") {
    await new Promise((r) => setTimeout(r, poll_after_seconds * 1000));
    claim = await claimSignup({ claim_handle });
  }
  // claim.starter.api_key.api_key is shown ONCE — store it now.
  const client = new KnoxCall({ apiKey: claim.starter.api_key.api_key, sandbox: true });
} catch (e) {
  if (e instanceof SignupError) console.error(e.status, e.type, e.message);
}
```

`signup()` is enumeration-safe: its reply is identical whether or not the address
already has an account. Treat `claim_handle` as a secret — it is what collects
the key.

## Webhook verification

`constructEvent` verifies the delivery signature AND parses it into a typed event in one step — use it in your webhook handler. Pass the **raw body bytes** (never re-serialized JSON):

```ts
import { constructWebhookEvent, WebhookSignatureVerificationError } from "@knoxcall/sdk";

app.post("/webhooks/knoxcall", express.raw({ type: "application/json" }), (req, res) => {
  try {
    // Positional and synchronous (pure computation, no I/O — no await):
    // (rawBody, headers, secret, options?)
    const event = constructWebhookEvent(
      req.body,                              // Buffer — the raw bytes
      req.headers,
      process.env.KNOXCALL_WEBHOOK_SECRET!,
      // { format: "stripe" | "github" | "slack" | "aws-sns" | "custom" } — match your webhook's hmac_format (default "legacy")
    );
    if (event.event === "request.server_error") {
      console.error(`${event.data.route_name} returned ${event.data.response.status}`);
    }
    res.sendStatus(200);
  } catch (e) {
    if (e instanceof WebhookSignatureVerificationError) return res.sendStatus(400);
    throw e;
  }
});
```

Also available as `client.webhooks.constructEvent()`. The returned `KnoxWebhookEvent` is a discriminated union on `event`: `request.*` events carry route/request/response data, `audit.event` carries the audit row, and unknown event types still parse (forward compatible). Timestamps are replay-checked (default tolerance 300s; pass `toleranceSeconds: null` to disable).

The lower-level boolean check remains for legacy-format callers who only need a yes/no:

```ts
import { verifyWebhookSignature } from "@knoxcall/sdk";
const ok = await verifyWebhookSignature({ rawBody, signature, secret });
```

## Error handling

All errors extend `KnoxCallError` and carry `.status`, `.code`, `.headers`, `.body`, and `.requestId` (the server's `X-Request-Id` — quote it when contacting support):

```ts
import { RateLimitError, ValidationError, AuthenticationError } from "@knoxcall/sdk";

try {
  await client.routes.create({ name: "x", target_base_url: "https://y" });
} catch (e) {
  if (e instanceof RateLimitError) {
    await sleep((e.retryAfter ?? 1) * 1000);
    // retry
  } else if (e instanceof ValidationError) {
    console.error("Validation failed:", e.fields, e.requestId);
  } else if (e instanceof AuthenticationError) {
    console.error("Auth failed:", e.message);
  } else {
    throw e;
  }
}
```

Hierarchy: `APIConnectionError` / `APIConnectionTimeoutError` / `APIUserAbortError` (transport), `AuthenticationError` (401), `PermissionDeniedError` (403), `NotFoundError` (404), `ConflictError` (409), `ValidationError` (422, with `.fields`), `RateLimitError` (429, with `.retryAfter`), `ServerError` (5xx), plus `WebhookSignatureVerificationError`, `SignupError`, `BootstrapError`, and `NotAuthenticatedError` (a `BootstrapError` subclass — no credential detected; see [Log in from your code](#log-in-from-your-code)).

## Telemetry hooks

Observe every request/response/retry without monkey-patching:

```ts
const client = new KnoxCall({
  telemetry: {
    onRequest: (info) => span.start(info.method, info.url),
    onResponse: (info) => metrics.timing("knoxcall.request", info.durationMs, { status: info.status }),
    onRetry: (info) => log.warn(`retrying after ${info.delayMs}ms (status ${info.status})`),
  },
});
```

## Low-level Session

When you want raw fetch semantics:

```ts
import { Session } from "@knoxcall/sdk";

const session = new Session({ tenant: "acme" });
const res = await session.fetch("/v1/routes");
```

## Retries & idempotency

Automatic retry with exponential backoff + jitter on network errors and HTTP 408, 429, 500, 502, 503, 504 (never 409 — a real conflict does not resolve by replaying; `Retry-After` is honored on 429, capped at 30s). Mutating requests (POST/PUT/PATCH/DELETE) automatically include an `X-Idempotency-Key` (ULID) that stays stable across retries, so replays are safe; pass `{ idempotencyKey }` on any mutating resource method to supply your own.

```ts
new KnoxCall({
  tenant: "acme",
  retry: { maxAttempts: 5, baseDelayMs: 200, maxDelayMs: 10000 },
});
```

## Browser entrypoint

`@knoxcall/sdk/browser` is a separate, Node-free entrypoint for SPA use (currently the `BrowserDpopKeyPair` helper). Browser code can't safely hold a client secret — the recommended pattern is BFF: your backend holds the OAuth client and proxies API calls. For one-shot in-browser reveals of encrypted values or vault tokens, mint a capability token server-side with `client.crypto.mintClientToken()` and let the page redeem it — no API key ever ships to the browser.

## License

Apache-2.0
