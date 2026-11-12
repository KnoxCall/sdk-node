// Top-level KnoxCall client.
//
//   const client = new KnoxCall({ tenant: "acme" });
//   await client.routes.list();
//   const resp = await client.call("3f1e2c9a-...", { path: "/v1/orders" });

import { APIClient, type KnoxCallOptions } from "./core.js";
import { AccountResource } from "./resources/account.js";
import { AgentsResource } from "./resources/agents.js";
import { AIGatewayResource } from "./resources/ai-gateway.js";
import { ApiKeysResource, RolesResource } from "./resources/api-keys.js";
import { AuditLogsResource } from "./resources/audit-logs.js";
import { LogsResource } from "./resources/logs.js";
import { ClientsResource } from "./resources/clients.js";
import { CryptoResource } from "./resources/crypto.js";
import { DynamicDbResource } from "./resources/dynamic-db.js";
import { EnvironmentsResource } from "./resources/environments.js";
import { OAuthClientsResource } from "./resources/oauth-clients.js";
import { PkiResource } from "./resources/pki.js";
import { RoutesResource } from "./resources/routes.js";
import { SecretsResource } from "./resources/secrets.js";
import { VaultsResource } from "./resources/vaults.js";
import { WebhooksResource } from "./resources/webhooks.js";
import { WorkflowsResource } from "./resources/workflows.js";
import { WrapResource } from "./resources/wrap.js";
import { OpportunitiesResource } from "./resources/opportunities.js";

export class KnoxCall extends APIClient {
  readonly routes: RoutesResource;
  readonly secrets: SecretsResource;
  readonly webhooks: WebhooksResource;
  readonly workflows: WorkflowsResource;
  readonly clients: ClientsResource;
  readonly oauthClients: OAuthClientsResource;
  readonly environments: EnvironmentsResource;
  readonly apiKeys: ApiKeysResource;
  readonly roles: RolesResource;
  readonly account: AccountResource;
  readonly auditLogs: AuditLogsResource;
  /** Per-call proxy request log + Merkle inclusion proofs. Not the change log — that is `auditLogs`. */
  readonly logs: LogsResource;
  readonly agents: AgentsResource;
  readonly crypto: CryptoResource;
  readonly pki: PkiResource;
  readonly vaults: VaultsResource;
  readonly dynamicDb: DynamicDbResource;
  readonly aiGateway: AIGatewayResource;
  readonly wrap: WrapResource;
  readonly opportunities: OpportunitiesResource;

  constructor(opts: KnoxCallOptions = {}) {
    super(opts);
    this.routes = new RoutesResource(this);
    this.secrets = new SecretsResource(this);
    this.webhooks = new WebhooksResource(this);
    this.workflows = new WorkflowsResource(this);
    this.clients = new ClientsResource(this);
    this.oauthClients = new OAuthClientsResource(this);
    this.environments = new EnvironmentsResource(this);
    this.apiKeys = new ApiKeysResource(this);
    this.roles = new RolesResource(this);
    this.account = new AccountResource(this);
    this.auditLogs = new AuditLogsResource(this);
    this.logs = new LogsResource(this);
    this.agents = new AgentsResource(this);
    this.crypto = new CryptoResource(this);
    this.pki = new PkiResource(this);
    this.vaults = new VaultsResource(this);
    this.dynamicDb = new DynamicDbResource(this);
    this.aiGateway = new AIGatewayResource(this);
    this.wrap = new WrapResource(this);
    this.opportunities = new OpportunitiesResource(this);
  }
}

/**
 * Low-level fetch-compatible session for users who want raw HTTP control.
 *
 *   const session = new Session({ tenant: "acme" });
 *   const res = await session.fetch("/v1/routes");
 */
export class Session extends APIClient {
  async fetch(path: string, init?: RequestInit): Promise<Response> {
    const method = init?.method ?? "GET";
    const headers = headersToRecord(init?.headers);
    const result = await this.request<unknown>({
      method,
      path,
      headers,
      body: init?.body && typeof init.body === "string" ? JSON.parse(init.body) : undefined,
      signal: init?.signal ?? undefined,
    });
    return new Response(JSON.stringify(result), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }
}

function headersToRecord(h?: HeadersInit): Record<string, string> {
  if (!h) return {};
  if (h instanceof Headers) {
    const out: Record<string, string> = {};
    h.forEach((v, k) => { out[k] = v; });
    return out;
  }
  if (Array.isArray(h)) return Object.fromEntries(h);
  return h as Record<string, string>;
}
