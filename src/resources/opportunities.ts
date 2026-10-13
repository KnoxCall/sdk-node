// Opportunities resource — mirrors src/client-api/opportunities.ts (PR5).
//
// Promotion opportunities: "we detected outbound API usage → create a route",
// from two sources (agent_monitor + gateway_traffic). List refreshes gateway
// detection on read; accept promotes a suggestion to a durable route + secret.

import type { APIClient } from "../core.js";
import { type Page, type PageParams, type Envelope, unwrap } from "./shared.js";

export type OpportunitySource = "agent_monitor" | "gateway_traffic";
export type OpportunityStatus = "pending" | "snoozed" | "onboarded" | "dismissed";

export interface Opportunity {
  id: string;
  source: OpportunitySource;
  service: string;
  destination_host: string | null;
  status: OpportunityStatus;
  confidence: number | null;
  suggested_route_json: Record<string, unknown> | null;
  evidence_json: Record<string, unknown> | null;
  accepted_route_id: string | null;
  created_at: string;
  updated_at: string;
  acted_at: string | null;
}

export interface AcceptOpportunityInput {
  /** Collection to file the route under (else the suggestion's, else "Wrapped APIs"). */
  collection_name?: string;
  /** Environment the route config is written into (else the tenant default). */
  environment?: string;
  /** Secret name/id to bind (else an escrowed wrap credential for the host is auto-bound). */
  secret?: string;
  /** Injected header name (default Authorization) + value prefix (default "Bearer "). */
  header_name?: string;
  value_prefix?: string;
}

export interface AcceptOpportunityResponse {
  opportunity_id: string;
  route: { id: string; slug: string | null; name: string };
  collection_id: string;
  environment: string;
}

export interface ListOpportunitiesParams extends PageParams {
  status?: OpportunityStatus;
}

export class OpportunitiesResource {
  constructor(private readonly client: APIClient) {}

  /** List promotion opportunities (refreshes gateway detection on read). */
  async list(params?: ListOpportunitiesParams): Promise<Page<Opportunity>> {
    return this.client.request<Page<Opportunity>>({
      method: "GET",
      path: "/v1/opportunities",
      query: params as Record<string, string | number | undefined> | undefined,
    });
  }

  /** Promote a gateway suggestion to a durable route + secret binding. */
  async accept(id: string, input: AcceptOpportunityInput = {}, opts?: { idempotencyKey?: string }): Promise<AcceptOpportunityResponse> {
    return unwrap(await this.client.request<Envelope<AcceptOpportunityResponse>>({
      method: "POST",
      path: `/v1/opportunities/${encodeURIComponent(id)}/accept`,
      body: input,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  /** Dismiss a pending suggestion. */
  async dismiss(id: string): Promise<{ opportunity_id: string; status: "dismissed" }> {
    return unwrap(await this.client.request<Envelope<{ opportunity_id: string; status: "dismissed" }>>({
      method: "POST",
      path: `/v1/opportunities/${encodeURIComponent(id)}/dismiss`,
    }));
  }
}
