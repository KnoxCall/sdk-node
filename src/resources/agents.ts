// Agents resource — secret-store agent registrations.

import type { APIClient } from "../core.js";
import { type Envelope, unwrap } from "./shared.js";

/** Row returned by GET /v1/agents (bare array — no pagination). */
export interface Agent {
  id: string;
  name: string;
  agent_id: string;
  status: "active" | "revoked";
  require_verified_build: boolean;
  last_seen_at: string | null;
  last_session_issued_at: string | null;
  created_at: string;
  has_tamper_events: boolean;
}

/** POST /v1/agents response — `agent_secret` is returned ONCE. */
export interface CreateAgentResponse {
  id: string;
  name: string;
  agent_id: string;
  status: "active" | "revoked";
  require_verified_build: boolean;
  created_at: string;
  /** Plaintext agent secret — only ever present in this response. */
  agent_secret: string;
}

/** Row returned by GET /v1/agents/:id/tamper-events (bare array, most recent 50). */
export interface AgentTamperEvent {
  id: string;
  version_reported: string | null;
  build_sig_reported: string | null;
  src_ip: string | null;
  action_taken: string | null;
  detected_at: string;
}

export class AgentsResource {
  constructor(private readonly client: APIClient) {}

  async list(): Promise<Agent[]> {
    return unwrap(await this.client.request<Envelope<Agent[]>>({
      method: "GET", path: "/v1/agents",
    }));
  }

  /**
   * ``agent_secret`` is returned once — save it immediately.
   *
   * Requires an explicit `agent:create` policy grant: a wildcard (`*:*`) rule
   * does not satisfy it, including the `legacy_admin` policy every key created
   * before 2026-06-30 still carries. The seeded Key - Infrastructure and Key -
   * Editor roles name the action literally and are unaffected. Without it the
   * call returns 403. Every successful mint also emails the account's owners.
   */
  async create(input: { name: string }, opts?: { idempotencyKey?: string }): Promise<CreateAgentResponse> {
    return unwrap(await this.client.request<Envelope<CreateAgentResponse>>({
      method: "POST", path: "/v1/agents", body: input, idempotencyKey: opts?.idempotencyKey,
    }));
  }

  async revoke(id: string, opts?: { idempotencyKey?: string }): Promise<{ revoked: true }> {
    return unwrap(await this.client.request<Envelope<{ revoked: true }>>({
      method: "DELETE",
      path: `/v1/agents/${encodeURIComponent(id)}`,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  async getTamperEvents(id: string): Promise<AgentTamperEvent[]> {
    return unwrap(await this.client.request<Envelope<AgentTamperEvent[]>>({
      method: "GET", path: `/v1/agents/${encodeURIComponent(id)}/tamper-events`,
    }));
  }
}
