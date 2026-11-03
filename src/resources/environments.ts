// Environments resource — mirrors src/client-api/environments.ts

import type { APIClient } from "../core.js";
import { type Envelope, unwrap } from "./shared.js";

/** Row returned by GET /v1/environments (bare array — no pagination). */
export interface Environment {
  id: string;
  name: string;
  display_name: string;
  description: string | null;
  color: string;
  is_default: boolean;
  created_at: string;
}

/** Full row returned by POST /v1/environments and PATCH /v1/environments/:id. */
export interface EnvironmentRecord extends Environment {
  tenant_id: string;
  sandbox: boolean;
}

export class EnvironmentsResource {
  constructor(private readonly client: APIClient) {}

  async list(): Promise<Environment[]> {
    return unwrap(await this.client.request<Envelope<Environment[]>>({
      method: "GET", path: "/v1/environments",
    }));
  }

  async create(
    input: { name: string; display_name?: string; description?: string; color?: string; is_default?: boolean },
    opts?: { idempotencyKey?: string },
  ): Promise<EnvironmentRecord> {
    return unwrap(await this.client.request<Envelope<EnvironmentRecord>>({
      method: "POST", path: "/v1/environments", body: input, idempotencyKey: opts?.idempotencyKey,
    }));
  }

  async update(
    id: string,
    input: { name?: string; display_name?: string; description?: string; color?: string; is_default?: boolean },
    opts?: { idempotencyKey?: string },
  ): Promise<EnvironmentRecord> {
    return unwrap(await this.client.request<Envelope<EnvironmentRecord>>({
      method: "PATCH",
      path: `/v1/environments/${encodeURIComponent(id)}`,
      body: input,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }

  async delete(id: string, opts?: { idempotencyKey?: string }): Promise<{ deleted: true }> {
    return unwrap(await this.client.request<Envelope<{ deleted: true }>>({
      method: "DELETE",
      path: `/v1/environments/${encodeURIComponent(id)}`,
      idempotencyKey: opts?.idempotencyKey,
    }));
  }
}
