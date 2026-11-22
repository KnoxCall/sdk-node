// Workflows resource — mirrors src/client-api/workflows.ts

import type { APIClient } from "../core.js";
import { type Envelope, type Page, type PageParams, iteratePages, unwrap } from "./shared.js";

/** Row returned by GET /v1/workflows. */
export interface Workflow {
  id: string;
  name: string;
  description: string | null;
  definition: unknown;
  environment: string | null;
  enabled: boolean;
  version: number;
  sandbox: boolean;
  timeout_seconds: number | null;
  published_at: string | null;
  created_at: string;
  updated_at: string;
  run_count?: number;
}

/** A workflow execution (run). */
export interface WorkflowExecution {
  id: string;
  workflow_id: string;
  status: string;
  trigger_type: string;
  started_at: string | null;
  completed_at: string | null;
  execution_time_ms: number | null;
  error_message: string | null;
  workflow_version: number | null;
  created_at: string;
  node_executions?: unknown[];
}

/** The queued-execution acknowledgement returned by execute(). */
export interface WorkflowRun {
  id: string;
  workflow_id: string;
  status: string;
}

export interface CreateWorkflowInput {
  name: string;
  definition: unknown;
  description?: string;
  trigger_config?: unknown;
  environment?: string;
  enabled?: boolean;
}

export type UpdateWorkflowInput = Partial<CreateWorkflowInput>;

export class WorkflowsResource {
  constructor(private readonly client: APIClient) {}

  /** List workflows (paginated). */
  async list(params?: PageParams): Promise<Page<Workflow>> {
    return this.client.request<Page<Workflow>>({
      method: "GET",
      path: "/v1/workflows",
      query: params as Record<string, string | number | undefined>,
    });
  }

  /** Iterate every workflow across all pages. */
  iterate(params?: PageParams): AsyncIterableIterator<Workflow> {
    return iteratePages((page) => this.list({ ...params, page }), params?.page ?? 1);
  }

  /** Fetch one workflow by id. */
  async get(id: string): Promise<Workflow> {
    return unwrap(
      await this.client.request<Envelope<Workflow>>({
        method: "GET",
        path: `/v1/workflows/${encodeURIComponent(id)}`,
      }),
    );
  }

  /** Create a workflow. */
  async create(input: CreateWorkflowInput, opts?: { idempotencyKey?: string }): Promise<Workflow> {
    return unwrap(
      await this.client.request<Envelope<Workflow>>({
        method: "POST",
        path: "/v1/workflows",
        body: input,
        idempotencyKey: opts?.idempotencyKey,
      }),
    );
  }

  /** Update a workflow. */
  async update(id: string, input: UpdateWorkflowInput, opts?: { idempotencyKey?: string }): Promise<Workflow> {
    return unwrap(
      await this.client.request<Envelope<Workflow>>({
        method: "PATCH",
        path: `/v1/workflows/${encodeURIComponent(id)}`,
        body: input,
        idempotencyKey: opts?.idempotencyKey,
      }),
    );
  }

  /** Delete a workflow. */
  async delete(id: string): Promise<{ id: string; deleted: true }> {
    return unwrap(
      await this.client.request<Envelope<{ id: string; deleted: true }>>({
        method: "DELETE",
        path: `/v1/workflows/${encodeURIComponent(id)}`,
      }),
    );
  }

  /**
   * Execute a workflow. Queues a run and returns the execution ack. Idempotent:
   * an auto-generated key (stable across retries) or an explicit idempotencyKey
   * makes a replay return the same execution.
   */
  async execute(id: string, input?: unknown, opts?: { idempotencyKey?: string }): Promise<WorkflowRun> {
    return unwrap(
      await this.client.request<Envelope<WorkflowRun>>({
        method: "POST",
        path: `/v1/workflows/${encodeURIComponent(id)}/execute`,
        body: { input },
        idempotencyKey: opts?.idempotencyKey,
      }),
    );
  }

  /** List a workflow's executions (paginated) — polling-trigger source. */
  async listExecutions(id: string, params?: PageParams): Promise<Page<WorkflowExecution>> {
    return this.client.request<Page<WorkflowExecution>>({
      method: "GET",
      path: `/v1/workflows/${encodeURIComponent(id)}/executions`,
      query: params as Record<string, string | number | undefined>,
    });
  }

  /** Iterate a workflow's executions across all pages. */
  iterateExecutions(id: string, params?: PageParams): AsyncIterableIterator<WorkflowExecution> {
    return iteratePages((page) => this.listExecutions(id, { ...params, page }), params?.page ?? 1);
  }

  /** Fetch one execution (with composed step details). */
  async getExecution(executionId: string): Promise<WorkflowExecution> {
    return unwrap(
      await this.client.request<Envelope<WorkflowExecution>>({
        method: "GET",
        path: `/v1/workflows/executions/${encodeURIComponent(executionId)}`,
      }),
    );
  }

  /** Cancel a running execution. */
  async cancelExecution(executionId: string): Promise<{ id: string; status: string }> {
    return unwrap(
      await this.client.request<Envelope<{ id: string; status: string }>>({
        method: "POST",
        path: `/v1/workflows/executions/${encodeURIComponent(executionId)}/cancel`,
      }),
    );
  }
}
