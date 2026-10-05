// Account resource — tenant info, usage stats.

import type { APIClient } from "../core.js";
import { type Envelope, unwrap } from "./shared.js";

/** GET /v1/account response. */
export interface Account {
  id: string;
  slug: string;
  name: string;
  region: string;
  subscription_plan: string;
  subscription_status: string;
  trial_start_at: string | null;
  trial_end_at: string | null;
  subscription_current_period_start: string | null;
  subscription_current_period_end: string | null;
  subscription_cancel_at: string | null;
  created_at: string;
}

export interface UsageCounter {
  used: number;
  limit: number | null;
}

/** GET /v1/account/usage response. */
export interface AccountUsage {
  billing_period: { year: number; month: number; start: string | null; end: string | null };
  api_calls: { used: number; limit: number | null; percentage: number };
  resources: {
    routes: UsageCounter;
    secrets: UsageCounter;
    clients: UsageCounter;
    environments: { used: number; limit: null };
  };
  plan: string;
  status: string;
}

export class AccountResource {
  constructor(private readonly client: APIClient) {}

  async get(): Promise<Account> {
    return unwrap(await this.client.request<Envelope<Account>>({
      method: "GET", path: "/v1/account",
    }));
  }

  async getUsage(): Promise<AccountUsage> {
    return unwrap(await this.client.request<Envelope<AccountUsage>>({
      method: "GET", path: "/v1/account/usage",
    }));
  }
}
