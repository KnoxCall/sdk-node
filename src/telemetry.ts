// Telemetry hooks — opt-in observability for users + Stripe-style
// next-request telemetry that piggybacks on the *next* HTTP call (so
// per-request observability adds zero latency).

export interface TelemetryRequestInfo {
  method: string;
  url: string;
  attempt: number;
  idempotencyKey?: string;
  /** Undefined until tenant auto-discovery has run on tenant-less clients. */
  tenantId?: string;
}

export interface TelemetryResponseInfo extends TelemetryRequestInfo {
  status: number;
  durationMs: number;
  requestId?: string;
}

export interface TelemetryRetryInfo extends TelemetryRequestInfo {
  status?: number;
  delayMs: number;
  reason: string;
}

export interface TelemetryHooks {
  onRequest?: (info: TelemetryRequestInfo) => void;
  onResponse?: (info: TelemetryResponseInfo) => void;
  onRetry?: (info: TelemetryRetryInfo) => void;
}

/**
 * Stripe-style next-request telemetry buffer. Each call captures timing
 * + status from request N and packs it into the `X-KnoxCall-Telemetry`
 * header of request N+1, so per-request observability adds zero latency.
 */
export class TelemetryBuffer {
  #lastResponseHeader: string | null = null;

  record(info: { method: string; path: string; status: number; durationMs: number }): void {
    // Compact form to fit comfortably in a header. Server can extract
    // p50/p99 latencies + status distribution per endpoint.
    this.#lastResponseHeader = JSON.stringify({
      lr: {
        m: info.method,
        p: info.path,
        s: info.status,
        d: Math.round(info.durationMs),
      },
    });
  }

  /** Pop the buffered payload for inclusion on the next request. */
  drain(): string | null {
    const h = this.#lastResponseHeader;
    this.#lastResponseHeader = null;
    return h;
  }
}
