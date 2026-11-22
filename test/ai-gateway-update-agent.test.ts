// The Node typed patch must send every field a caller sets — and only those.
//
// Node was the surface with no runtime coverage when `UpdateAgentInput` was
// rewritten from `Partial<CreateAgentInput>` to an explicit interface, while Go
// and Python each had a test asserting the exact PATCH body. A source-level
// name scan (tests/coverage/ai-gateway-sdk-typed-patch-parity.test.ts) is
// erased at runtime and checks names, not serialisation — so nothing proved the
// interface change actually reaches the wire.
//
// What this file does NOT do: prove the interface REFUSES a field (e.g.
// `status`, which the server drops because pause/resume own the lifecycle).
// A type-level refusal is erased before runtime and any test of it needs a
// cast, which compiles whatever the interface says. That claim belongs to the
// coverage guard, which reads the interface itself.
//
// Deriving the patch from the CREATE input was wrong in both directions: it
// offered `provider`, `upstream_secret_id` and `upstream` (create-only, which
// PATCH silently ignores) and omitted 23 fields the server accepts.
import { describe, it, expect } from 'vitest';
import { KnoxCall } from '../src/index.js';
import type { UpdateAgentInput } from '../src/resources/ai-gateway.js';

function makeClient(onPatch: (body: unknown) => void) {
  const fetchImpl = (async (url: string | URL | Request, init?: RequestInit) => {
    if (init?.method === 'PATCH') onPatch(JSON.parse(String(init.body)));
    return new Response(
      JSON.stringify({ data: { id: 'ag_1', slug: 'digest' }, meta: { request_id: 'req_1' } }),
      { status: 200, headers: { 'Content-Type': 'application/json' } },
    );
  }) as unknown as typeof fetch;
  return new KnoxCall({
    tenant: 'acme',
    baseUrl: 'https://api.test',
    bootstrap: { type: 'access_token', accessToken: 'kc_live_x' },
    fetchImpl,
  });
}

describe('aiGateway.updateAgent — the typed patch on the wire', () => {
  it('sends exactly the fields that were set, and nothing else', async () => {
    let body: Record<string, unknown> = {};
    const client = makeClient((b) => { body = b as Record<string, unknown>; });

    await client.aiGateway.updateAgent('ag_1', { slug: 'digest', tags: { team: 'core' } });

    // Not "contains": a patch that names a column SETS it, so an extra key is a
    // setting the caller never asked for.
    expect(body).toEqual({ slug: 'digest', tags: { team: 'core' } });
  });

  it('carries the whole writable surface, including what the old Partial<CreateAgentInput> omitted', async () => {
    let body: Record<string, unknown> = {};
    const client = makeClient((b) => { body = b as Record<string, unknown>; });

    const patch: UpdateAgentInput = {
      name: 'Digest',
      slug: 'digest',
      fallback_route_ids: ['c0ffee00-1111-4a2b-8c3d-000000000002'],
      model_rewrite: { fast: 'claude-haiku-4-5' },
      budget_per_call_max_tokens: 8192,
      budget_overage_action: 'fallback',
      fallback_agent_id: 'c0ffee00-3333-4a2b-8c3d-000000000003',
      pii_streaming_holdback_chars: 64,
      pii_streaming_mode: 'holdback',
      tags: { cost_center: 'research' },
      cache_mode: 'semantic',
      cache_ttl_seconds: 300,
      cache_similarity_threshold: 0.92,
      cache_embedding_model: 'text-embedding-3-small',
      output_schema: { type: 'object' },
      output_validation_action: 'retry',
      // `eu`, not a cloud region id: RESIDENCY_REGIONS is us|eu|uk|ca|au|jp|in
      // and anything else is a 400. A mock transport would have accepted the
      // wrong value silently, and these tests double as usage documentation.
      data_residency_region: 'eu',
      cmek_key_id: 'c0ffee00-6666-4a2b-8c3d-000000000006',
      routing_policy: { max_attempts: 3 },
      guardrail_webhook_mode: 'both',
    };
    await client.aiGateway.updateAgent('ag_1', patch);

    expect(body).toEqual(patch as unknown as Record<string, unknown>);
  });

});
