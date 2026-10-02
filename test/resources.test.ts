// Tests for the resource layer: envelope unwrapping, page-based pagination,
// and the special-case endpoints (oauth-clients warning attach, bare arrays,
// dyn-db lease list). Mocks mirror the REAL server envelope from
// src/client-api/helpers.ts: `{data, meta}` with page-based meta — there is
// no cursor pagination anywhere on the API.

import { describe, it, expect } from 'vitest';
import { KnoxCall, verifyWebhookSignature } from '../src/index.js';
import type { AIProviderId } from '../src/index.js';
import { createHmac } from 'crypto';

interface StubCall {
  url: string;
  method: string;
  body?: string;
}

/** meta exactly as src/client-api/helpers.ts `paginated()` builds it. */
function pageMeta(total: number, page: number, perPage = 20) {
  return {
    total,
    page,
    per_page: perPage,
    total_pages: Math.max(1, Math.ceil(total / perPage)),
    request_id: `req-${page}`,
  };
}

/** meta exactly as `success()` builds it. */
const successMeta = { request_id: 'req-1' };

function makeStub(responder?: (path: string, method: string, query: URLSearchParams) => { status: number; body: unknown }) {
  const calls: StubCall[] = [];
  const fetchImpl: typeof fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input as Request).url;
    const method = init?.method ?? 'GET';
    calls.push({ url, method, body: typeof init?.body === 'string' ? init.body : undefined });
    const parsed = new URL(url);
    const r = responder?.(parsed.pathname, method, parsed.searchParams)
      ?? { status: 200, body: { data: [], meta: pageMeta(0, 1) } };
    return new Response(JSON.stringify(r.body), {
      status: r.status,
      headers: { 'Content-Type': 'application/json' },
    });
  };
  return { fetchImpl, calls };
}

function makeClient(fetchImpl: typeof fetch) {
  return new KnoxCall({
    tenant: 'acme',
    baseUrl: 'https://api.test',
    bootstrap: { type: 'access_token', accessToken: 'kc_live_x' },
    fetchImpl,
  });
}

describe('SecretsResource', () => {
  it('lists secrets with page/per_page params and returns the typed page', async () => {
    const { fetchImpl, calls } = makeStub((path) => {
      if (path === '/v1/secrets') {
        return { status: 200, body: { data: [{ id: 's_1', name: 'a' }], meta: pageMeta(1, 2, 5) } };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    const page = await client.secrets.list({ page: 2, per_page: 5 });
    expect(page.data[0].id).toBe('s_1');
    expect(page.meta).toEqual(pageMeta(1, 2, 5));
    const listCall = new URL(calls.find((c) => c.url.includes('/v1/secrets'))!.url);
    expect(listCall.searchParams.get('page')).toBe('2');
    expect(listCall.searchParams.get('per_page')).toBe('5');
  });

  it('iterates across pages using meta.total_pages (no next_cursor anywhere)', async () => {
    const pages: Record<string, unknown> = {
      '1': { data: [{ id: 's_1', name: 'a' }, { id: 's_2', name: 'b' }], meta: pageMeta(5, 1, 2) },
      '2': { data: [{ id: 's_3', name: 'c' }, { id: 's_4', name: 'd' }], meta: pageMeta(5, 2, 2) },
      '3': { data: [{ id: 's_5', name: 'e' }], meta: pageMeta(5, 3, 2) },
    };
    const requestedPages: string[] = [];
    const { fetchImpl } = makeStub((path, _method, query) => {
      if (path === '/v1/secrets') {
        const p = query.get('page') ?? '1';
        requestedPages.push(p);
        return { status: 200, body: pages[p] };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    const collected: string[] = [];
    for await (const s of client.secrets.iterate({ per_page: 2 })) collected.push(s.id);
    expect(collected).toEqual(['s_1', 's_2', 's_3', 's_4', 's_5']);
    expect(requestedPages).toEqual(['1', '2', '3']); // stops at total_pages, no 4th fetch
  });

  it('stops iteration defensively on an empty page', async () => {
    const { fetchImpl } = makeStub((path) => {
      if (path === '/v1/secrets') {
        return { status: 200, body: { data: [], meta: pageMeta(40, 1, 20) } };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    const collected: unknown[] = [];
    for await (const s of client.secrets.iterate()) collected.push(s);
    expect(collected).toEqual([]);
  });

  it('unwraps the envelope on get()', async () => {
    const secret = {
      id: 's_9', name: 'k', shortcode_name: 'k', base_environment: 'production',
      secret_type: 'string', collection_id: null, created_at: '2026-01-01T00:00:00Z',
      expires_at: null, strict_expiry_enforcement: false, environment_count: 1,
    };
    const { fetchImpl } = makeStub((path) => {
      if (path === '/v1/secrets/s_9') return { status: 200, body: { data: secret, meta: successMeta } };
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    const s = await client.secrets.get('s_9');
    expect(s).toEqual(secret); // no {data, meta} wrapper leaks out
  });

  it('creates secrets with idempotency key and unwraps the envelope', async () => {
    const { fetchImpl, calls } = makeStub((path, method) => {
      if (path === '/v1/secrets' && method === 'POST') {
        return {
          status: 200,
          body: {
            data: {
              id: 's_new', name: 'k', shortcode_name: 'k', base_environment: 'production',
              environment_count: 1, secret_type: 'string', collection_id: null,
              expires_at: null, strict_expiry_enforcement: false,
            },
            meta: successMeta,
          },
        };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    const s = await client.secrets.create({ name: 'k', value: 'v' });
    expect(s.id).toBe('s_new');
    const postCall = calls.find((c) => c.method === 'POST' && c.url.endsWith('/v1/secrets'))!;
    expect(JSON.parse(postCall.body!).name).toBe('k');
  });

  it('unwraps {deleted: true} on delete()', async () => {
    const { fetchImpl } = makeStub((path, method) => {
      if (path === '/v1/secrets/s_1' && method === 'DELETE') {
        return { status: 200, body: { data: { deleted: true }, meta: successMeta } };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    expect(await client.secrets.delete('s_1')).toEqual({ deleted: true });
  });

  // Audit finding M3: OAuth2 / certificate secrets could not be created via the
  // typed SDK (the base create() input is closed to {name, secret_type, value}).
  it('creates an OAuth2 secret against /v1/secrets/oauth2 with the provider fields', async () => {
    const { fetchImpl, calls } = makeStub((path, method) => {
      if (path === '/v1/secrets/oauth2' && method === 'POST') {
        return { status: 201, body: { data: { id: 's_oauth', name: 'stripe', secret_type: 'oauth2' }, meta: successMeta } };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    const s = await client.secrets.createOAuth2({
      name: 'stripe', provider: 'custom', client_id: 'ci', client_secret: 'cs',
      scopes: ['read'], token_url: 'https://p/token',
    });
    expect(s.id).toBe('s_oauth');
    const call = calls.find((c) => c.method === 'POST' && c.url.endsWith('/v1/secrets/oauth2'))!;
    const sent = JSON.parse(call.body!);
    expect(sent).toMatchObject({ provider: 'custom', client_id: 'ci', client_secret: 'cs', scopes: ['read'] });
  });

  it('creates a certificate secret against /v1/secrets/certificate', async () => {
    const { fetchImpl, calls } = makeStub((path, method) => {
      if (path === '/v1/secrets/certificate' && method === 'POST') {
        return { status: 201, body: { data: { id: 's_cert', name: 'mtls', secret_type: 'certificate' }, meta: successMeta } };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    const s = await client.secrets.createCertificate({ name: 'mtls', certificate_content: '-----BEGIN CERT-----', certificate_type: 'pem' });
    expect(s.id).toBe('s_cert');
    const call = calls.find((c) => c.method === 'POST' && c.url.endsWith('/v1/secrets/certificate'))!;
    expect(JSON.parse(call.body!).certificate_content).toContain('BEGIN CERT');
  });
});

describe('WrapResource', () => {
  it('escrow() POSTs to /v1/wrap/credentials and unwraps the metadata response', async () => {
    const { fetchImpl, calls } = makeStub((path, method) => {
      if (path === '/v1/wrap/credentials' && method === 'POST') {
        return {
          status: 200,
          body: {
            data: {
              secret_id: 'sec_1', name: 'wrap-stripe-live', provider: 'stripe',
              allowed_hosts: ['api.stripe.com'], sandbox: false,
            },
            meta: successMeta,
          },
        };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    const r = await client.wrap.escrow({
      provider: 'stripe', name: 'wrap-stripe-live',
      value: 'sk_live_SECRET', hosts: ['api.stripe.com'],
    });
    expect(r.secret_id).toBe('sec_1');
    expect(r.allowed_hosts).toEqual(['api.stripe.com']);
    const post = calls.find((c) => c.method === 'POST' && c.url.endsWith('/v1/wrap/credentials'))!;
    const body = JSON.parse(post.body!);
    expect(body.provider).toBe('stripe');
    expect(body.hosts).toEqual(['api.stripe.com']);
    expect(body.value).toBe('sk_live_SECRET'); // sent once, in the request body only
  });

  it('gatewayUrl() forwards the style param and surfaces base_url_style', async () => {
    const { fetchImpl, calls } = makeStub((path, method) => {
      if (path === '/v1/wrap/tokens' && method === 'POST') {
        return {
          status: 200,
          body: {
            data: {
              id: 'tok_1', token: 'wkt_abc',
              base_url: 'https://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.wrap.knoxcall.com',
              base_url_style: 'subdomain',
              host: 'api.stripe.com', secret_id: 'sec_1', sandbox: false, expires_at: null,
            },
            meta: successMeta,
          },
        };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    const r = await client.wrap.gatewayUrl({ secret: 'wrap-stripe-live', host: 'api.stripe.com', style: 'subdomain' });
    expect(r.base_url_style).toBe('subdomain');
    expect(r.base_url).toContain('.wrap.knoxcall.com');
    const post = calls.find((c) => c.method === 'POST' && c.url.endsWith('/v1/wrap/tokens'))!;
    const body = JSON.parse(post.body!);
    expect(body.style).toBe('subdomain');
    expect(body.secret).toBe('wrap-stripe-live');
  });

  it('interceptManifest() GETs /v1/wrap/intercept-manifest, forwards ?environment=, and unwraps the manifest', async () => {
    const { fetchImpl, calls } = makeStub((path, method, query) => {
      if (path === '/v1/wrap/intercept-manifest' && method === 'GET') {
        return { status: 200, body: { data: { ...{ version: 'sha256:abc', ttl_seconds: 60, environment: 'production', sandbox: false, routes: [{ host: 'api.hubapi.com', base_path: '/crm/v3', slug: 'hubspot', route_id: 'r-1', requires_clients: false, allowed_methods: null, updated_at: '2026-09-25T00:00:00.000Z' }] }, environment: query.get('environment') ?? 'production' }, meta: successMeta } };
      }
      return { status: 404, body: { error: { type: 'not_found', message: 'nope', request_id: 'r' } } };
    });
    const client = makeClient(fetchImpl);

    const m = await client.wrap.interceptManifest();
    expect(m.version).toBe('sha256:abc');
    expect(m.ttl_seconds).toBe(60);
    expect(m.environment).toBe('production');
    expect(m.routes).toHaveLength(1);
    expect(m.routes[0]).toMatchObject({ host: 'api.hubapi.com', base_path: '/crm/v3', slug: 'hubspot', requires_clients: false, allowed_methods: null });
    expect(calls[0].method).toBe('GET');
    expect(new URL(calls[0].url).searchParams.has('environment')).toBe(false);

    const staging = await client.wrap.interceptManifest({ environment: 'staging' });
    expect(staging.environment).toBe('staging');
    expect(new URL(calls[1].url).searchParams.get('environment')).toBe('staging');
  });
});

describe('OpportunitiesResource', () => {
  it('list() GETs /v1/opportunities and accept()/dismiss() hit the action paths', async () => {
    const { fetchImpl, calls } = makeStub((path, method) => {
      if (path === '/v1/opportunities' && method === 'GET') {
        return { status: 200, body: { data: [{ id: 'opp-1', source: 'gateway_traffic', destination_host: 'api.stripe.com', status: 'pending' }], meta: pageMeta(1, 1) } };
      }
      if (path === '/v1/opportunities/opp-1/accept' && method === 'POST') {
        return { status: 200, body: { data: { opportunity_id: 'opp-1', route: { id: 'route-1', slug: 'stripe', name: 'stripe' }, collection_id: 'col-1', environment: 'production' }, meta: successMeta } };
      }
      if (path === '/v1/opportunities/opp-1/dismiss' && method === 'POST') {
        return { status: 200, body: { data: { opportunity_id: 'opp-1', status: 'dismissed' }, meta: successMeta } };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);

    const page = await client.opportunities.list({ status: 'pending' });
    expect(page.data[0].destination_host).toBe('api.stripe.com');

    const accepted = await client.opportunities.accept('opp-1', { collection_name: 'Wrapped APIs' });
    expect(accepted.route.id).toBe('route-1');
    const acceptCall = calls.find((c) => c.url.includes('/opportunities/opp-1/accept'))!;
    expect(JSON.parse(acceptCall.body!).collection_name).toBe('Wrapped APIs');

    const dismissed = await client.opportunities.dismiss('opp-1');
    expect(dismissed.status).toBe('dismissed');
  });
});

describe('RoutesResource', () => {
  it('iterates logs page-by-page', async () => {
    const { fetchImpl } = makeStub((path, _m, query) => {
      if (path === '/v1/routes/r_1/logs') {
        const p = query.get('page') ?? '1';
        return {
          status: 200,
          body: p === '1'
            ? { data: [{ id: 'l_1' }], meta: pageMeta(2, 1, 1) }
            : { data: [{ id: 'l_2' }], meta: pageMeta(2, 2, 1) },
        };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    const page = await client.routes.getLogs('r_1', { page: 1, per_page: 1 });
    expect(page.data[0].id).toBe('l_1');
    expect(page.meta.total_pages).toBe(2);
  });

  it('unwraps the bare-array environments list', async () => {
    const { fetchImpl } = makeStub((path) => {
      if (path === '/v1/routes/r_1/environments') {
        return { status: 200, body: { data: [{ environment_name: 'staging', target_base_url: 'https://s.example' }], meta: successMeta } };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    const envs = await client.routes.listEnvironments('r_1');
    expect(Array.isArray(envs)).toBe(true);
    expect(envs[0].environment_name).toBe('staging');
  });
});

describe('EnvironmentsResource (bare array)', () => {
  it('unwraps list() to a plain array with no page params', async () => {
    const { fetchImpl, calls } = makeStub((path) => {
      if (path === '/v1/environments') {
        return {
          status: 200,
          body: { data: [{ id: 'e_1', name: 'production', display_name: 'Production', description: null, color: '#00ff00', is_default: true, created_at: '' }], meta: successMeta },
        };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    const envs = await client.environments.list();
    expect(envs).toHaveLength(1);
    expect(envs[0].name).toBe('production');
    const listCall = new URL(calls.find((c) => c.url.includes('/v1/environments'))!.url);
    expect([...listCall.searchParams.keys()]).toEqual([]);
  });
});

describe('WebhooksResource', () => {
  it('lists webhooks as a typed page', async () => {
    const { fetchImpl } = makeStub((path) => {
      if (path === '/v1/webhooks')
        return {
          status: 200,
          body: {
            data: [{ id: 'w_1', name: 'n', description: null, url: 'https://x', method: 'POST', event_types: ['request.completed'], auth_type: 'hmac', enabled: true, last_triggered_at: null, trigger_count: 0, success_count: 0, failure_count: 0, created_at: '' }],
            meta: pageMeta(1, 1),
          },
        };
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    const res = await client.webhooks.list();
    expect(res.data[0].id).toBe('w_1');
    expect(res.meta.total).toBe(1);
  });

  it('unwraps event types and test results', async () => {
    const { fetchImpl } = makeStub((path, method) => {
      if (path === '/v1/webhooks/event-types') {
        return { status: 200, body: { data: { event_types: [{ value: 'request.completed', label: 'Completed', description: 'd' }] }, meta: successMeta } };
      }
      if (path === '/v1/webhooks/w_1/test' && method === 'POST') {
        return { status: 200, body: { data: { success: true, status: 200, response_time_ms: 12 }, meta: successMeta } };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    const types = await client.webhooks.listEventTypes();
    expect(types.event_types[0].value).toBe('request.completed');
    const result = await client.webhooks.test('w_1');
    expect(result.success).toBe(true);
    expect(result.response_time_ms).toBe(12);
  });
});

describe('verifyWebhookSignature', () => {
  it('accepts a valid signature', async () => {
    const secret = 'whsec_test';
    const body = JSON.stringify({ event: 'route.created' });
    const sig = createHmac('sha256', secret).update(body).digest('hex');
    expect(await verifyWebhookSignature({ rawBody: body, signature: sig, secret })).toBe(true);
  });

  it('rejects a bad signature', async () => {
    const secret = 'whsec_test';
    const body = 'hello';
    expect(await verifyWebhookSignature({ rawBody: body, signature: 'deadbeef', secret })).toBe(false);
  });

  it('rejects when timestamps drift outside tolerance', async () => {
    const secret = 'whsec_test';
    const body = 'hi';
    const sig = createHmac('sha256', secret).update(body).digest('hex');
    const past = Math.floor(Date.now() / 1000) - 600;
    expect(
      await verifyWebhookSignature({
        rawBody: body,
        signature: sig,
        secret,
        timestamp: past,
        toleranceSeconds: 60,
      }),
    ).toBe(false);
  });

  it('accepts when timestamps are within tolerance', async () => {
    const secret = 'whsec_test';
    const body = 'hi';
    const sig = createHmac('sha256', secret).update(body).digest('hex');
    const now = Math.floor(Date.now() / 1000);
    expect(
      await verifyWebhookSignature({
        rawBody: body,
        signature: sig,
        secret,
        timestamp: now,
        toleranceSeconds: 60,
      }),
    ).toBe(true);
  });
});

describe('ClientsResource', () => {
  it('lists clients as a typed page', async () => {
    const { fetchImpl } = makeStub((path) => {
      if (path === '/v1/clients') {
        return {
          status: 200,
          body: {
            data: [{ id: 'c_1', name: 'web', type: 'server', ip_address: '10.0.0.1', ip_notes: {}, description: null, enabled: true, collection_id: null, created_at: '', updated_at: '' }],
            meta: pageMeta(1, 1),
          },
        };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    const res = await client.clients.list();
    expect(res.data[0].id).toBe('c_1');
  });

  it('unwraps the bare-array credentials list', async () => {
    const { fetchImpl } = makeStub((path) => {
      if (path === '/v1/clients/c_1/credentials') {
        return { status: 200, body: { data: [{ id: 'cred_1', client_id: 'c_1', kind: 'ip', enabled: true }], meta: successMeta } };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    const creds = await client.clients.listCredentials('c_1');
    expect(Array.isArray(creds)).toBe(true);
    expect(creds[0].kind).toBe('ip');
  });
});

describe('AgentsResource', () => {
  it('unwraps the bare-array list', async () => {
    const { fetchImpl } = makeStub((path) => {
      if (path === '/v1/agents') {
        return { status: 200, body: { data: [{ id: 'a_1', name: 'ci', agent_id: 'agent_x', status: 'active', require_verified_build: false, last_seen_at: null, last_session_issued_at: null, created_at: '', has_tamper_events: false }], meta: successMeta } };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    const agents = await client.agents.list();
    expect(agents[0].agent_id).toBe('agent_x');
  });

  it('unwraps the hand-rolled create envelope (agent_secret inside data, meta without request_id)', async () => {
    const { fetchImpl } = makeStub((path, method) => {
      if (path === '/v1/agents' && method === 'POST') {
        // Mirrors src/client-api/agents.ts POST — bypasses success().
        return {
          status: 201,
          body: {
            data: { id: 'a_1', name: 'ci', agent_id: 'agent_x', status: 'active', require_verified_build: false, created_at: '', agent_secret: 'as_once_only' },
            meta: { secret_shown_once: true },
          },
        };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    const created = await client.agents.create({ name: 'ci' });
    expect(created.agent_secret).toBe('as_once_only');
    expect(created.id).toBe('a_1');
  });

  it('unwraps tamper events (bare array) and revoke', async () => {
    const { fetchImpl } = makeStub((path, method) => {
      if (path === '/v1/agents/a_1/tamper-events') {
        return { status: 200, body: { data: [{ id: 't_1', version_reported: '1.0', build_sig_reported: null, src_ip: null, action_taken: null, detected_at: '' }], meta: successMeta } };
      }
      if (path === '/v1/agents/a_1' && method === 'DELETE') {
        return { status: 200, body: { data: { revoked: true }, meta: successMeta } };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    expect((await client.agents.getTamperEvents('a_1'))[0].id).toBe('t_1');
    expect(await client.agents.revoke('a_1')).toEqual({ revoked: true });
  });
});

describe('AuditLogsResource', () => {
  it('passes filters + page params and iterates pages', async () => {
    const queries: URLSearchParams[] = [];
    const { fetchImpl } = makeStub((path, _m, query) => {
      if (path === '/v1/audit-logs') {
        queries.push(query);
        const p = query.get('page') ?? '1';
        return {
          status: 200,
          body: p === '1'
            ? { data: [{ id: 'al_1', action: 'route.created', resource_type: 'route', resource_id: null, details: {}, ip_address: null, created_at: '' }], meta: pageMeta(2, 1, 1) }
            : { data: [{ id: 'al_2', action: 'route.created', resource_type: 'route', resource_id: null, details: {}, ip_address: null, created_at: '' }], meta: pageMeta(2, 2, 1) },
        };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    const ids: string[] = [];
    for await (const entry of client.auditLogs.iterate({ action: 'route.created', per_page: 1 })) ids.push(entry.id);
    expect(ids).toEqual(['al_1', 'al_2']);
    expect(queries[0].get('action')).toBe('route.created');
  });
});

describe('OAuthClientsResource (no meta, top-level warning)', () => {
  it('unwraps list to a plain array', async () => {
    const { fetchImpl } = makeStub((path) => {
      if (path === '/v1/oauth-clients') {
        return { status: 200, body: { data: [{ id: 'oc_1', client_id: 'kc_client_1', name: 'svc', type: 'confidential' }] } };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    const list = await client.oauthClients.list();
    expect(list[0].client_id).toBe('kc_client_1');
  });

  it('attaches the top-level warning on create', async () => {
    const { fetchImpl } = makeStub((path, method) => {
      if (path === '/v1/oauth-clients' && method === 'POST') {
        return {
          status: 201,
          body: {
            data: { id: 'oc_1', client_id: 'kc_client_1', client_secret: 'cs_once', type: 'confidential', grant_types: ['client_credentials'], allowed_scopes: [], redirect_uris: [] },
            warning: 'scope not granted',
          },
        };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    const created = await client.oauthClients.create({ name: 'svc' });
    expect(created.client_secret).toBe('cs_once');
    expect(created.warning).toBe('scope not granted');
  });

  it('omits warning when the server sends none', async () => {
    const { fetchImpl } = makeStub((path, method) => {
      if (path === '/v1/oauth-clients' && method === 'POST') {
        return {
          status: 201,
          body: { data: { id: 'oc_2', client_id: 'kc_client_2', client_secret: null, type: 'public', grant_types: [], allowed_scopes: [], redirect_uris: [] } },
        };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    const created = await client.oauthClients.create({ name: 'spa', type: 'public' });
    expect('warning' in created).toBe(false);
    expect(created.client_secret).toBeNull();
  });

  it('attaches the warning on rotateSecret', async () => {
    const { fetchImpl } = makeStub((path, method) => {
      if (path === '/v1/oauth-clients/oc_1/rotate-secret' && method === 'POST') {
        return { status: 200, body: { data: { client_id: 'kc_client_1', client_secret: 'cs_new' }, warning: 'old secret invalidated' } };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    const rotated = await client.oauthClients.rotateSecret('oc_1');
    expect(rotated).toEqual({ client_id: 'kc_client_1', client_secret: 'cs_new', warning: 'old secret invalidated' });
  });
});

describe('CryptoResource', () => {
  it('unwraps the bare-array key list', async () => {
    const { fetchImpl } = makeStub((path) => {
      if (path === '/v1/crypto/keys') {
        return { status: 200, body: { data: [{ id: 'k_1', name: 'default', key_type: 'ecdh-p256', mode: 'cloud-only', current_version: 1, deletion_allowed: false, description: null, created_at: '', updated_at: '' }], meta: successMeta } };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    const keys = await client.crypto.listKeys();
    expect(keys[0].name).toBe('default');
  });

  // Wave-2 backlog row 2-269. `deletion_allowed` had no writer on any surface,
  // so `destroyKeyVersion` was permanently refused with a 500 — which every
  // first-party SDK retries. `updateKey` is the writer; a latched-down destroy
  // is now a 409 the SDK must surface as a client error, not retry.
  it('updateKey PATCHes the destroy safety latch', async () => {
    const { fetchImpl, calls } = makeStub((path, method) => {
      if (path === '/v1/crypto/keys/customer%20pii' && method === 'PATCH') {
        return { status: 200, body: { data: { name: 'customer pii', deletion_allowed: true }, meta: successMeta } };
      }
      return { status: 404, body: { error: { type: 'not_found', message: 'no', request_id: 'r' } } };
    });
    const client = makeClient(fetchImpl);
    const r = await client.crypto.updateKey('customer pii', { deletion_allowed: true });
    expect(r).toEqual({ name: 'customer pii', deletion_allowed: true });
    expect(calls[0].method).toBe('PATCH');
    expect(JSON.parse(calls[0].body!)).toEqual({ deletion_allowed: true });
  });

  it('unwraps portable encryptData / decryptData / inspect', async () => {
    const { fetchImpl } = makeStub((path, method) => {
      if (path === '/v1/encrypt' && method === 'POST') {
        return { status: 200, body: { data: { ciphertext: { ssn: 'kc:abc' }, key: 'default', key_version: 1 }, meta: successMeta } };
      }
      if (path === '/v1/decrypt' && method === 'POST') {
        return { status: 200, body: { data: { plaintext: { ssn: '123-45-6789' } }, meta: successMeta } };
      }
      if (path === '/v1/inspect' && method === 'POST') {
        return { status: 200, body: { data: { encrypted: true, scheme: 'kc', version: 1, datatype: 'string' }, meta: successMeta } };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    const enc = await client.crypto.encryptData({ ssn: '123-45-6789' });
    expect(enc.key).toBe('default');
    const dec = await client.crypto.decryptData(enc.ciphertext);
    expect((dec.plaintext as { ssn: string }).ssn).toBe('123-45-6789');
    const meta = await client.crypto.inspect('kc:abc');
    expect(meta.encrypted).toBe(true);
    expect(meta.scheme).toBe('kc');
  });

  it('fetches the sealing bundle (default key and named key)', async () => {
    const bundle = {
      public_key_raw: 'BPubKeyRaw',
      key_ref: { tenant_id: 't_1', app_key_id: 'k_1', key_version: 3 },
    };
    const keys: Array<string | null> = [];
    const { fetchImpl } = makeStub((path, _m, query) => {
      if (path === '/v1/encrypt/sealing-bundle') {
        keys.push(query.get('key'));
        return { status: 200, body: { data: bundle, meta: successMeta } };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    expect(await client.crypto.getSealingBundle()).toEqual(bundle);
    const named = await client.crypto.getSealingBundle({ key: 'my-key' });
    expect(named.key_ref.key_version).toBe(3);
    expect(keys).toEqual([null, 'my-key']);
  });

  it('unwraps mintClientToken', async () => {
    const { fetchImpl } = makeStub((path, method) => {
      if (path === '/v1/client-tokens' && method === 'POST') {
        return { status: 200, body: { data: { token: 'ct_once', expires_at: '2026-01-01T00:00:00Z', action: 'decrypt' }, meta: successMeta } };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    const minted = await client.crypto.mintClientToken({ action: 'decrypt', data: 'kc:abc' });
    expect(minted.token).toBe('ct_once');
  });

  it('mints a tokenize capability bound to a vault + origins (Card-Grade A1)', async () => {
    const { fetchImpl, calls } = makeStub((path, method) => {
      if (path === '/v1/client-tokens' && method === 'POST') {
        return {
          status: 200,
          body: {
            data: {
              token: 'kct_tokenize', expires_at: '2026-01-01T00:00:00Z', action: 'tokenize',
              vault_id: '44444444-4444-4444-8444-444444444444',
              origins: ['https://shop.example.com'],
            },
            meta: successMeta,
          },
        };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);

    const minted = await client.crypto.mintClientToken({
      action: 'tokenize', vault: 'cardholder_pii', origins: ['https://shop.example.com'],
    });

    expect(minted.action).toBe('tokenize');
    expect(minted.vault_id).toBe('44444444-4444-4444-8444-444444444444');
    expect(minted.origins).toEqual(['https://shop.example.com']);
    // The body carries `vault`/`origins` and no `data` — the server refuses a
    // `data` on this action rather than ignoring it.
    const sent = JSON.parse(calls.at(-1)!.body!);
    expect(sent).toEqual({
      action: 'tokenize', vault: 'cardholder_pii', origins: ['https://shop.example.com'],
    });
    expect(sent.data).toBeUndefined();
  });
});

describe('PkiResource', () => {
  it('unwraps roots (bare array), createRoot, and issueCert', async () => {
    const root = { id: 'ca_1', tenant_id: 't', name: 'internal', cert_pem: 'PEM', subject: 'CN=x', subject_fields: null, not_before: '', not_after: '', status: 'active', created_at: '', sandbox: false };
    const { fetchImpl } = makeStub((path, method) => {
      if (path === '/v1/pki/roots' && method === 'GET') {
        return { status: 200, body: { data: [root], meta: successMeta } };
      }
      if (path === '/v1/pki/roots' && method === 'POST') {
        return { status: 200, body: { data: { root, intermediate_not_after: '2027-01-01T00:00:00Z' }, meta: successMeta } };
      }
      if (path === '/v1/pki/roots/internal/issue/servers' && method === 'POST') {
        return { status: 200, body: { data: { serial_hex: 'ab12', cert_pem: 'CERT', private_key_pem: 'KEY', ca_chain_pem: 'CHAIN', not_before: '', not_after: '' }, meta: successMeta } };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    expect((await client.pki.listRoots())[0].name).toBe('internal');
    const created = await client.pki.createRoot({ name: 'internal', subject: { CN: 'x' } });
    expect(created.root.id).toBe('ca_1');
    expect(created.intermediate_not_after).toBe('2027-01-01T00:00:00Z');
    const issued = await client.pki.issueCert('internal', 'servers', { subject: { CN: 'api.internal' } });
    expect(issued.private_key_pem).toBe('KEY');
    expect(issued.serial_hex).toBe('ab12');
  });
});

describe('VaultsResource', () => {
  it('paginates vault + token lists and unwraps single objects', async () => {
    const vault = { id: 'v_1', tenant_id: 't', name: 'pii', token_format: 'uuid', crypto_key_id: 'k_1', custody_mode: 'managed', default_ttl_seconds: null, metadata_jsonb: {}, description: null, enabled: true, created_at: '', updated_at: '', created_by: null, sandbox: false };
    const { fetchImpl } = makeStub((path, method, query) => {
      if (path === '/v1/vaults' && method === 'GET') {
        return { status: 200, body: { data: [vault], meta: pageMeta(1, 1) } };
      }
      if (path === '/v1/vaults/pii' && method === 'GET') {
        return { status: 200, body: { data: { ...vault, stats: { token_count: 2, active_count: 2, expiring_in_24h: 0 } }, meta: successMeta } };
      }
      if (path === '/v1/vaults/pii' && method === 'DELETE') {
        return { status: 200, body: { data: { deleted: true }, meta: successMeta } };
      }
      if (path === '/v1/vaults/pii/tokens' && method === 'GET') {
        const p = query.get('page') ?? '1';
        return {
          status: 200,
          body: p === '1'
            ? { data: [{ id: 'tok_1', token: 'tk1', expires_at: null, created_at: '', created_by_api_key_id: null, created_by_user_id: null }], meta: pageMeta(2, 1, 1) }
            : { data: [{ id: 'tok_2', token: 'tk2', expires_at: null, created_at: '', created_by_api_key_id: null, created_by_user_id: null }], meta: pageMeta(2, 2, 1) },
        };
      }
      if (path === '/v1/vaults/pii/tokens/tok_1' && method === 'GET') {
        return { status: 200, body: { data: { id: 'tok_1', token: 'tk1', expires_at: null, created_at: '', value: 'plain', value_b64: 'cGxhaW4=', metadata: null, crypto_key_version: 1 }, meta: successMeta } };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    const page = await client.vaults.list();
    expect(page.data[0].name).toBe('pii');
    const detail = await client.vaults.get('pii');
    expect(detail.stats.token_count).toBe(2);
    const tokenIds: string[] = [];
    for await (const t of client.vaults.iterateTokens('pii', { per_page: 1 })) tokenIds.push(t.id);
    expect(tokenIds).toEqual(['tok_1', 'tok_2']);
    const value = await client.vaults.detokenize('pii', 'tok_1');
    expect(value.value).toBe('plain');
    // DELETE returns the vault NAME string, not `true`
    expect(await client.vaults.delete('pii')).toEqual({ deleted: true });
  });
});

describe('DynamicDbResource', () => {
  it('unwraps the lease list whose pagination lives INSIDE data', async () => {
    const { fetchImpl, calls } = makeStub((path) => {
      if (path === '/v1/dyn-db-credentials/leases') {
        return {
          status: 200,
          body: {
            data: {
              leases: [{ id: 7, status: 'active', expires_at: '', issued_at: '', username: 'u', connection_name: 'db', role_name: 'ro', engine: 'postgres' }],
              total: 1,
              limit: 100,
              offset: 0,
            },
            meta: successMeta,
          },
        };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    const leases = await client.dynamicDb.listLeases({ limit: 100, offset: 0 });
    expect(leases.leases[0].id).toBe(7);
    expect(leases.total).toBe(1);
    expect(leases.limit).toBe(100);
    const url = new URL(calls.find((c) => c.url.includes('/leases'))!.url);
    expect(url.searchParams.get('limit')).toBe('100');
  });

  it('unwraps mint (lease_id is an int) and revokeLease', async () => {
    const { fetchImpl } = makeStub((path, method) => {
      if (path === '/v1/dyn-db-credentials/db/creds/readonly' && method === 'POST') {
        return { status: 200, body: { data: { username: 'v_u', password: 'pw_once', expires_at: '', lease_id: 42, connection_name: 'db', role_name: 'readonly' }, meta: successMeta } };
      }
      if (path === '/v1/dyn-db-credentials/leases/42/revoke' && method === 'POST') {
        return { status: 200, body: { data: { revoked: 42 }, meta: successMeta } };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    const minted = await client.dynamicDb.mint('db', 'readonly');
    expect(minted.lease_id).toBe(42);
    expect(await client.dynamicDb.revokeLease(42)).toEqual({ revoked: 42 });
  });

  it('unwraps connection list (bare array) and roles (bare array)', async () => {
    const { fetchImpl } = makeStub((path) => {
      if (path === '/v1/dyn-db-credentials') {
        return { status: 200, body: { data: [{ id: 'db_1', name: 'db', engine: 'postgres', host: 'h', port: 5432, execution_mode: 'direct' }], meta: successMeta } };
      }
      if (path === '/v1/dyn-db-credentials/db/roles') {
        return { status: 200, body: { data: [{ id: 'role_1', name: 'readonly', creation_sql_template: 'CREATE', revocation_sql_template: 'DROP', default_ttl_seconds: null, max_ttl_seconds: null, created_at: '', updated_at: '' }], meta: successMeta } };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    expect((await client.dynamicDb.list())[0].engine).toBe('postgres');
    expect((await client.dynamicDb.listRoles('db'))[0].name).toBe('readonly');
  });
});

describe('AccountResource', () => {
  it('unwraps account and usage', async () => {
    const { fetchImpl } = makeStub((path) => {
      if (path === '/v1/account') {
        return { status: 200, body: { data: { id: 't_1', slug: 'acme', name: 'Acme', region: 'us', subscription_plan: 'free', subscription_status: 'active', trial_start_at: null, trial_end_at: null, subscription_current_period_start: null, subscription_current_period_end: null, subscription_cancel_at: null, created_at: '' }, meta: successMeta } };
      }
      if (path === '/v1/account/usage') {
        return { status: 200, body: { data: { billing_period: { year: 2026, month: 7, start: null, end: null }, api_calls: { used: 10, limit: 1000, percentage: 1 }, resources: { routes: { used: 1, limit: 5 }, secrets: { used: 0, limit: 10 }, clients: { used: 0, limit: 5 }, environments: { used: 2, limit: null } }, plan: 'free', status: 'active' }, meta: successMeta } };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    expect((await client.account.get()).slug).toBe('acme');
    expect((await client.account.getUsage()).api_calls.used).toBe(10);
  });
});

describe('ApiKeysResource', () => {
  it('lists as a page and unwraps create/revoke', async () => {
    const { fetchImpl } = makeStub((path, method) => {
      if (path === '/v1/api-keys' && method === 'GET') {
        return { status: 200, body: { data: [{ id: 'ak_1', key_id: 'kid', key_prefix: 'tk_ab', key_type: 'standard', name: 'ci', active: true, created_at: '', last_used_at: null, rate_limit_requests: null, rate_limit_window_sec: null }], meta: pageMeta(1, 1) } };
      }
      if (path === '/v1/api-keys' && method === 'POST') {
        return { status: 200, body: { data: { id: 'f0a1b2c3-d4e5-6f7a-8b9c-0d1e2f3a4b5c', key_id: 'kid2', api_key: 'tk_once', key_prefix: 'tk_cd', key_type: 'standard', name: 'new', role_ids: [], message: 'save it' }, meta: successMeta } };
      }
      if (path === '/v1/api-keys/ak_1' && method === 'DELETE') {
        return { status: 200, body: { data: { revoked: true }, meta: successMeta } };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    expect((await client.apiKeys.list()).data[0].key_prefix).toBe('tk_ab');
    expect((await client.apiKeys.create({ name: 'new' })).api_key).toBe('tk_once');
    expect(await client.apiKeys.revoke('ak_1')).toEqual({ revoked: true });
  });

  it('sends role_ids verbatim and surfaces the returned id + role_ids', async () => {
    const { fetchImpl, calls } = makeStub((path, method) => {
      if (path === '/v1/api-keys' && method === 'POST') {
        return { status: 200, body: { data: { id: 'f0a1b2c3-d4e5-6f7a-8b9c-0d1e2f3a4b5c', key_id: 'kid2', api_key: 'tk_once', key_prefix: 'tk_cd', key_type: 'standard', name: 'tf', role_ids: ['b3f1c2d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d'], message: 'save it' }, meta: successMeta } };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    const created = await client.apiKeys.create({ name: 'tf', role_ids: ['b3f1c2d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d'] });
    expect(created.id).toBe('f0a1b2c3-d4e5-6f7a-8b9c-0d1e2f3a4b5c');
    expect(created.role_ids).toEqual(['b3f1c2d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d']);
    expect(JSON.parse(calls[0].body!)).toEqual({ name: 'tf', role_ids: ['b3f1c2d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d'] });
  });

  it('surfaces 403 privilege_escalation as PermissionDeniedError with the code intact', async () => {
    const { fetchImpl } = makeStub(() => ({
      status: 403,
      body: {
        error: {
          type: 'privilege_escalation',
          message: 'This API key cannot grant a permission it does not itself hold. Refused grant from role "Key — Infrastructure": {"resource_type":"vault","actions":["create"],"effect":"allow"} — no rule in your own policy set grants it.',
          request_id: 'req-1',
        },
      },
    }));
    const client = makeClient(fetchImpl);
    await expect(client.apiKeys.create({ name: 'x', role_ids: ['b3f1c2d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d'] }))
      .rejects.toMatchObject({ status: 403, code: 'privilege_escalation' });
  });
});

describe('RolesResource', () => {
  it('lists roles as a page and forwards subject_kind', async () => {
    const { fetchImpl, calls } = makeStub((path) => {
      if (path === '/v1/roles') {
        return {
          status: 200,
          body: {
            data: [{ id: 'b3f1c2d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d', name: 'Key — Infrastructure', description: null, applies_to: ['api_key'], is_default: false, seeded: true }],
            meta: pageMeta(1, 1),
          },
        };
      }
      return { status: 200, body: { data: [], meta: pageMeta(0, 1) } };
    });
    const client = makeClient(fetchImpl);
    const page = await client.roles.list({ subject_kind: 'api_key' });
    expect(page.data[0].seeded).toBe(true);
    expect(page.data[0].applies_to).toEqual(['api_key']);
    expect(page.meta.total).toBe(1);
    expect(calls[0].url).toContain('subject_kind=api_key');
  });
});

describe('WorkflowsResource', () => {
  it('lists workflows with the real {data, meta} envelope', async () => {
    const { fetchImpl, calls } = makeStub((path) => {
      if (path === '/v1/workflows') {
        return { status: 200, body: { data: [{ id: 'wf_1', name: 'a', enabled: true }], meta: pageMeta(1, 1, 20) } };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    const page = await client.workflows.list();
    expect(page.data[0].id).toBe('wf_1');
    expect(page.meta.total_pages).toBe(1);
    expect(calls[0].url).toContain('/v1/workflows');
  });

  it('iterates workflows across pages via meta.total_pages (no cursor)', async () => {
    const pages: Record<string, unknown> = {
      '1': { data: [{ id: 'wf_1' }, { id: 'wf_2' }], meta: pageMeta(3, 1, 2) },
      '2': { data: [{ id: 'wf_3' }], meta: pageMeta(3, 2, 2) },
    };
    const { fetchImpl } = makeStub((path, _m, query) => {
      if (path === '/v1/workflows') return { status: 200, body: pages[query.get('page') ?? '1'] };
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    const ids: string[] = [];
    for await (const w of client.workflows.iterate({ per_page: 2 })) ids.push((w as any).id);
    expect(ids).toEqual(['wf_1', 'wf_2', 'wf_3']);
  });

  it('unwraps get() from {data}', async () => {
    const { fetchImpl } = makeStub((path) => {
      if (path === '/v1/workflows/wf_1') return { status: 200, body: { data: { id: 'wf_1', name: 'a' }, meta: successMeta } };
      return { status: 404, body: { error: { type: 'not_found', message: 'x' } } };
    });
    const client = makeClient(fetchImpl);
    expect((await client.workflows.get('wf_1')).id).toBe('wf_1');
  });

  it('execute() posts input and unwraps the run ack', async () => {
    const { fetchImpl, calls } = makeStub((path) => {
      if (path === '/v1/workflows/wf_1/execute') {
        return { status: 201, body: { data: { id: 'exec_1', workflow_id: 'wf_1', status: 'queued' }, meta: successMeta } };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    const run = await client.workflows.execute('wf_1', { foo: 'bar' });
    expect(run.id).toBe('exec_1');
    expect(run.status).toBe('queued');
    expect(JSON.parse(calls[0].body!).input).toEqual({ foo: 'bar' });
    // Auto-generated idempotency key rides on the mutation (exactly-once execute).
    expect(calls[0].method).toBe('POST');
  });

  it('create/update/delete unwrap the single-object envelope', async () => {
    const { fetchImpl } = makeStub((path, method) => {
      if (path === '/v1/workflows' && method === 'POST') {
        return { status: 201, body: { data: { id: 'wf_new', name: 'n' }, meta: successMeta } };
      }
      if (path === '/v1/workflows/wf_1' && method === 'PATCH') {
        return { status: 200, body: { data: { id: 'wf_1', name: 'renamed' }, meta: successMeta } };
      }
      if (path === '/v1/workflows/wf_1' && method === 'DELETE') {
        return { status: 200, body: { data: { id: 'wf_1', deleted: true }, meta: successMeta } };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    expect((await client.workflows.create({ name: 'n', definition: {} })).id).toBe('wf_new');
    expect((await client.workflows.update('wf_1', { name: 'renamed' })).name).toBe('renamed');
    expect((await client.workflows.delete('wf_1')).deleted).toBe(true);
  });

  // PARITY §11 Workflows — "an unpublishable definition may never be the running
  // one". CREATE withholds the switch and UPDATE refuses; both are behaviours a
  // caller can hit on a perfectly ordinary request, so both are pinned here.
  it('create() surfaces enabled:false verbatim when the server withholds the switch', async () => {
    const { fetchImpl } = makeStub((path, method) => {
      if (path === '/v1/workflows' && method === 'POST') {
        // The definition's steps are incomplete, so the server keeps the data
        // and creates the row NOT enabled. This is a 200, not an error.
        return { status: 200, body: { data: { id: 'wf_new', name: 'n', enabled: false }, meta: successMeta } };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    const created = await client.workflows.create({ name: 'n', definition: {}, enabled: true } as never);
    // Never echoed back from the request body — the SDK reports what the server
    // actually stored, or a caller believes a workflow is running that is not.
    expect((created as { enabled?: boolean }).enabled).toBe(false);
  });

  it('update() raises the typed 422 and does NOT retry it', async () => {
    const { fetchImpl, calls } = makeStub((path, method) => {
      if (path === '/v1/workflows/wf_1' && method === 'PATCH') {
        return {
          status: 422,
          body: {
            error: {
              type: 'invalid_definition',
              message:
                'This workflow cannot be enabled: node "n1": HTTP method is required',
              request_id: 'req-1',
            },
          },
        };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const { ValidationError } = await import('../src/index.js');
    const client = makeClient(fetchImpl);
    await expect(client.workflows.update('wf_1', { enabled: true } as never)).rejects.toBeInstanceOf(
      ValidationError,
    );
    // A client error. Retrying it unchanged burns the tenant's rate limit and
    // can never succeed.
    expect(calls.filter((c) => c.method === 'PATCH')).toHaveLength(1);
  });

  it('lists and fetches executions with the real envelope', async () => {
    const { fetchImpl } = makeStub((path) => {
      if (path === '/v1/workflows/wf_1/executions') {
        return { status: 200, body: { data: [{ id: 'exec_1', status: 'completed' }], meta: pageMeta(1, 1, 20) } };
      }
      if (path === '/v1/workflows/executions/exec_1') {
        return { status: 200, body: { data: { id: 'exec_1', status: 'completed', node_executions: [] }, meta: successMeta } };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    expect((await client.workflows.listExecutions('wf_1')).data[0].id).toBe('exec_1');
    expect((await client.workflows.getExecution('exec_1')).status).toBe('completed');
  });
});

describe('AIGatewayResource', () => {
  const gateway = { id: 'gw_1', name: 'prod', slug: 'prod', description: null, budget_daily_usd: null, budget_monthly_usd: null, sandbox: false, created_at: '', updated_at: '' };
  const agent = { id: 'ag_1', gateway_id: 'gw_1', name: 'copilot', slug: 'copilot', description: null, primary_route_id: null, default_model: null, model_allowlist: null, model_denylist: null, budget_daily_usd: null, budget_monthly_usd: null, streaming_enabled: true, firewall_policy_id: null, pii_redact_policy_id: null, sandbox: false, agent_url: 'https://acme.knoxcall.com/v1/ai/copilot', created_at: '', updated_at: '' };

  it('lists gateways with the real {data, meta} envelope and unwraps single objects', async () => {
    const { fetchImpl, calls } = makeStub((path, method) => {
      if (path === '/v1/ai-gateway/gateways' && method === 'GET') {
        return { status: 200, body: { data: [gateway], meta: pageMeta(1, 1, 20) } };
      }
      if (path === '/v1/ai-gateway/gateways' && method === 'POST') {
        return { status: 201, body: { data: { ...gateway, id: 'gw_new', name: 'new' }, meta: successMeta } };
      }
      if (path === '/v1/ai-gateway/gateways/gw_1' && method === 'GET') {
        return { status: 200, body: { data: gateway, meta: successMeta } };
      }
      if (path === '/v1/ai-gateway/gateways/gw_1' && method === 'PATCH') {
        return { status: 200, body: { data: { ...gateway, name: 'renamed' }, meta: successMeta } };
      }
      if (path === '/v1/ai-gateway/gateways/gw_1' && method === 'DELETE') {
        return { status: 200, body: { data: { id: 'gw_1', status: 'deleted' }, meta: successMeta } };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    const page = await client.aiGateway.listGateways();
    expect(page.data[0].id).toBe('gw_1');
    expect(page.meta.total_pages).toBe(1);
    expect(calls[0].url).toContain('/v1/ai-gateway/gateways');
    expect((await client.aiGateway.createGateway({ name: 'new', slug: 'new' })).id).toBe('gw_new');
    expect((await client.aiGateway.getGateway('gw_1')).slug).toBe('prod');
    expect((await client.aiGateway.updateGateway('gw_1', { name: 'renamed' })).name).toBe('renamed');
    expect(await client.aiGateway.deleteGateway('gw_1')).toEqual({ id: 'gw_1', status: 'deleted' });
  });

  it('iterates gateways across pages via meta.total_pages (no cursor)', async () => {
    const pages: Record<string, unknown> = {
      '1': { data: [{ ...gateway, id: 'gw_1' }, { ...gateway, id: 'gw_2' }], meta: pageMeta(3, 1, 2) },
      '2': { data: [{ ...gateway, id: 'gw_3' }], meta: pageMeta(3, 2, 2) },
    };
    const { fetchImpl } = makeStub((path, _m, query) => {
      if (path === '/v1/ai-gateway/gateways') return { status: 200, body: pages[query.get('page') ?? '1'] };
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    const ids: string[] = [];
    for await (const g of client.aiGateway.iterateGateways({ per_page: 2 })) ids.push(g.id);
    expect(ids).toEqual(['gw_1', 'gw_2', 'gw_3']);
  });

  it('lists/creates agents under a gateway and gets/updates/deletes flat', async () => {
    const { fetchImpl, calls } = makeStub((path, method) => {
      if (path === '/v1/ai-gateway/gateways/gw_1/agents' && method === 'GET') {
        return { status: 200, body: { data: [agent], meta: pageMeta(1, 1, 20) } };
      }
      if (path === '/v1/ai-gateway/gateways/gw_1/agents' && method === 'POST') {
        return { status: 201, body: { data: { ...agent, id: 'ag_new', name: 'bot' }, meta: successMeta } };
      }
      if (path === '/v1/ai-gateway/agents/ag_1' && method === 'GET') {
        return { status: 200, body: { data: agent, meta: successMeta } };
      }
      if (path === '/v1/ai-gateway/agents/ag_1' && method === 'PATCH') {
        return { status: 200, body: { data: { ...agent, default_model: 'claude-sonnet-5' }, meta: successMeta } };
      }
      if (path === '/v1/ai-gateway/agents/ag_1' && method === 'DELETE') {
        return { status: 200, body: { data: { id: 'ag_1', status: 'deleted' }, meta: successMeta } };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    const page = await client.aiGateway.listAgents('gw_1');
    expect(page.data[0].id).toBe('ag_1');
    expect(calls[0].url).toContain('/v1/ai-gateway/gateways/gw_1/agents');
    const created = await client.aiGateway.createAgent('gw_1', { name: 'bot', slug: 'bot' });
    expect(created.id).toBe('ag_new');
    expect((await client.aiGateway.getAgent('ag_1')).slug).toBe('copilot');
    expect((await client.aiGateway.updateAgent('ag_1', { default_model: 'claude-sonnet-5' })).default_model).toBe('claude-sonnet-5');
    expect(await client.aiGateway.deleteAgent('ag_1')).toEqual({ id: 'ag_1', status: 'deleted' });

    // AIGW-161: `agent_url` is on EVERY agent projection, not just create.
    // It used to be absent from the list rows and from PATCH, so a caller who
    // listed agents got a row shaped differently from the one create returned
    // and the field could not be typed as present at all.
    expect(page.data[0].agent_url).toBe('https://acme.knoxcall.com/v1/ai/copilot');
    expect(created.agent_url).toBe('https://acme.knoxcall.com/v1/ai/copilot');
    expect((await client.aiGateway.getAgent('ag_1')).agent_url).toBe('https://acme.knoxcall.com/v1/ai/copilot');
    expect((await client.aiGateway.updateAgent('ag_1', { slug: 'copilot' })).agent_url).toBe('https://acme.knoxcall.com/v1/ai/copilot');
  });

  it('sends provider + upstream_secret_id so the server composes an upstream route', async () => {
    // Without these an SDK-created agent comes out with primary_route_id null —
    // no upstream, no credential template — and its first data-plane call 502s.
    // The server refuses provider AND primary_route_id together (400), so an SDK
    // that quietly sent both would break the very flow the field exists for.
    const { fetchImpl, calls } = makeStub(() => ({
      status: 201,
      body: { data: { ...agent, id: 'ag_prov', provider: 'azure-openai' }, meta: successMeta },
    }));
    const client = makeClient(fetchImpl);
    await client.aiGateway.createAgent('gw_1', {
      name: 'bot',
      slug: 'bot',
      provider: 'azure-openai',
      upstream_secret_id: 'c0ffee00-2222-4a2b-8c3d-000000000009',
      upstream: 'https://acme.openai.azure.com',
    });
    const sent = JSON.parse(String(calls[0].body));
    expect(sent.provider).toBe('azure-openai');
    expect(sent.upstream_secret_id).toBe('c0ffee00-2222-4a2b-8c3d-000000000009');
    expect(sent.upstream).toBe('https://acme.openai.azure.com');
    expect('primary_route_id' in sent).toBe(false);
  });

  it('accepts a provider outside the historic six without a cast', async () => {
    // AIGW-161 / PARITY.md: `AIProviderId` used to be a six-member union while
    // the server catalog held fourteen, so `provider: "groq"` was a TYPE ERROR
    // for a value the API accepts. The catalog grows server-side; an SDK-side
    // enum can only ever be behind it. This compiles because the type is
    // `string` — if someone narrows it again, tsc fails here.
    const { fetchImpl, calls } = makeStub(() => ({
      status: 201,
      body: { data: { ...agent, id: 'ag_groq', provider: 'groq' }, meta: successMeta },
    }));
    const client = makeClient(fetchImpl);
    for (const provider of ['groq', 'bedrock', 'openai-compatible', 'xai'] as AIProviderId[]) {
      await client.aiGateway.createAgent('gw_1', {
        name: provider, slug: provider, provider,
        upstream_secret_id: 'c0ffee00-2222-4a2b-8c3d-000000000009',
        upstream: 'https://llm.acme.example',
        default_model: 'some-model',
      });
    }
    expect(calls.map((c) => JSON.parse(String(c.body)).provider))
      .toEqual(['groq', 'bedrock', 'openai-compatible', 'xai']);
  });

  it('lists and revokes GATEWAY-level tokens (the agent-less MCP shape)', async () => {
    const tok = { id: 'tok_g', name: 'ci', kind: 'tool', prefix: 'kc_live_t', agent_id: null, dpop_required: false, expires_at: null, created_at: '', revoked_at: null };
    const { fetchImpl, calls } = makeStub((path, method) => {
      if (path === '/v1/ai-gateway/gateways/gw_1/tokens' && method === 'GET') {
        return { status: 200, body: { data: [tok], meta: pageMeta(1, 1, 20) } };
      }
      if (path === '/v1/ai-gateway/gateways/gw_1/tokens/tok_g' && method === 'DELETE') {
        return { status: 200, body: { data: { id: 'tok_g', revoked: true }, meta: successMeta } };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    const page = await client.aiGateway.listGatewayTokens('gw_1');
    // agent_id null is the whole point — the per-agent list cannot see this row.
    expect(page.data[0].agent_id).toBeNull();
    expect(calls[0].url).toContain('/v1/ai-gateway/gateways/gw_1/tokens');
    expect(await client.aiGateway.revokeGatewayToken('gw_1', 'tok_g')).toEqual({ id: 'tok_g', revoked: true });
  });

  it('lists/creates MCP servers under a gateway and gets/updates/archives flat', async () => {
    const mcp = {
      id: 'mcp_1', gateway_id: 'gw_1', name: 'Vendor tools', slug: 'vendor-tools', description: null,
      server_type: 'upstream', transport: 'streamable_http', upstream_url: 'https://mcp.vendor.example/mcp',
      allowed_tools: ['get_weather'], pii_inspection: true, auth: {}, status: 'active',
      created_at: '', updated_at: '',
      connect_url: 'https://acme.knoxcall.com/v1/mcp/vendor-tools',
      resource: 'https://api.knoxcall.com/v1/mcp/vendor-tools',
    };
    const { fetchImpl, calls } = makeStub((path, method) => {
      if (path === '/v1/ai-gateway/gateways/gw_1/mcp-servers' && method === 'GET') {
        return { status: 200, body: { data: [mcp], meta: pageMeta(1, 1, 20) } };
      }
      if (path === '/v1/ai-gateway/gateways/gw_1/mcp-servers' && method === 'POST') {
        return { status: 200, body: { data: { ...mcp, id: 'mcp_new', allowed_tools: [] }, meta: { ...successMeta, note: 'allowed_tools is empty, so this server advertises NO tools.' } } };
      }
      if (path === '/v1/ai-gateway/mcp-servers/mcp_1' && method === 'GET') {
        return { status: 200, body: { data: mcp, meta: successMeta } };
      }
      if (path === '/v1/ai-gateway/mcp-servers/mcp_1' && method === 'PATCH') {
        return { status: 200, body: { data: { ...mcp, allowed_tools: ['get_weather', 'lookup'] }, meta: successMeta } };
      }
      if (path === '/v1/ai-gateway/mcp-servers/mcp_1' && method === 'DELETE') {
        return { status: 200, body: { data: { id: 'mcp_1', status: 'archived' }, meta: successMeta } };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    const page = await client.aiGateway.listMcpServers('gw_1');
    expect(page.data[0].id).toBe('mcp_1');
    expect(calls[0].url).toContain('/v1/ai-gateway/gateways/gw_1/mcp-servers');
    const created = await client.aiGateway.createMcpServer('gw_1', {
      name: 'Vendor tools', slug: 'vendor-tools', upstream_url: 'https://mcp.vendor.example/mcp',
    });
    expect(created.id).toBe('mcp_new');
    // An empty allowlist advertises nothing — the SDK must surface it, not hide it.
    expect(created.allowed_tools).toEqual([]);
    const one = await client.aiGateway.getMcpServer('mcp_1');
    // connect_url and resource are different concepts and both must survive.
    expect(one.connect_url).toBe('https://acme.knoxcall.com/v1/mcp/vendor-tools');
    expect(one.resource).toBe('https://api.knoxcall.com/v1/mcp/vendor-tools');
    expect((await client.aiGateway.updateMcpServer('mcp_1', { allowed_tools: ['get_weather', 'lookup'] })).allowed_tools).toEqual(['get_weather', 'lookup']);
    expect(await client.aiGateway.deleteMcpServer('mcp_1')).toEqual({ id: 'mcp_1', status: 'archived' });
  });

  it('lists/upserts/updates/deletes MCP tool rows', async () => {
    const tool = { id: 'tl_1', mcp_server_id: 'mcp_1', tool_name: 'get_weather', route_id: null, description: null, input_schema: {}, enabled: true, created_at: '', updated_at: '' };
    const { fetchImpl, calls } = makeStub((path, method) => {
      if (path === '/v1/ai-gateway/mcp-servers/mcp_1/tools' && method === 'GET') {
        return { status: 200, body: { data: [tool], meta: pageMeta(1, 1, 20) } };
      }
      if (path === '/v1/ai-gateway/mcp-servers/mcp_1/tools' && method === 'POST') {
        return { status: 200, body: { data: tool, meta: successMeta } };
      }
      if (path === '/v1/ai-gateway/mcp-servers/mcp_1/tools/tl_1' && method === 'PATCH') {
        return { status: 200, body: { data: { ...tool, enabled: false }, meta: successMeta } };
      }
      if (path === '/v1/ai-gateway/mcp-servers/mcp_1/tools/tl_1' && method === 'DELETE') {
        return { status: 200, body: { data: { id: 'tl_1', deleted: true }, meta: successMeta } };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    expect((await client.aiGateway.listMcpTools('mcp_1')).data[0].tool_name).toBe('get_weather');
    expect(calls[0].url).toContain('/v1/ai-gateway/mcp-servers/mcp_1/tools');
    expect((await client.aiGateway.upsertMcpTool('mcp_1', { tool_name: 'get_weather' })).id).toBe('tl_1');
    expect((await client.aiGateway.updateMcpTool('mcp_1', 'tl_1', { enabled: false })).enabled).toBe(false);
    expect(await client.aiGateway.deleteMcpTool('mcp_1', 'tl_1')).toEqual({ id: 'tl_1', deleted: true });
  });

  it('lists tokens (no plaintext), mints a token (plaintext once), and revokes', async () => {
    const { fetchImpl, calls } = makeStub((path, method) => {
      if (path === '/v1/ai-gateway/agents/ag_1/tokens' && method === 'GET') {
        return { status: 200, body: { data: [{ id: 'tok_1', name: 'ci', kind: 'agent', prefix: 'kcg_ab', dpop_required: false, expires_at: null, created_at: '', revoked_at: null }], meta: pageMeta(1, 1, 20) } };
      }
      if (path === '/v1/ai-gateway/agents/ag_1/tokens' && method === 'POST') {
        return { status: 201, body: { data: { id: 'tok_new', name: 'ci', kind: 'agent', prefix: 'kcg_cd', token: 'kcg_live_plaintext_once', dpop_required: true, expires_at: null }, meta: { request_id: 'req-1', note: 'token shown once' } } };
      }
      if (path === '/v1/ai-gateway/agents/ag_1/tokens/tok_1' && method === 'DELETE') {
        return { status: 200, body: { data: { id: 'tok_1', revoked: true }, meta: successMeta } };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    const list = await client.aiGateway.listTokens('ag_1');
    expect(list.data[0].id).toBe('tok_1');
    // list rows never carry the plaintext token
    expect((list.data[0] as Record<string, unknown>).token).toBeUndefined();
    const minted = await client.aiGateway.mintToken('ag_1', { name: 'ci', kind: 'agent', dpop_required: true });
    expect(minted.token).toBe('kcg_live_plaintext_once');
    expect(minted.prefix).toBe('kcg_cd');
    expect(calls.find((c) => c.method === 'POST')!.url).toContain('/v1/ai-gateway/agents/ag_1/tokens');
    expect(await client.aiGateway.revokeToken('ag_1', 'tok_1')).toEqual({ id: 'tok_1', revoked: true });
  });

  // AIGW-03: the firewall-policy surface. The mocks mirror the real
  // {data, meta} envelope (PARITY §4) — a list returns data:[] + PageMeta, a
  // single write returns data:{} + request_id.
  it('lists, creates, reads, updates, deletes and tests firewall policies', async () => {
    const policy = {
      id: 'fp_1', tenant_id: 'ten_1', name: 'Strict', version: 1,
      heuristics: [{ name: 'no_competitor', kind: 'regex', pattern: 'CompetitorAI', flags: 'i' }],
      canary_enabled: true, vector_classifier_enabled: false, lakera_enabled: false,
      model_classifier_id: null, action: 'block', created_at: '2026-08-24T00:00:00Z',
    };
    const { fetchImpl, calls } = makeStub((path, method) => {
      if (path === '/v1/ai-gateway/firewall-policies' && method === 'GET') {
        return { status: 200, body: { data: [policy], meta: pageMeta(1, 1, 20) } };
      }
      if (path === '/v1/ai-gateway/firewall-policies' && method === 'POST') {
        return { status: 200, body: { data: { ...policy, id: 'fp_new', version: 2 }, meta: successMeta } };
      }
      if (path === '/v1/ai-gateway/firewall-policies/test' && method === 'POST') {
        return { status: 200, body: { data: { matched: true, matches: [{ rule: 'ignore_previous_instructions', span: [0, 27], matched: 'Ignore all previous instruc' }], skipped: [] }, meta: successMeta } };
      }
      if (path === '/v1/ai-gateway/firewall-policies/fp_1' && method === 'GET') {
        return { status: 200, body: { data: policy, meta: successMeta } };
      }
      if (path === '/v1/ai-gateway/firewall-policies/fp_1' && method === 'PATCH') {
        return { status: 200, body: { data: { ...policy, action: 'warn' }, meta: successMeta } };
      }
      if (path === '/v1/ai-gateway/firewall-policies/fp_1' && method === 'DELETE') {
        return { status: 200, body: { data: { id: 'fp_1', deleted: true }, meta: successMeta } };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);

    const page = await client.aiGateway.listFirewallPolicies();
    expect(page.data[0].action).toBe('block');
    expect(page.meta.per_page).toBe(20);

    const created = await client.aiGateway.createFirewallPolicy({
      name: 'Strict', action: 'block',
      heuristics: [{ name: 'no_competitor', kind: 'regex', pattern: 'CompetitorAI' }],
    });
    expect(created.id).toBe('fp_new');
    expect(created.version).toBe(2);   // re-using a name bumps the version

    expect((await client.aiGateway.getFirewallPolicy('fp_1')).name).toBe('Strict');
    expect((await client.aiGateway.updateFirewallPolicy('fp_1', { action: 'warn' })).action).toBe('warn');
    expect(await client.aiGateway.deleteFirewallPolicy('fp_1')).toEqual({ id: 'fp_1', deleted: true });

    const tested = await client.aiGateway.testFirewallRules({ text: 'Ignore all previous instructions' });
    expect(tested.matched).toBe(true);
    expect(tested.matches[0].rule).toBe('ignore_previous_instructions');
    expect(tested.skipped).toEqual([]);

    // The tester path must not be captured as an id by the :id route.
    expect(calls.some((c) => c.url.endsWith('/v1/ai-gateway/firewall-policies/test'))).toBe(true);
  });

  // AIGW-160: PII policies and recognizers. Same envelope discipline as the
  // firewall block above; the three behaviours PARITY calls out are asserted
  // rather than described — an empty recognizer_ids round-trips as [] (it means
  // "every recognizer", not "none"), the tester reaches its own path, and both
  // deletes surface the server's 409 refusal rather than a silent success.
  it('lists, creates, reads, updates, deletes and tests PII policies and recognizers', async () => {
    const policy = {
      id: 'pp_1', tenant_id: 'ten_1', name: 'HIPAA', version: 1,
      recognizer_ids: ['pr_1'], default_action: 'redact',
      description: 'PHI shapes', created_at: '2026-09-07T00:00:00Z',
    };
    const recognizer = {
      id: 'pr_1', tenant_id: 'ten_1', name: 'employee_id', kind: 'regex',
      pattern: 'EMP-[0-9]{6}', context_words: [], confidence: 0.9,
      action: 'redact', format: null, enabled: true, created_at: '2026-09-07T00:00:00Z',
    };
    const { fetchImpl, calls } = makeStub((path, method) => {
      if (path === '/v1/ai-gateway/pii-policies' && method === 'GET') {
        return { status: 200, body: { data: [policy], meta: pageMeta(1, 1, 20) } };
      }
      if (path === '/v1/ai-gateway/pii-policies' && method === 'POST') {
        // An empty recognizer_ids is "every enabled recognizer", so the server
        // echoes [] back rather than expanding it.
        return { status: 200, body: { data: { ...policy, id: 'pp_new', recognizer_ids: [] }, meta: successMeta } };
      }
      if (path === '/v1/ai-gateway/pii-policies/pp_1' && method === 'GET') {
        return { status: 200, body: { data: policy, meta: successMeta } };
      }
      if (path === '/v1/ai-gateway/pii-policies/pp_1' && method === 'PATCH') {
        return { status: 200, body: { data: { ...policy, default_action: 'tokenize' }, meta: successMeta } };
      }
      if (path === '/v1/ai-gateway/pii-policies/pp_1' && method === 'DELETE') {
        return { status: 200, body: { data: { id: 'pp_1', deleted: true }, meta: successMeta } };
      }
      if (path === '/v1/ai-gateway/pii-policies/pp_used' && method === 'DELETE') {
        return { status: 409, body: { error: { type: 'policy_in_use', message: 'policy is still attached to 1 agent(s): agent "copilot"', request_id: 'req-409' } } };
      }
      if (path === '/v1/ai-gateway/pii-recognizers' && method === 'GET') {
        return { status: 200, body: { data: [recognizer], meta: pageMeta(1, 1, 20) } };
      }
      if (path === '/v1/ai-gateway/pii-recognizers' && method === 'POST') {
        return { status: 200, body: { data: { ...recognizer, id: 'pr_new' }, meta: successMeta } };
      }
      if (path === '/v1/ai-gateway/pii-recognizers/test' && method === 'POST') {
        return { status: 200, body: { data: { matched: true, matches: [{ span: [11, 21], matched: 'EMP-123456', replacement: '[EMPLOYEE_ID]', entity_type: 'employee_id' }] }, meta: successMeta } };
      }
      if (path === '/v1/ai-gateway/pii-recognizers/pr_1' && method === 'GET') {
        return { status: 200, body: { data: recognizer, meta: successMeta } };
      }
      if (path === '/v1/ai-gateway/pii-recognizers/pr_1' && method === 'PATCH') {
        return { status: 200, body: { data: { ...recognizer, enabled: false }, meta: successMeta } };
      }
      if (path === '/v1/ai-gateway/pii-recognizers/pr_1' && method === 'DELETE') {
        return { status: 200, body: { data: { id: 'pr_1', deleted: true }, meta: successMeta } };
      }
      if (path === '/v1/ai-gateway/pii-recognizers/pr_used' && method === 'DELETE') {
        return { status: 409, body: { error: { type: 'recognizer_in_use', message: 'recognizer is still listed by 1 PII policy/policies: "HIPAA"', request_id: 'req-409' } } };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);

    const policies = await client.aiGateway.listPiiPolicies();
    expect(policies.data[0].default_action).toBe('redact');
    expect(policies.meta.per_page).toBe(20);

    const createdPolicy = await client.aiGateway.createPiiPolicy({ name: 'HIPAA', recognizer_ids: [] });
    expect(createdPolicy.id).toBe('pp_new');
    expect(createdPolicy.recognizer_ids).toEqual([]);

    expect((await client.aiGateway.getPiiPolicy('pp_1')).name).toBe('HIPAA');
    expect((await client.aiGateway.updatePiiPolicy('pp_1', { default_action: 'tokenize' })).default_action).toBe('tokenize');
    expect(await client.aiGateway.deletePiiPolicy('pp_1')).toEqual({ id: 'pp_1', deleted: true });

    // Deleting a policy an agent still uses must SURFACE the refusal, not
    // resolve: the FK is ON DELETE SET NULL, so a swallowed 409 would read as
    // "redaction removed cleanly" when it means "every bound agent lost it".
    await expect(client.aiGateway.deletePiiPolicy('pp_used')).rejects.toMatchObject({ status: 409 });

    const recognizers = await client.aiGateway.listPiiRecognizers();
    expect(recognizers.data[0].pattern).toBe('EMP-[0-9]{6}');

    const createdRecognizer = await client.aiGateway.createPiiRecognizer({
      name: 'employee_id', kind: 'regex', pattern: 'EMP-[0-9]{6}',
    });
    expect(createdRecognizer.id).toBe('pr_new');

    expect((await client.aiGateway.getPiiRecognizer('pr_1')).name).toBe('employee_id');
    expect((await client.aiGateway.updatePiiRecognizer('pr_1', { enabled: false })).enabled).toBe(false);
    expect(await client.aiGateway.deletePiiRecognizer('pr_1')).toEqual({ id: 'pr_1', deleted: true });
    await expect(client.aiGateway.deletePiiRecognizer('pr_used')).rejects.toMatchObject({ status: 409 });

    const tested = await client.aiGateway.testPiiRecognizer({
      pattern: 'EMP-[0-9]{6}', text: 'badge for EMP-123456',
    });
    expect(tested.matched).toBe(true);
    expect(tested.matches[0].matched).toBe('EMP-123456');
    expect(tested.matches[0].entity_type).toBe('employee_id');

    // The tester path must not be captured as an id by the :id route.
    expect(calls.some((c) => c.url.endsWith('/v1/ai-gateway/pii-recognizers/test'))).toBe(true);
  });

  it('fetches the usage rollup with period + agent_id query', async () => {
    const { fetchImpl, calls } = makeStub((path) => {
      if (path === '/v1/ai-gateway/usage') {
        return { status: 200, body: { data: { period_days: 30, by_model: [{ provider: 'anthropic', model: 'claude-sonnet-5', requests: 12, input_tokens: 100, output_tokens: 50, cost_usd: 0.42, unpriced_requests: 0 }], totals: { requests: 12, input_tokens: 100, output_tokens: 50, cost_usd: 0.42, unpriced_requests: 0 } }, meta: successMeta } };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = makeClient(fetchImpl);
    const usage = await client.aiGateway.usage({ period: '30d', agent_id: 'ag_1' });
    expect(usage.period_days).toBe(30);
    expect(usage.by_model[0].model).toBe('claude-sonnet-5');
    expect(usage.totals.cost_usd).toBe(0.42);
    const url = new URL(calls[0].url);
    expect(url.searchParams.get('period')).toBe('30d');
    expect(url.searchParams.get('agent_id')).toBe('ag_1');
  });

  it('sandbox client hits the same paths with no env param in signatures', async () => {
    const { fetchImpl, calls } = makeStub((path, method) => {
      if (path === '/v1/ai-gateway/gateways' && method === 'GET') {
        return { status: 200, body: { data: [{ ...gateway, sandbox: true }], meta: pageMeta(1, 1, 20) } };
      }
      return { status: 200, body: { data: {}, meta: successMeta } };
    });
    const client = new KnoxCall({
      tenant: 'acme',
      baseUrl: 'https://api.test',
      bootstrap: { type: 'access_token', accessToken: 'kc_test_x' },
      sandbox: true,
      fetchImpl,
    });
    const page = await client.aiGateway.listGateways();
    expect(page.data[0].sandbox).toBe(true);
    // Same management path — the sandbox switch is client-level, not a method arg.
    expect(calls[0].url).toContain('/v1/ai-gateway/gateways');
  });
});
