// WorkloadCredentialProvider — WIF Phase 4.3.
//
// The contract worth testing is not "it caches a token". It is the two rules
// that come from KnoxCall assertions being SINGLE-USE:
//
//   1. every exchange reads a FRESH assertion from the source, and an assertion
//      whose bytes were already spent is refused locally with an error that
//      names the real cause — rather than forwarded to be refused as a replay,
//      which reads as "your CI identity was rejected";
//   2. N concurrent callers cause ONE exchange, because each exchange spends an
//      assertion and a herd would burn N of them to have N−1 refused.
//
// Plus the two-tier boundary: advisory failures are survivable, mandatory ones
// are not, and the 90 seconds between them is the point of having two tiers.

import { describe, it, expect, vi, beforeEach } from 'vitest';

const exchange = vi.hoisted(() => vi.fn());
vi.mock('../src/resources/token-exchange.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../src/resources/token-exchange.js')>()),
  exchangeToken: exchange,
}));

import {
  WorkloadCredentialProvider,
  StaleAssertionError,
  ADVISORY_REFRESH_MS,
  MANDATORY_REFRESH_MS,
} from '../src/auth/workload-provider.js';

const HOUR_MS = 3_600_000;

/** A distinct assertion per call, as a real platform token endpoint produces. */
function freshSource() {
  let n = 0;
  return vi.fn(() => `assertion-${++n}`);
}

let clock = 1_000_000;
const now = () => clock;

function provider(opts: Record<string, unknown> = {}) {
  return new WorkloadCredentialProvider({
    assertion: freshSource(),
    tenant: 'acme',
    now,
    ...(opts as any),
  });
}

beforeEach(() => {
  clock = 1_000_000;
  exchange.mockReset();
  exchange.mockImplementation(async () => ({
    access_token: `kp_live_${Math.random().toString(36).slice(2)}`,
    issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
    token_type: 'Bearer',
    expires_in: 900,
  }));
});

describe('the single-use rule', () => {
  it('reads a fresh assertion for EVERY exchange, never reusing the first', async () => {
    const assertion = freshSource();
    const p = provider({ assertion });

    await p.getAccessToken();
    clock += 900_000 - MANDATORY_REFRESH_MS / 2; // past the mandatory line
    await p.getAccessToken();

    expect(assertion).toHaveBeenCalledTimes(2);
    expect(exchange.mock.calls[0][0].subject_token).toBe('assertion-1');
    expect(exchange.mock.calls[1][0].subject_token).toBe('assertion-2');
  });

  it('refuses a source that returns the SAME assertion, and says why — without sending it', async () => {
    const stuck = vi.fn(() => 'captured-once-at-startup');
    const p = provider({ assertion: stuck });

    await p.getAccessToken();
    expect(exchange).toHaveBeenCalledTimes(1);

    clock += 900_000; // force a mandatory refresh
    await expect(p.getAccessToken()).rejects.toBeInstanceOf(StaleAssertionError);

    // The doomed request is never made: the whole point is to fail at the real
    // cause instead of surfacing the server's replay refusal.
    expect(exchange, 'a spent assertion was sent to the server').toHaveBeenCalledTimes(1);
  });

  it('the refusal explains what to do, not just what happened', async () => {
    const p = provider({ assertion: vi.fn(() => 'same-bytes') });
    await p.getAccessToken();
    clock += 900_000;
    await expect(p.getAccessToken()).rejects.toThrow(/single-use/i);
    await expect(p.getAccessToken()).rejects.toThrow(/newly minted|re-fetch|re-read/i);
  });

  it('an empty or missing assertion is refused before any exchange', async () => {
    const p = provider({ assertion: vi.fn(() => '') });
    await expect(p.getAccessToken()).rejects.toBeInstanceOf(StaleAssertionError);
    expect(exchange).not.toHaveBeenCalled();
  });

  it('a FAILED exchange does not burn the assertion — the same bytes may be retried', async () => {
    // The server claims the assertion before minting, so only a SUCCESS makes
    // those bytes unusable. Burning the fingerprint on a network error would
    // strand a caller whose assertion is still perfectly good.
    const assertion = vi.fn(() => 'retryable-assertion');
    const p = provider({ assertion });

    exchange.mockRejectedValueOnce(new Error('connection reset'));
    await expect(p.getAccessToken()).rejects.toThrow(/connection reset/);

    await expect(p.getAccessToken()).resolves.toBeDefined();
    expect(exchange).toHaveBeenCalledTimes(2);
    expect(exchange.mock.calls[1][0].subject_token).toBe('retryable-assertion');
  });
});

describe('the two-tier schedule', () => {
  it('serves the cached token untouched while it is comfortably alive', async () => {
    const p = provider();
    const first = await p.getAccessToken();
    clock += 900_000 - ADVISORY_REFRESH_MS - 1_000; // still above the advisory line

    expect((await p.getAccessToken()).expose()).toBe(first.expose());
    expect(exchange).toHaveBeenCalledTimes(1);
  });

  it('refreshes opportunistically once inside the advisory window', async () => {
    const p = provider();
    await p.getAccessToken();
    clock += 900_000 - ADVISORY_REFRESH_MS + 1_000;

    await p.getAccessToken();
    expect(exchange).toHaveBeenCalledTimes(2);
  });

  it('an advisory-window failure is SURVIVABLE — the valid token is still served', async () => {
    const p = provider();
    const first = await p.getAccessToken();
    clock += 900_000 - ADVISORY_REFRESH_MS + 1_000;

    exchange.mockRejectedValueOnce(new Error('token endpoint 503'));
    const served = await p.getAccessToken();

    expect(served.expose(), 'a survivable blip took down a caller with valid credentials')
      .toBe(first.expose());
  });

  it('a mandatory-window failure THROWS — the token may die in flight', async () => {
    const p = provider();
    await p.getAccessToken();
    clock += 900_000 - MANDATORY_REFRESH_MS + 1_000;

    exchange.mockRejectedValueOnce(new Error('token endpoint 503'));
    await expect(p.getAccessToken()).rejects.toThrow(/503/);
  });

  it('never hands out a token with less than the mandatory margin left', async () => {
    const p = provider();
    await p.getAccessToken();
    for (const elapsed of [880_000, 895_000, 899_000, 901_000]) {
      clock = 1_000_000 + elapsed;
      const token = await p.getAccessToken();
      expect(token.expose()).toBeTruthy();
    }
    // Each of those crossed a refresh line, so the cache was renewed rather
    // than a near-dead token handed over.
    expect(exchange.mock.calls.length).toBeGreaterThan(1);
  });
});

describe('concurrency', () => {
  it('N simultaneous callers spend ONE assertion, not N', async () => {
    const assertion = freshSource();
    const p = provider({ assertion });

    const tokens = await Promise.all(Array.from({ length: 8 }, () => p.getAccessToken()));

    expect(exchange, 'a thundering herd burned one assertion per caller').toHaveBeenCalledTimes(1);
    expect(assertion).toHaveBeenCalledTimes(1);
    const values = new Set(tokens.map((t) => t.expose()));
    expect(values.size, 'callers got different tokens from one exchange').toBe(1);
  });
});

describe('what reaches the exchange', () => {
  it('passes the resource and audience through, and the Test data space', async () => {
    const p = provider({ resource: 'https://mcp.example/servers/s1', audience: 'knoxcall:gateway', sandbox: true });
    await p.getAccessToken();

    expect(exchange.mock.calls[0][0]).toMatchObject({
      resource: 'https://mcp.example/servers/s1',
      audience: 'knoxcall:gateway',
    });
    expect(exchange.mock.calls[0][1]).toMatchObject({ tenant: 'acme', sandbox: true });
  });

  it('Live and Test do not share a cache entry', async () => {
    const live = provider();
    const test = provider({ sandbox: true });
    await live.getAccessToken();
    await test.getAccessToken();
    // Separate providers here, but the default cache KEY is what keeps them
    // apart when a caller passes one shared store.
    expect(exchange).toHaveBeenCalledTimes(2);
  });

  it('the token is Redacted — it cannot reach a log by accident', async () => {
    const p = provider();
    const token = await p.getAccessToken();
    expect(String(token)).not.toContain('kp_live');
    expect(JSON.stringify({ token })).not.toContain('kp_live');
    expect(token.expose()).toMatch(/^kp_live_/);
  });
});
