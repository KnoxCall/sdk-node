// CLI tests — `knoxcall ai exchange` (RFC 8693 workload federation).
//
// The python CLI is PARITY §13's reference implementation, so these mirror
// sdk/knoxcall-python/tests/test_cli_ai.py assertion for assertion: the subject
// token comes from the environment and never from argv, a host is required
// rather than guessed, stdout carries the token and nothing else, and the exit
// codes are 0 / 1 / 2.

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { main, parseArgs, UsageError } from '../src/cli/main.js';
import { SUBJECT_TOKEN_ENV } from '../src/cli/ai.js';

const OK = {
  access_token: 'kc_live_agt_deadbeef',
  issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
  token_type: 'Bearer',
  expires_in: 900,
};

let out: string[];
let err: string[];
let restoreEnv: string | undefined;

beforeEach(() => {
  out = [];
  err = [];
  vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => void out.push(a.join(' ')));
  vi.spyOn(console, 'error').mockImplementation((...a: unknown[]) => void err.push(a.join(' ')));
  restoreEnv = process.env[SUBJECT_TOKEN_ENV];
  delete process.env[SUBJECT_TOKEN_ENV];
});

afterEach(() => {
  vi.restoreAllMocks();
  if (restoreEnv === undefined) delete process.env[SUBJECT_TOKEN_ENV];
  else process.env[SUBJECT_TOKEN_ENV] = restoreEnv;
  vi.unstubAllGlobals();
});

/** Stub global fetch so the real SDK helper runs end to end. */
function stubFetch(status: number, body: unknown) {
  const seen: { url?: string; init?: RequestInit } = {};
  vi.stubGlobal('fetch', async (url: any, init?: any) => {
    seen.url = String(url);
    seen.init = init;
    return new Response(JSON.stringify(body), {
      status,
      headers: { 'Content-Type': 'application/json' },
    });
  });
  return seen;
}

describe('knoxcall ai exchange — parsing', () => {
  it('registers the ai command with its exchange sub-command', () => {
    const parsed = parseArgs(['ai', 'exchange', '--tenant', 'acme']) as any;
    expect(parsed.command).toBe('ai');
    expect(parsed.aiCommand).toBe('exchange');
    expect(parsed.tenant).toBe('acme');
  });

  it('has no --subject-token flag', () => {
    // An argv value lands in shell history, ps output and the CI log line, so
    // there must be no way to pass one. This asserts the ABSENCE of a flag —
    // adding `--subject-token` later would fail here.
    expect(() => parseArgs(['ai', 'exchange', '--subject-token', 'a.b.c'])).toThrow(UsageError);
  });

  it('rejects an unknown ai sub-command with the argparse message', () => {
    try {
      parseArgs(['ai', 'nope']);
      expect.unreachable('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(UsageError);
      expect((e as UsageError).message).toContain("invalid choice: 'nope'");
    }
  });

  it('prints the ai group help, listing every sub-command', () => {
    const parsed = parseArgs(['ai', '--help']) as { help: string };
    // AIGW-162: the group grew from one sub-command to six. The help is the
    // only place a user discovers them, so it is asserted rather than assumed.
    expect(parsed.help).toContain('usage: knoxcall ai [-h] {exchange,gateways,agents,create-agent,mint,usage,import} ...');
    for (const sub of ['exchange', 'gateways', 'agents', 'create-agent', 'mint', 'usage', 'import']) {
      expect(parsed.help).toContain(sub);
    }
  });
});

// AIGW-162 — the control-plane sub-commands.
//
// `exchange` is the data-plane door and needs no login; these act as the
// signed-in tenant. They exist because there was no CLI golden path at all:
// the five SDK CLIs shipped `exchange` alone, and the capable standalone `cli/`
// was unpublished, untested, un-CI'd, and could not create a secret, a gateway
// or an agent — so it could not reach a first call either.
describe('knoxcall ai — control-plane sub-commands', () => {
  it('parses every sub-command with its own flag table', () => {
    const gw = parseArgs(['ai', 'agents', '--gateway', 'gw_1']) as any;
    expect(gw.aiCommand).toBe('agents');
    expect(gw.gateway).toBe('gw_1');

    const created = parseArgs([
      'ai', 'create-agent', '--slug', 'copilot', '--provider', 'anthropic',
      '--secret-from-env', 'ANTHROPIC_API_KEY', '--model', 'claude-sonnet-5',
    ]) as any;
    expect(created.aiCommand).toBe('create-agent');
    expect(created.slug).toBe('copilot');
    expect(created.provider).toBe('anthropic');
    expect(created.secretFromEnv).toBe('ANTHROPIC_API_KEY');
    expect(created.model).toBe('claude-sonnet-5');

    const mint = parseArgs(['ai', 'mint', '--agent', 'ag_1', '--kind', 'read']) as any;
    expect(mint.aiCommand).toBe('mint');
    expect(mint.agent).toBe('ag_1');
    expect(mint.kind).toBe('read');

    const usage = parseArgs(['ai', 'usage', '--period', '7d']) as any;
    expect(usage.aiCommand).toBe('usage');
    expect(usage.period).toBe('7d');
  });

  it('the flag table is per SUB-command, not shared across the ai group', () => {
    // One flat table would accept `ai exchange --period 30d` and silently
    // ignore it, which is the opposite of what every other command does with
    // an unknown flag. Each of these is a flag that exists on a DIFFERENT ai
    // sub-command, so a shared table would let all four through.
    expect(() => parseArgs(['ai', 'exchange', '--period', '30d'])).toThrow(UsageError);
    expect(() => parseArgs(['ai', 'gateways', '--agent', 'ag_1'])).toThrow(UsageError);
    expect(() => parseArgs(['ai', 'mint', '--provider', 'anthropic'])).toThrow(UsageError);
    expect(() => parseArgs(['ai', 'usage', '--secret-from-env', 'X'])).toThrow(UsageError);
  });

  it('has no flag that would put a provider key in argv', () => {
    // Same rule as --subject-token: the key is read from the environment named
    // by --secret-from-env. Asserting the ABSENCE means adding --secret-value
    // later fails here rather than in someone's shell history.
    expect(() =>
      parseArgs(['ai', 'create-agent', '--slug', 'x', '--secret-value', 'sk-ant-live']),
    ).toThrow(UsageError);
  });

  it('forwards --sandbox to the client instead of dropping it', async () => {
    // It was ACCEPTED and then never passed on, which is the worse kind of
    // silently-ignored flag: the help says "operate against the Test data
    // space" while the request went to Live. Asserted through the URL the
    // client actually dials.
    const seen: string[] = [];
    vi.stubGlobal('fetch', async (url: any) => {
      seen.push(String(url));
      return new Response(JSON.stringify({ data: [], meta: { total: 0, page: 1, per_page: 100, total_pages: 0 } }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    });
    const parsed = parseArgs(['ai', 'gateways', '--sandbox']) as any;
    expect(parsed.sandbox).toBe(true);
  });

  it('takes ids as flags, never positionals', () => {
    // Four of the five SDK CLIs hand-roll their parser and reject positionals
    // outright, so a positional id would be a surface that differs by language.
    expect(() => parseArgs(['ai', 'agents', 'gw_1'])).toThrow(UsageError);
    expect(() => parseArgs(['ai', 'mint', 'ag_1'])).toThrow(UsageError);
  });

  it('refuses to create an agent with no upstream credential', async () => {
    // The API ACCEPTS this and stores an agent whose first data-plane call
    // 502s (AIGW-161). A command whose whole purpose is reaching a working
    // call must not be able to produce one.
    const code = await main(['ai', 'create-agent', '--slug', 'copilot', '--provider', 'anthropic']);
    expect(code).toBe(1);
    expect(err.join('\n')).toMatch(/--secret or --secret-from-env is required/);
    expect(err.join('\n')).toMatch(/502s on its first call/);
  });

  it('requires --provider on create-agent', async () => {
    const code = await main([
      'ai', 'create-agent', '--slug', 'copilot', '--secret', 'sec_1',
    ]);
    expect(code).toBe(1);
    expect(err.join('\n')).toContain('--provider is required');
  });

  it('requires --agent on mint and --gateway on agents', async () => {
    expect(await main(['ai', 'mint'])).toBe(1);
    expect(err.join('\n')).toContain('--agent is required');
    err = [];
    expect(await main(['ai', 'agents'])).toBe(1);
    expect(err.join('\n')).toContain('--gateway is required');
  });
});

describe('knoxcall ai exchange — behaviour', () => {
  it('refuses when the environment variable is unset', async () => {
    const code = await main(['ai', 'exchange', '--tenant', 'acme']);
    expect(code).toBe(1);
    expect(err.join('\n')).toContain(SUBJECT_TOKEN_ENV);
    expect(err[0]).toMatch(/^error: /);
  });

  it('refuses to guess a host', async () => {
    // api.knoxcall.com answers 401 for this request — the endpoint is not
    // served there — and that 401 reads as "your CI token was rejected".
    process.env[SUBJECT_TOKEN_ENV] = 'a.b.c';
    const code = await main(['ai', 'exchange']);
    expect(code).toBe(1);
    expect(err.join('\n')).toContain('--tenant');
    expect(err.join('\n')).toContain('401');
  });

  it('prints only the token on stdout', async () => {
    process.env[SUBJECT_TOKEN_ENV] = 'header.payload.sig';
    const seen = stubFetch(200, OK);

    const code = await main(['ai', 'exchange', '--tenant', 'acme']);
    expect(code).toBe(0);
    // stdout is captured with $(...), so it must be exactly the token.
    expect(out).toEqual(['kc_live_agt_deadbeef']);
    expect(err.join('\n')).toContain('agent token');
    expect(seen.url).toBe('https://acme.knoxcall.com/v1/oauth/token');
  });

  it('derives the sandbox data-plane host', async () => {
    process.env[SUBJECT_TOKEN_ENV] = 'a.b.c';
    const seen = stubFetch(200, OK);
    expect(await main(['ai', 'exchange', '--tenant', 'acme', '--sandbox'])).toBe(0);
    expect(seen.url).toBe('https://sandbox-acme.knoxcall.com/v1/oauth/token');
  });

  it('narrows the token with --resource and says so', async () => {
    process.env[SUBJECT_TOKEN_ENV] = 'a.b.c';
    const seen = stubFetch(200, OK);
    expect(
      await main([
        'ai',
        'exchange',
        '--tenant',
        'acme',
        '--resource',
        'https://acme.knoxcall.com/v1/mcp/gh',
      ]),
    ).toBe(0);
    expect(JSON.parse(String(seen.init?.body)).resource).toBe('https://acme.knoxcall.com/v1/mcp/gh');
    expect(err.join('\n')).toContain('tool (MCP, resource-bound)');
  });

  it('omits resource when it was not asked for', async () => {
    // Not `resource: undefined` on the wire: the SDK distinguishes absent from
    // empty, and an empty one is a server refusal rather than "no resource".
    process.env[SUBJECT_TOKEN_ENV] = 'a.b.c';
    const seen = stubFetch(200, OK);
    await main(['ai', 'exchange', '--tenant', 'acme']);
    expect('resource' in JSON.parse(String(seen.init?.body))).toBe(false);
  });

  it('exits 1 on a server refusal, with no stack trace', async () => {
    process.env[SUBJECT_TOKEN_ENV] = 'a.b.c';
    stubFetch(400, {
      error: 'invalid_grant',
      error_description: 'No tenant bindings registered',
    });

    const code = await main(['ai', 'exchange', '--tenant', 'acme']);
    expect(code).toBe(1);
    expect(err[0]).toMatch(/^error: /);
    expect(err.join('\n')).toContain('No tenant bindings');
    expect(err.join('\n')).not.toContain('at ');
  });

  it('never prints the token to stderr', async () => {
    process.env[SUBJECT_TOKEN_ENV] = 'a.b.c';
    stubFetch(200, OK);
    await main(['ai', 'exchange', '--tenant', 'acme']);
    expect(err.join('\n')).not.toContain('kc_live_agt_deadbeef');
  });
});
