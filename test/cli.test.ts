// CLI tests — `knoxcall login/logout/whoami` (PKCE, loopback, device flow).
// Mirrors knoxcall-python/tests/test_cli.py (PARITY §13).
//
// All token-endpoint HTTP is stubbed (injected fetchImpl); the loopback
// callback server binds 127.0.0.1:0 and is driven with real fetch.
// Credentials files live under a per-test temp dir only
// (KNOXCALL_CREDENTIALS_FILE pinned in beforeEach).

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { formatExpiry, readProfile, writeProfile } from '../src/auth/credentials-file.js';
import { CLIError, persistLogin } from '../src/cli/common.js';
import {
  LoopbackServer,
  authCodeFlow,
  buildAuthorizeUrl,
  generatePkcePair,
  pollDeviceToken,
  runLogin,
} from '../src/cli/login.js';
import { runLogout } from '../src/cli/logout.js';
import { runWhoami } from '../src/cli/whoami.js';
import { runInit } from '../src/cli/init.js';
import { main, parseArgs, type ParseResult } from '../src/cli/main.js';

const ENV_VARS = [
  'KNOXCALL_TENANT',
  'KNOXCALL_ENVIRONMENT',
  'KNOXCALL_BASE_URL',
  'KNOXCALL_PROXY_BASE_URL',
  'KNOXCALL_ACCESS_TOKEN',
  'KNOXCALL_API_KEY',
  'KNOXCALL_CLIENT_ID',
  'KNOXCALL_CLIENT_SECRET',
  'KNOXCALL_CREDENTIALS_FILE',
  'KNOXCALL_PROFILE',
] as const;

const BASE = 'https://api.example.test';

let savedEnv: Record<string, string | undefined>;
let tempDir: string;
let credsPath: string;
let logLines: string[];
let errLines: string[];

beforeEach(() => {
  savedEnv = {};
  for (const name of ENV_VARS) {
    savedEnv[name] = process.env[name];
    delete process.env[name];
  }
  tempDir = mkdtempSync(join(tmpdir(), 'knoxcall-cli-'));
  credsPath = join(tempDir, 'credentials.json');
  // Never let the CLI read or write a real ~/.knoxcall file.
  process.env.KNOXCALL_CREDENTIALS_FILE = credsPath;

  logLines = [];
  errLines = [];
  vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
    logLines.push(args.map(String).join(' '));
  });
  vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
    errLines.push(args.map(String).join(' '));
  });
});

afterEach(() => {
  vi.restoreAllMocks();
  for (const name of ENV_VARS) {
    if (savedEnv[name] === undefined) delete process.env[name];
    else process.env[name] = savedEnv[name];
  }
  rmSync(tempDir, { recursive: true, force: true });
});

const stdout = () => logLines.join('\n');
const stderr = () => errLines.join('\n');

interface SeenForm {
  url: string;
  path: string;
  form: URLSearchParams;
}

function stubFetch(
  handler: (req: SeenForm) => Response | Promise<Response>,
): typeof fetch {
  return (async (input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const form = new URLSearchParams(typeof init?.body === 'string' ? init.body : '');
    return handler({ url, path: new URL(url).pathname, form });
  }) as typeof fetch;
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function parseLogin(argv: string[]) {
  const parsed: ParseResult = parseArgs(argv);
  if ('help' in parsed || parsed.command !== 'login') throw new Error('expected login args');
  return parsed;
}

function parseProfileCmd(argv: string[]) {
  const parsed: ParseResult = parseArgs(argv);
  if ('help' in parsed || parsed.command === 'login') throw new Error('expected logout/whoami args');
  return parsed;
}

// ── PKCE ─────────────────────────────────────────────────────────────────────

describe('PKCE', () => {
  it('generates an S256, urlsafe verifier/challenge pair', () => {
    const { verifier, challenge } = generatePkcePair();
    expect(verifier.length).toBeGreaterThanOrEqual(43); // RFC 7636 §4.1
    expect(verifier.length).toBeLessThanOrEqual(128);
    expect(verifier).toMatch(/^[A-Za-z0-9\-_]+$/);
    const expected = createHash('sha256').update(verifier, 'ascii').digest('base64url');
    expect(challenge).toBe(expected);
    expect(challenge).not.toContain('=');
    // fresh entropy per call
    expect(generatePkcePair().verifier).not.toBe(verifier);
  });

  it('builds the authorize URL with the cli alias and S256', () => {
    const url = buildAuthorizeUrl(BASE, {
      redirectUri: 'http://127.0.0.1:51234/callback',
      state: 'st_1',
      codeChallenge: 'chal',
      tenant: 'acme',
    });
    expect(url.startsWith(`${BASE}/oauth/authorize?`)).toBe(true);
    const query = new URL(url).searchParams;
    expect(query.get('client_id')).toBe('knoxcall-cli');
    expect(query.get('response_type')).toBe('code');
    expect(query.get('code_challenge_method')).toBe('S256');
    expect(query.get('redirect_uri')).toBe('http://127.0.0.1:51234/callback');
    expect(query.get('state')).toBe('st_1');
    expect(query.get('tenant')).toBe('acme');
  });
});

// ── Loopback callback server ─────────────────────────────────────────────────

describe('loopback callback server', () => {
  it('returns the code on a matching-state callback', async () => {
    const server = await LoopbackServer.start();
    try {
      const hit = fetch(`http://127.0.0.1:${server.port}/callback?code=abc123&state=st1`);
      const code = await server.waitForCode({ expectedState: 'st1', timeoutMs: 5000 });
      await hit.catch(() => {});
      expect(code).toBe('abc123');
    } finally {
      await server.close();
    }
  });

  it('surfaces the error param as a CLIError', async () => {
    const server = await LoopbackServer.start();
    try {
      const hit = fetch(
        `http://127.0.0.1:${server.port}/callback?error=access_denied&error_description=nope&state=st1`,
      );
      await expect(
        server.waitForCode({ expectedState: 'st1', timeoutMs: 5000 }),
      ).rejects.toThrowError(/nope/);
      await hit.catch(() => {});
    } finally {
      await server.close();
    }
  });

  it('rejects a state mismatch', async () => {
    const server = await LoopbackServer.start();
    try {
      const hit = fetch(`http://127.0.0.1:${server.port}/callback?code=abc123&state=EVIL`);
      await expect(
        server.waitForCode({ expectedState: 'st1', timeoutMs: 5000 }),
      ).rejects.toThrowError(/state/i);
      await hit.catch(() => {});
    } finally {
      await server.close();
    }
  });
});

// ── Auth-code flow end-to-end (fake browser, stubbed token endpoint) ─────────

describe('auth-code flow', () => {
  it('exchanges the code with the PKCE verifier and never prints the token', async () => {
    const exchanged: string[] = [];
    const fetchImpl = stubFetch((req) => {
      expect(req.path).toBe('/oauth/token');
      exchanged.push(req.form.toString());
      return json(200, {
        access_token: 'kc_ac',
        refresh_token: 'rt_ac',
        token_type: 'Bearer',
        expires_in: 3600,
        tenant: 'acme',
        client_id: 'kc_cli_real',
      });
    });

    let browserHit: Promise<unknown> = Promise.resolve();
    const fakeBrowser = (url: string) => {
      const query = new URL(url).searchParams;
      expect(query.get('client_id')).toBe('knoxcall-cli');
      const redirect = query.get('redirect_uri')!;
      const state = query.get('state')!;
      browserHit = fetch(`${redirect}?code=authcode1&state=${encodeURIComponent(state)}`).catch(
        () => {},
      );
    };

    const body = await authCodeFlow(BASE, {
      fetchImpl,
      openBrowser: fakeBrowser,
      timeoutMs: 10_000,
    });
    await browserHit;

    expect(body.access_token).toBe('kc_ac');
    const form = new URLSearchParams(exchanged[0]);
    expect(form.get('grant_type')).toBe('authorization_code');
    expect(form.get('code')).toBe('authcode1');
    expect(form.get('code_verifier')).toBeTruthy();
    expect(form.get('client_id')).toBe('knoxcall-cli');
    // the token never hits stdout
    expect(stdout()).not.toContain('kc_ac');
    // the URL is always printed (never rely on the browser opening)
    expect(stdout()).toContain('/oauth/authorize?');
  });
});

// ── Device flow polling ──────────────────────────────────────────────────────

describe('device flow polling', () => {
  it('honors interval and slow_down, sleeping before the first poll', async () => {
    const responses: Array<[number, unknown]> = [
      [400, { error: 'authorization_pending' }],
      [400, { error: 'slow_down' }],
      [400, { error: 'authorization_pending' }],
      [200, { access_token: 'kc_dev', refresh_token: 'rt', expires_in: 3600 }],
    ];
    const calls: string[] = [];
    const fetchImpl = stubFetch((req) => {
      const [status, body] = responses[calls.length];
      calls.push(req.form.toString());
      return json(status, body);
    });

    const sleeps: number[] = [];
    const body = await pollDeviceToken(BASE, 'dev_code_1', {
      interval: 5,
      expiresIn: 900,
      fetchImpl,
      sleep: (s) => {
        sleeps.push(s);
      },
    });

    expect(body.access_token).toBe('kc_dev');
    // 5s until slow_down, then bumped by +5 per RFC 8628 §3.5
    expect(sleeps).toEqual([5, 5, 10, 10]);
    for (const c of calls) {
      expect(c).toContain('device_code=dev_code_1');
    }
    expect(new URLSearchParams(calls[0]).get('grant_type')).toBe(
      'urn:ietf:params:oauth:grant-type:device_code',
    );
  });

  it.each([
    ['access_denied', /denied/],
    ['expired_token', /knoxcall login/],
  ])('stops on %s', async (error, fragment) => {
    const fetchImpl = stubFetch(() => json(400, { error }));
    await expect(
      pollDeviceToken(BASE, 'dev_code_1', { fetchImpl, sleep: () => {} }),
    ).rejects.toThrowError(fragment);
  });
});

// ── Profile write / merge / persist ──────────────────────────────────────────

describe('profile persistence', () => {
  it('writes and merges profiles without touching siblings', () => {
    writeProfile(credsPath, 'default', { tenant: 'acme', refresh_token: 'rt1' });
    writeProfile(credsPath, 'work', { tenant: 'globex', refresh_token: 'rt2' });

    const doc = JSON.parse(readFileSync(credsPath, 'utf8'));
    expect(doc.version).toBe(1);
    expect(Object.keys(doc.profiles).sort()).toEqual(['default', 'work']);

    // overwriting one profile leaves the other intact
    writeProfile(credsPath, 'default', { tenant: 'acme', refresh_token: 'rt3' });
    expect(readProfile(credsPath, 'default')!.refresh_token).toBe('rt3');
    expect(readProfile(credsPath, 'work')!.refresh_token).toBe('rt2');
  });

  it('persistLogin records the extension members under the lock', async () => {
    await persistLogin({
      path: credsPath,
      profile: 'default',
      baseUrl: BASE,
      tokenBody: {
        access_token: 'kc_a',
        refresh_token: 'rt_a',
        expires_in: 3600,
        scope: 'routes:read',
        tenant: 'acme',
        client_id: 'kc_cli_real', // extension member: real per-tenant client
      },
    });
    const onDisk = readProfile(credsPath, 'default')!;
    expect(onDisk.client_id).toBe('kc_cli_real');
    expect(onDisk.tenant).toBe('acme');
    expect(onDisk.base_url).toBe(BASE);
    expect(onDisk.refresh_token).toBe('rt_a');
    expect(String(onDisk.access_token_expires_at)).toMatch(/Z$/);
    // the file lock was released
    expect(existsSync(`${credsPath}.lock`)).toBe(false);
  });
});

// ── login command (device path, fully stubbed) ───────────────────────────────

function deviceLoginFetch(): typeof fetch {
  return stubFetch((req) => {
    if (req.path === '/oauth/device_authorization') {
      expect(req.form.get('client_id')).toBe('knoxcall-cli');
      return json(200, {
        device_code: 'dc1',
        user_code: 'ABCD-EFGH',
        verification_uri: `${BASE}/oauth/activate`,
        verification_uri_complete: `${BASE}/oauth/activate?user_code=ABCD-EFGH`,
        expires_in: 900,
        interval: 5,
      });
    }
    return json(200, {
      access_token: 'kc_dev',
      refresh_token: 'rt_dev',
      token_type: 'Bearer',
      expires_in: 3600,
      scope: 'routes:read',
      tenant: 'acme',
      client_id: 'kc_cli_real',
    });
  });
}

describe('login command', () => {
  it.each(['--device', '--no-browser'])('%s runs the device flow and writes the profile', async (flag) => {
    const args = parseLogin(['login', flag, '--base-url', BASE]);
    const rc = await runLogin(args, { fetchImpl: deviceLoginFetch(), sleep: () => {} });
    expect(rc).toBe(0);

    const record = readProfile(credsPath, 'default')!;
    expect(record.client_id).toBe('kc_cli_real');
    expect(record.refresh_token).toBe('rt_dev');
    expect(record.tenant).toBe('acme');
    expect(record.base_url).toBe(BASE);

    const out = stdout();
    expect(out).toContain('ABCD-EFGH'); // user code shown prominently
    expect(out).toContain('acme');
    expect(out).not.toContain('kc_dev'); // tokens never printed
    expect(out).not.toContain('rt_dev');
  });

  it('respects the --profile flag', async () => {
    const args = parseLogin(['login', '--device', '--base-url', BASE, '--profile', 'staging']);
    expect(await runLogin(args, { fetchImpl: deviceLoginFetch(), sleep: () => {} })).toBe(0);
    expect(readProfile(credsPath, 'staging')!.access_token).toBe('kc_dev');
    expect(readProfile(credsPath, 'default')).toBeNull();
  });
});

// ── logout ───────────────────────────────────────────────────────────────────

function seedProfiles(): void {
  for (const [name, rt] of [
    ['default', 'rt_default'],
    ['work', 'rt_work'],
  ] as const) {
    writeProfile(credsPath, name, {
      tenant: 'acme',
      base_url: BASE,
      client_id: 'kc_cli_real',
      refresh_token: rt,
      access_token: 'kc_x',
      access_token_expires_at: formatExpiry(Date.now() + 3600 * 1000),
    });
  }
}

describe('logout command', () => {
  it('revokes the refresh token, removes the profile, and deletes the file when last', async () => {
    seedProfiles();
    const seen: Array<[string, string]> = [];
    const fetchImpl = stubFetch((req) => {
      seen.push([req.path, req.form.toString()]);
      return json(200, {});
    });

    const rc = await runLogout(parseProfileCmd(['logout', '--profile', 'work']), { fetchImpl });
    expect(rc).toBe(0);
    expect(seen[0][0]).toBe('/oauth/revoke');
    const form = new URLSearchParams(seen[0][1]);
    expect(form.get('token')).toBe('rt_work');
    expect(form.get('token_type_hint')).toBe('refresh_token');
    expect(form.get('client_id')).toBe('kc_cli_real');
    expect(readProfile(credsPath, 'work')).toBeNull();
    expect(readProfile(credsPath, 'default')).not.toBeNull(); // other profile kept

    // removing the last profile deletes the file
    expect(await runLogout(parseProfileCmd(['logout']), { fetchImpl })).toBe(0);
    expect(existsSync(credsPath)).toBe(false);
  });

  it('removes the profile even when the revoke endpoint is unreachable', async () => {
    seedProfiles();
    const fetchImpl = stubFetch(() => {
      throw new Error('server unreachable');
    });
    expect(await runLogout(parseProfileCmd(['logout', '--profile', 'work']), { fetchImpl })).toBe(0);
    expect(readProfile(credsPath, 'work')).toBeNull();
  });

  it('is a noop without stored credentials', async () => {
    expect(await runLogout(parseProfileCmd(['logout']))).toBe(0);
    expect(stdout()).toContain('nothing to do');
  });
});

// ── whoami ───────────────────────────────────────────────────────────────────

describe('whoami command', () => {
  it('reports the tenant via the SDK client without printing tokens', async () => {
    seedProfiles();
    const fetchImpl = stubFetch((req) => {
      expect(req.path).toBe('/v1/account');
      return json(200, {
        data: {
          id: '4a2f6b7e-0000-0000-0000-000000000000',
          slug: 'acme',
          name: 'Acme Inc',
          subscription_plan: 'scale',
        },
        meta: { request_id: 'req_1' },
      });
    });
    const rc = await runWhoami(parseProfileCmd(['whoami']), { fetchImpl });
    expect(rc).toBe(0);
    const out = stdout();
    expect(out).toContain('Tenant: Acme Inc');
    expect(out).toContain('Slug:   acme');
    expect(out).toContain('Plan:   scale');
    expect(out).toContain(`Profile: default (${credsPath})`);
    expect(out).not.toContain('kc_x'); // stored access token never printed
  });

  it('errors with a re-login hint when not logged in', async () => {
    await expect(runWhoami(parseProfileCmd(['whoami']))).rejects.toThrowError(CLIError);
    await expect(runWhoami(parseProfileCmd(['whoami']))).rejects.toThrowError(/knoxcall login/);
  });
});

describe('init command', () => {
  it('scaffold mode prints the wrap quickstart and makes no writes', async () => {
    seedProfiles();
    const paths: string[] = [];
    const fetchImpl = stubFetch((req) => {
      paths.push(req.path);
      return json(200, { data: { slug: 'acme', name: 'Acme Inc' }, meta: {} });
    });
    const rc = await runInit({}, { fetchImpl });
    expect(rc).toBe(0);
    const out = stdout();
    expect(out).toContain('Signed in as Acme Inc');
    expect(out).toContain('Wrap a provider SDK through KnoxCall');
    expect(out).toContain('knoxcall init --provider stripe');
    expect(paths).not.toContain('/v1/wrap/credentials'); // scaffold writes nothing
  });

  it('escrow mode moves the key into custody and prints the base_url', async () => {
    seedProfiles();
    const paths: string[] = [];
    const fetchImpl = stubFetch((req) => {
      paths.push(req.path);
      if (req.path === '/v1/wrap/credentials') {
        return json(200, { data: { secret_id: 'sec_1', name: 'wrap-stripe', provider: 'stripe', allowed_hosts: ['api.stripe.com'], sandbox: false }, meta: {} });
      }
      if (req.path === '/v1/wrap/tokens') {
        return json(200, { data: { id: 'tok_1', token: 'wkt_x', base_url: 'https://api.knoxcall.com/wg/wkt_x/api.stripe.com', base_url_style: 'path', host: 'api.stripe.com', secret_id: 'sec_1', sandbox: false, expires_at: null }, meta: {} });
      }
      return json(200, { data: { slug: 'acme', name: 'Acme Inc' }, meta: {} });
    });
    const rc = await runInit(
      { provider: 'stripe', secretName: 'wrap-stripe', host: 'api.stripe.com' },
      { fetchImpl, env: { KNOXCALL_WRAP_SECRET: 'sk_live_SECRET' } },
    );
    expect(rc).toBe(0);
    expect(paths).toContain('/v1/wrap/credentials');
    expect(paths).toContain('/v1/wrap/tokens');
    const out = stdout();
    expect(out).toContain('in KnoxCall custody');
    expect(out).toContain('https://api.knoxcall.com/wg/wkt_x/api.stripe.com');
    expect(out).not.toContain('sk_live_SECRET'); // the raw provider key is never printed
  });

  it('escrow mode requires the key in KNOXCALL_WRAP_SECRET (never a flag)', async () => {
    seedProfiles();
    const fetchImpl = stubFetch(() => json(200, { data: { slug: 'acme', name: 'Acme Inc' }, meta: {} }));
    await expect(
      runInit({ provider: 'stripe', secretName: 'wrap-stripe', host: 'api.stripe.com' }, { fetchImpl, env: {} }),
    ).rejects.toThrowError(/KNOXCALL_WRAP_SECRET/);
  });

  it('errors with a re-login hint when not logged in', async () => {
    await expect(runInit({})).rejects.toThrowError(/knoxcall login/);
  });
});

// ── main() dispatch, exit codes, help ────────────────────────────────────────

describe('main()', () => {
  it('prints a human error to stderr and exits 1', async () => {
    const rc = await main(['whoami']); // no stored credentials in the isolated env
    expect(rc).toBe(1);
    expect(stderr()).toMatch(/^error: /);
    expect(stderr()).toContain('knoxcall login');
    expect(stderr()).not.toContain('    at '); // no stack trace
  });

  it('logout without credentials exits 0', async () => {
    expect(await main(['logout'])).toBe(0);
  });

  it('--help prints usage and exits 0', async () => {
    expect(await main(['--help'])).toBe(0);
    expect(stdout()).toContain('usage: knoxcall');
    expect(stdout()).toContain('{login,logout,whoami,init,ai}');
  });

  it('login --help prints the login options and exits 0', async () => {
    expect(await main(['login', '--help'])).toBe(0);
    expect(stdout()).toContain('--no-browser');
    expect(stdout()).toContain('--sandbox');
  });

  it('usage errors exit 2 with argparse-style messages', async () => {
    expect(await main([])).toBe(2);
    expect(stderr()).toContain('the following arguments are required: {login,logout,whoami,init,ai}');

    errLines = [];
    expect(await main(['bogus'])).toBe(2);
    expect(stderr()).toContain("invalid choice: 'bogus'");

    errLines = [];
    expect(await main(['login', '--bogus'])).toBe(2);
    expect(stderr()).toContain('unrecognized arguments: --bogus');

    errLines = [];
    expect(await main(['login', '--tenant'])).toBe(2);
    expect(stderr()).toContain('argument --tenant: expected one argument');
  });
});
