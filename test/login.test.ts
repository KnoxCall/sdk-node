// login() / ensureLogin() — the opt-in interactive-auth helpers. The
// underlying browser/device flow is exercised in cli.test.ts; here we cover the
// wrapper: stored-profile reuse (no prompt) and the interactive guard.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

import { KnoxCall, login, ensureLogin, NotAuthenticatedError, BootstrapError } from '../src/index.js';
import { writeProfile } from '../src/auth/credentials-file.js';

const ENV_VARS = [
  'KNOXCALL_TENANT',
  'KNOXCALL_ACCESS_TOKEN',
  'KNOXCALL_API_KEY',
  'KNOXCALL_CLIENT_ID',
  'KNOXCALL_CLIENT_SECRET',
  'KNOXCALL_CREDENTIALS_FILE',
  'KNOXCALL_PROFILE',
  'KNOXCALL_NO_INTERACTIVE',
  'CI',
] as const;

let saved: Record<string, string | undefined>;
let tempDir: string;
let credsPath: string;

beforeEach(() => {
  saved = {};
  for (const name of ENV_VARS) {
    saved[name] = process.env[name];
    delete process.env[name];
  }
  tempDir = mkdtempSync(join(tmpdir(), 'knoxcall-login-'));
  credsPath = join(tempDir, 'credentials.json');
  process.env.KNOXCALL_CREDENTIALS_FILE = credsPath;
});

afterEach(() => {
  for (const name of ENV_VARS) {
    if (saved[name] === undefined) delete process.env[name];
    else process.env[name] = saved[name];
  }
  rmSync(tempDir, { recursive: true, force: true });
});

describe('NotAuthenticatedError', () => {
  it('is a subclass of BootstrapError (existing catches still work)', () => {
    const e = new NotAuthenticatedError('nope');
    expect(e).toBeInstanceOf(BootstrapError);
    expect(e.name).toBe('NotAuthenticatedError');
  });
});

describe('ensureLogin', () => {
  it('returns a client seeded from a stored profile without prompting or network', async () => {
    writeProfile(credsPath, 'default', {
      tenant: 'acme',
      base_url: 'https://api.example.test',
      client_id: 'kc_cli_real',
      refresh_token: 'rt_1',
      access_token: 'kc_live_stored',
      access_token_expires_at: new Date(Date.now() + 3600_000).toISOString(),
      scope: '',
    });
    // No TTY in the test runner: if this tried to prompt, it would throw.
    const client = await ensureLogin();
    expect(client).toBeInstanceOf(KnoxCall);
    expect(client.tenant).toBe('acme');
    expect(client.baseUrl).toBe('https://api.example.test');
  });
});

describe('interactive guard', () => {
  it('login() refuses when KNOXCALL_NO_INTERACTIVE is set', async () => {
    process.env.KNOXCALL_NO_INTERACTIVE = '1';
    await expect(login()).rejects.toBeInstanceOf(NotAuthenticatedError);
  });

  it('ensureLogin() with no stored profile refuses in CI', async () => {
    process.env.CI = 'true';
    await expect(ensureLogin()).rejects.toBeInstanceOf(NotAuthenticatedError);
  });
});
