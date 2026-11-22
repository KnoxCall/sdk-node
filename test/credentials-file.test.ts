// Credentials-file provider tests — StoredCredentials bootstrap (PARITY §2/§10).
// Mirrors knoxcall-python/tests/test_credentials_file.py.
//
// Every test points KNOXCALL_CREDENTIALS_FILE at a per-test temp dir so the
// real ~/.knoxcall is never touched (or even read).

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { inspect } from 'util';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, utimesSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

import {
  KnoxCall,
  AccessToken,
  ClientCredentials,
  StoredCredentials,
  AuthenticationError,
  KnoxCallError,
} from '../src/index.js';
import { autoDetectBootstrap } from '../src/auth/bootstrap.js';
import {
  CredentialsFileLock,
  formatExpiry,
  readProfile,
  writeProfile,
} from '../src/auth/credentials-file.js';
import { fetchToken } from '../src/auth/oauth.js';
import type { CachedToken, TokenStore } from '../src/auth/token-store.js';

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
  // Cloud OIDC providers — must not fire on CI machines during chain tests.
  'ACTIONS_ID_TOKEN_REQUEST_URL',
  'ACTIONS_ID_TOKEN_REQUEST_TOKEN',
  'AWS_WEB_IDENTITY_TOKEN_FILE',
  'IDENTITY_ENDPOINT',
  'IDENTITY_HEADER',
  'VERCEL_OIDC_TOKEN',
  'CIRCLE_OIDC_TOKEN_V2',
  'BUILDKITE_OIDC_TOKEN',
] as const;

const TOKEN_ENDPOINT = 'https://api.example.test/oauth/token';

let savedEnv: Record<string, string | undefined>;
let tempDir: string;
let credsPath: string;

beforeEach(() => {
  savedEnv = {};
  for (const name of ENV_VARS) {
    savedEnv[name] = process.env[name];
    delete process.env[name];
  }
  tempDir = mkdtempSync(join(tmpdir(), 'knoxcall-creds-'));
  credsPath = join(tempDir, 'credentials.json');
  // Never let the chain or the provider read a real ~/.knoxcall file.
  process.env.KNOXCALL_CREDENTIALS_FILE = credsPath;
});

afterEach(() => {
  for (const name of ENV_VARS) {
    if (savedEnv[name] === undefined) delete process.env[name];
    else process.env[name] = savedEnv[name];
  }
  rmSync(tempDir, { recursive: true, force: true });
});

function writeCreds(
  path: string,
  overrides: Partial<{
    profile: string;
    tenant: string;
    base_url: string;
    access_token: string;
    refresh_token: string;
    expiresInSec: number;
    client_id: string;
    scope: string;
  }> = {},
): string {
  const { profile = 'default', expiresInSec = 3600, ...rest } = overrides;
  writeProfile(path, profile, {
    tenant: 'acme',
    base_url: 'https://api.example.test',
    client_id: 'kc_cli_real',
    refresh_token: 'rt_1',
    access_token: 'kc_stored_fresh',
    access_token_expires_at: formatExpiry(Date.now() + expiresInSec * 1000),
    scope: 'routes:read',
    ...rest,
  });
  return path;
}

interface SeenRequest {
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: string;
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function stubFetch(handler: (req: SeenRequest) => Response | Promise<Response>): typeof fetch {
  return async (input, init) => {
    const url = typeof input === 'string' ? input : (input as Request).url;
    const headers: Record<string, string> = {};
    if (init?.headers) {
      const h = init.headers as Record<string, string>;
      for (const k of Object.keys(h)) headers[k.toLowerCase()] = h[k];
    }
    return handler({
      url,
      method: init?.method ?? 'GET',
      headers,
      body: typeof init?.body === 'string' ? init.body : undefined,
    });
  };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// ── Auto-detect chain position (slot 2) ───────────────────────────────────────

describe('auto-detect chain (slot 2)', () => {
  it('picks up the credentials file', async () => {
    writeCreds(credsPath);
    expect(await autoDetectBootstrap()).toBeInstanceOf(StoredCredentials);
  });

  it('env access token beats the file', async () => {
    writeCreds(credsPath);
    process.env.KNOXCALL_ACCESS_TOKEN = 'kc_env_token';
    expect(await autoDetectBootstrap()).toBeInstanceOf(AccessToken);
  });

  it('file beats env client-credentials', async () => {
    writeCreds(credsPath);
    process.env.KNOXCALL_CLIENT_ID = 'tk_env';
    process.env.KNOXCALL_CLIENT_SECRET = 'sec';
    expect(await autoDetectBootstrap()).toBeInstanceOf(StoredCredentials);
  });

  it('file beats cloud OIDC providers', async () => {
    writeCreds(credsPath);
    process.env.VERCEL_OIDC_TOKEN = 'vercel-oidc';
    expect(await autoDetectBootstrap()).toBeInstanceOf(StoredCredentials);
  });

  it('missing file skips the provider silently', async () => {
    // credsPath was never written
    process.env.KNOXCALL_CLIENT_ID = 'tk_env';
    process.env.KNOXCALL_CLIENT_SECRET = 'sec';
    expect(await autoDetectBootstrap()).toBeInstanceOf(ClientCredentials);
  });

  it('missing profile skips the provider silently', async () => {
    writeCreds(credsPath); // only "default" exists
    process.env.KNOXCALL_PROFILE = 'work';
    process.env.KNOXCALL_CLIENT_ID = 'tk_env';
    process.env.KNOXCALL_CLIENT_SECRET = 'sec';
    expect(await autoDetectBootstrap()).toBeInstanceOf(ClientCredentials);
  });

  it('malformed file skips the provider, chain continues (no crash)', async () => {
    writeFileSync(credsPath, '{this is not json', 'utf8');
    process.env.KNOXCALL_CLIENT_ID = 'tk_env';
    process.env.KNOXCALL_CLIENT_SECRET = 'sec';
    expect(await autoDetectBootstrap()).toBeInstanceOf(ClientCredentials);
  });
});

// ── Fresh-token fast path ─────────────────────────────────────────────────────

describe('fresh-token fast path', () => {
  it('uses the stored access token with zero HTTP, redacted', async () => {
    writeCreds(credsPath, { expiresInSec: 3600 });
    const calls: string[] = [];
    const fetchImpl = stubFetch((req) => {
      calls.push(req.url);
      return json(500, {});
    });

    const token = await fetchToken({
      tokenEndpoint: TOKEN_ENDPOINT,
      bootstrap: new StoredCredentials(),
      fetchImpl,
    });

    expect(token.accessToken.expose()).toBe('kc_stored_fresh');
    expect(token.tenant).toBe('acme');
    expect(token.scope).toEqual(['routes:read']);
    expect(calls).toEqual([]); // no HTTP at all on the fast path
    // The file is the sole refresh authority — no in-process refresh token
    // means the stale-fallback can never replay a rotated (consumed) token.
    expect(token.refreshToken).toBeUndefined();
    // tokens are redacted in debug output (PARITY §3)
    expect(inspect(token)).not.toContain('kc_stored_fresh');
    expect(String(token.accessToken)).toBe('[REDACTED]');
  });
});

// ── Refresh + rotated write-back ──────────────────────────────────────────────

describe('refresh + rotated write-back', () => {
  it('refreshes an expired token and atomically writes back the rotated refresh token', async () => {
    writeCreds(credsPath, {
      access_token: 'kc_old',
      refresh_token: 'rt_old',
      expiresInSec: 10, // inside the 60s freshness window → must refresh
    });
    const seen: SeenRequest[] = [];
    const fetchImpl = stubFetch((req) => {
      seen.push(req);
      return json(200, {
        access_token: 'kc_new',
        refresh_token: 'rt_new',
        token_type: 'Bearer',
        expires_in: 3600,
        scope: 'routes:read secrets:read',
        tenant: 'acme',
        client_id: 'kc_cli_real',
      });
    });

    const token = await fetchToken({
      tokenEndpoint: TOKEN_ENDPOINT,
      bootstrap: new StoredCredentials(),
      fetchImpl,
    });

    expect(token.accessToken.expose()).toBe('kc_new');
    expect(token.refreshToken).toBeUndefined(); // the file holds it, never the process
    expect(seen).toHaveLength(1);
    expect(seen[0].url).toBe(TOKEN_ENDPOINT);
    const form = seen[0].body!;
    expect(form).toContain('grant_type=refresh_token');
    expect(form).toContain('refresh_token=rt_old');
    expect(form).toContain('client_id=kc_cli_real'); // the REAL client id, not the alias
    expect(form).not.toContain('client_secret'); // public client — no secret
    expect(seen[0].headers['authorization']).toBeUndefined();

    const onDisk = readProfile(credsPath, 'default')!;
    expect(onDisk.refresh_token).toBe('rt_new'); // rotation persisted
    expect(onDisk.access_token).toBe('kc_new');
    expect(onDisk.scope).toBe('routes:read secrets:read');
    // atomic write: no temp-file or lock litter left behind
    expect(readdirSync(tempDir).sort()).toEqual(['credentials.json']);
  });

  it('invalid_grant raises AuthenticationError with the re-login hint', async () => {
    writeCreds(credsPath, { expiresInSec: 0 });
    const fetchImpl = stubFetch(() =>
      json(400, { error: 'invalid_grant', error_description: 'family revoked' }),
    );

    const err = await fetchToken({
      tokenEndpoint: TOKEN_ENDPOINT,
      bootstrap: new StoredCredentials(),
      fetchImpl,
    }).then(
      () => null,
      (e: unknown) => e as AuthenticationError,
    );

    expect(err).toBeInstanceOf(AuthenticationError);
    expect(err!.message).toContain('knoxcall login');
    expect(err!.code).toBe('invalid_grant');
  });

  it('expired profile without a refresh token raises the re-login hint', async () => {
    writeProfile(credsPath, 'default', {
      tenant: 'acme',
      base_url: 'https://api.example.test',
      client_id: 'kc_cli_real',
      access_token: 'kc_dead',
      access_token_expires_at: formatExpiry(Date.now() - 10_000),
    });

    await expect(
      fetchToken({ tokenEndpoint: TOKEN_ENDPOINT, bootstrap: new StoredCredentials() }),
    ).rejects.toThrow(/knoxcall login/);
  });
});

// ── Lock: cross-process serialization + hygiene ───────────────────────────────

describe('credentials file lock', () => {
  it('serializes a concurrent double-refresh: exactly one POST, loser adopts the rotated token', async () => {
    // Two concurrent fetches race an expired token: exactly ONE refresh POST
    // happens — the loser re-reads the file under the lock and adopts the
    // rotated token (single-use refresh tokens make a second POST a family
    // revocation).
    writeCreds(credsPath, {
      access_token: 'kc_old',
      refresh_token: 'rt_only',
      expiresInSec: 0,
    });
    const posts: string[] = [];
    const fetchImpl = stubFetch(async (req) => {
      posts.push(req.body!);
      await sleep(300); // hold the refresh so the other caller queues on the file lock
      return json(200, {
        access_token: 'kc_new',
        refresh_token: 'rt_rotated',
        token_type: 'Bearer',
        expires_in: 3600,
      });
    });

    const go = () =>
      fetchToken({ tokenEndpoint: TOKEN_ENDPOINT, bootstrap: new StoredCredentials(), fetchImpl });
    const [a, b] = await Promise.all([go(), go()]);

    expect(posts).toHaveLength(1);
    expect(a.accessToken.expose()).toBe('kc_new');
    expect(b.accessToken.expose()).toBe('kc_new');
    expect(readProfile(credsPath, 'default')!.refresh_token).toBe('rt_rotated');
    expect(existsSync(`${credsPath}.lock`)).toBe(false);
  });

  it('breaks a stale lock (past the stale window) instead of waiting out the timeout', async () => {
    const lockPath = `${credsPath}.lock`;
    writeFileSync(lockPath, '999 0 deadbeef\n', 'ascii');
    const old = new Date(Date.now() - 120_000); // well past the 60s staleness window
    utimesSync(lockPath, old, old);

    const lock = new CredentialsFileLock(credsPath);
    const start = Date.now();
    await lock.acquire();
    try {
      expect(Date.now() - start).toBeLessThan(5000); // broke the stale lock, no 10s wait
      expect(existsSync(lockPath)).toBe(true); // we now hold a fresh lock of our own
    } finally {
      lock.release();
    }
    expect(existsSync(lockPath)).toBe(false);
  });

  it('does not delete a stale lock that is still within the stale window', async () => {
    const lockPath = `${credsPath}.lock`;
    writeFileSync(lockPath, '123 now aabbcc\n', 'ascii');
    const recent = new Date(Date.now() - 45_000); // 45s: stale by the OLD 30s rule, fresh by 60s
    utimesSync(lockPath, recent, recent);
    const lock = new CredentialsFileLock(credsPath, { timeoutMs: 300, retryIntervalMs: 50 });
    await expect(lock.acquire()).rejects.toThrow(/timed out waiting for the credentials file lock/);
    expect(existsSync(lockPath)).toBe(true); // the not-yet-stale lock was left intact
  });

  it('release() never deletes a lock owned by another process', async () => {
    const lockPath = `${credsPath}.lock`;
    const lock = new CredentialsFileLock(credsPath);
    await lock.acquire();
    expect(existsSync(lockPath)).toBe(true);
    // Simulate our lock having been broken as stale and re-taken by a peer:
    // the on-disk owner tag no longer matches what we wrote.
    writeFileSync(lockPath, '4242 0 peerowned\n', 'ascii');
    lock.release();
    // The peer's live lock must survive our release.
    expect(existsSync(lockPath)).toBe(true);
    expect(readFileSync(lockPath, 'ascii')).toContain('peerowned');
  });

  it('times out on a live (fresh) lock', async () => {
    writeFileSync(`${credsPath}.lock`, '123 now feed01\n', 'ascii'); // fresh mtime
    const lock = new CredentialsFileLock(credsPath, { timeoutMs: 300, retryIntervalMs: 50 });
    await expect(lock.acquire()).rejects.toThrow(KnoxCallError);
    await expect(
      new CredentialsFileLock(credsPath, { timeoutMs: 300, retryIntervalMs: 50 }).acquire(),
    ).rejects.toThrow(/timed out waiting for the credentials file lock/);
  });
});

// ── Env overrides for path + profile ──────────────────────────────────────────

describe('env overrides', () => {
  it('KNOXCALL_CREDENTIALS_FILE points the provider at a custom path', async () => {
    const custom = join(tempDir, 'elsewhere', 'creds.json');
    writeCreds(custom, { access_token: 'kc_custom_path' });
    process.env.KNOXCALL_CREDENTIALS_FILE = custom;

    const bootstrap = await autoDetectBootstrap();
    expect(bootstrap).toBeInstanceOf(StoredCredentials);
    const token = await fetchToken({ tokenEndpoint: TOKEN_ENDPOINT, bootstrap });
    expect(token.accessToken.expose()).toBe('kc_custom_path');
  });

  it('KNOXCALL_PROFILE selects a non-default profile', async () => {
    writeCreds(credsPath, { profile: 'default', tenant: 'acme', access_token: 'kc_default' });
    writeCreds(credsPath, { profile: 'work', tenant: 'globex', access_token: 'kc_work' });
    process.env.KNOXCALL_PROFILE = 'work';

    const token = await fetchToken({
      tokenEndpoint: TOKEN_ENDPOINT,
      bootstrap: new StoredCredentials(),
    });
    expect(token.accessToken.expose()).toBe('kc_work');
    expect(token.tenant).toBe('globex');
  });
});

// ── Client seeding: file tenant/base_url, explicit always wins ────────────────

describe('client seeding from the credentials file', () => {
  it('seeds tenant and baseUrl on a zero-config client (auto-detect path)', async () => {
    writeCreds(credsPath); // tenant acme, api.example.test
    const seen: string[] = [];
    const fetchImpl = stubFetch((req) => {
      seen.push(req.url);
      return json(200, { data: { ok: true } });
    });

    const client = new KnoxCall({ fetchImpl }); // zero-config
    await client.request({ method: 'GET', path: '/v1/ping' });

    expect(client.tenant).toBe('acme');
    expect(client.baseUrl).toBe('https://api.example.test');
    expect(seen).toEqual(['https://api.example.test/v1/ping']);
  });

  it('seeds at construction for an explicit StoredCredentials bootstrap and derives the proxy host', () => {
    writeCreds(credsPath, { base_url: 'https://api.knoxcall.com' });
    const client = new KnoxCall({ bootstrap: new StoredCredentials() });
    expect(client.tenant).toBe('acme');
    expect(client.baseUrl).toBe('https://api.knoxcall.com');
    expect(client.proxyBaseUrl).toBe('https://acme.knoxcall.com');
  });

  it('explicit constructor tenant and baseUrl beat the file', async () => {
    writeCreds(credsPath); // tenant acme, api.example.test
    const fetchImpl = stubFetch(() => {
      throw new Error('no HTTP expected — stored token is fresh');
    });

    const client = new KnoxCall({
      tenant: 'zeta',
      baseUrl: 'https://explicit.example.test',
      bootstrap: new StoredCredentials(),
      fetchImpl,
    });
    await client.authenticate(); // fast path — stored token is fresh, no HTTP
    expect(client.tenant).toBe('zeta');
    expect(client.baseUrl).toBe('https://explicit.example.test');
  });

  it('env tenant and base URL beat the file', async () => {
    writeCreds(credsPath);
    process.env.KNOXCALL_TENANT = 'envcorp';
    process.env.KNOXCALL_BASE_URL = 'https://env.example.test';

    const client = new KnoxCall();
    await client.authenticate();
    expect(client.tenant).toBe('envcorp');
    expect(client.baseUrl).toBe('https://env.example.test');
  });

  it('sandbox: true counts as an explicit base URL and beats the file', () => {
    writeCreds(credsPath);
    const client = new KnoxCall({ sandbox: true, bootstrap: new StoredCredentials() });
    expect(client.baseUrl).toBe('https://sandbox.knoxcall.com');
    // the seeded tenant still feeds the sandbox-shaped data plane
    expect(client.proxyBaseUrl).toBe('https://sandbox-acme.knoxcall.com');
  });

  it('keys the token cache by file:{path}:{profile} when the file carries no tenant', async () => {
    writeProfile(credsPath, 'default', {
      base_url: 'https://api.example.test',
      client_id: 'kc_cli_real',
      refresh_token: 'rt_1',
      access_token: 'kc_stored_fresh',
      access_token_expires_at: formatExpiry(Date.now() + 3600_000),
    });
    const keys: string[] = [];
    const store: TokenStore = {
      async get() { return null; },
      async set(key: string, _token: CachedToken) { keys.push(key); },
      async delete() {},
      async withLock<T>(_key: string, fn: () => Promise<T>) { return fn(); },
    };

    const client = new KnoxCall({ bootstrap: new StoredCredentials(), tokenStore: store });
    await client.authenticate();

    expect(keys).toHaveLength(1);
    expect(keys[0]).toBe(`file:${credsPath}:default:`);
  });
});

describe("lock with missing parent directory (first-login regression)", () => {
  it("acquires immediately when ~/.knoxcall does not exist yet", async () => {
    // "wx" on the lock path used to throw ENOENT, which #tryAcquire swallowed
    // as contention — spinning until the timeout. Acquire must create the
    // parent directory and succeed at once.
    const base = mkdtempSync(join(tmpdir(), "kc-freshlock-"));
    try {
      const path = join(base, "fresh", "nested", "credentials.json");
      const lock = new CredentialsFileLock(path, { timeoutMs: 2000 });
      const start = Date.now();
      await lock.acquire();
      try {
        expect(Date.now() - start).toBeLessThan(1000);
        expect(existsSync(`${path}.lock`)).toBe(true);
      } finally {
        lock.release();
      }
      expect(existsSync(`${path}.lock`)).toBe(false);
      // Full first-login write path works in the fresh dir too.
      writeProfile(path, "default", { tenant: "acme", client_id: "kc_cli_x" });
      expect(readProfile(path, "default")?.tenant).toBe("acme");
    } finally {
      rmSync(base, { recursive: true, force: true });
    }
  });
});
