// Security misconfiguration warnings: plaintext http:// to a non-loopback host
// (item 1) and a world-readable credentials file (item 2). Both warn-once and
// never block.

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

import { KnoxCall } from '../src/index.js';
import { isInsecureRemoteUrl, _resetWarnedForTests } from '../src/warn.js';
import { readProfile, writeProfile } from '../src/auth/credentials-file.js';

let warnSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  _resetWarnedForTests();
  warnSpy = vi.spyOn(process, 'emitWarning').mockImplementation(() => {});
});

afterEach(() => {
  warnSpy.mockRestore();
});

function warnedCodes(): string[] {
  return warnSpy.mock.calls
    .map((c) => (c[1] as { code?: string } | undefined)?.code)
    .filter((c): c is string => typeof c === 'string');
}

describe('isInsecureRemoteUrl', () => {
  it('flags plaintext http:// only for non-loopback hosts', () => {
    expect(isInsecureRemoteUrl('http://api.example.com')).toBe(true);
    expect(isInsecureRemoteUrl('http://10.0.0.5:3000')).toBe(true);
    expect(isInsecureRemoteUrl('https://api.example.com')).toBe(false);
    expect(isInsecureRemoteUrl('http://localhost:3000')).toBe(false);
    expect(isInsecureRemoteUrl('http://127.0.0.1:3000')).toBe(false);
    expect(isInsecureRemoteUrl('http://foo.localhost')).toBe(false);
    expect(isInsecureRemoteUrl(undefined)).toBe(false);
  });
});

describe('insecure-URL construction warning (item 1)', () => {
  it('warns once for an http:// non-loopback base URL', () => {
    new KnoxCall({ accessToken: 'kc_live_x', tenant: 'acme', baseUrl: 'http://api.example.com', proxyBaseUrl: 'https://acme.example.test' });
    expect(warnedCodes()).toContain('KNOXCALL_INSECURE_BASE_URL');
  });

  it('does NOT warn for http://localhost (normal dev)', () => {
    new KnoxCall({ accessToken: 'kc_live_x', tenant: 'acme', baseUrl: 'http://localhost:3000', proxyBaseUrl: 'http://localhost:3000' });
    expect(warnedCodes()).not.toContain('KNOXCALL_INSECURE_BASE_URL');
    expect(warnedCodes()).not.toContain('KNOXCALL_INSECURE_PROXY_URL');
  });

  it('warns for an http:// non-loopback proxy URL', () => {
    new KnoxCall({ accessToken: 'kc_live_x', tenant: 'acme', baseUrl: 'https://api.example.test', proxyBaseUrl: 'http://proxy.example.com' });
    expect(warnedCodes()).toContain('KNOXCALL_INSECURE_PROXY_URL');
  });
});

describe('loose credentials-file permission warning (item 2)', () => {
  it.skipIf(process.platform === 'win32')('warns when the credentials file is group/other-readable', () => {
    const dir = mkdtempSync(join(tmpdir(), 'knoxcall-perm-'));
    const path = join(dir, 'credentials.json');
    try {
      writeProfile(path, 'default', { tenant: 'acme', client_id: 'kc_cli', refresh_token: 'rt', access_token: 'kc_a', access_token_expires_at: '2099-01-01T00:00:00Z', scope: '' });
      chmodSync(path, 0o644); // group/other readable
      readProfile(path, 'default');
      expect(warnedCodes()).toContain('KNOXCALL_CREDENTIALS_FILE_PERMS');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it.skipIf(process.platform === 'win32')('does NOT warn for a 0600 file', () => {
    const dir = mkdtempSync(join(tmpdir(), 'knoxcall-perm-'));
    const path = join(dir, 'credentials.json');
    try {
      writeProfile(path, 'default', { tenant: 'acme', client_id: 'kc_cli', refresh_token: 'rt', access_token: 'kc_a', access_token_expires_at: '2099-01-01T00:00:00Z', scope: '' });
      chmodSync(path, 0o600);
      readProfile(path, 'default');
      expect(warnedCodes()).not.toContain('KNOXCALL_CREDENTIALS_FILE_PERMS');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
