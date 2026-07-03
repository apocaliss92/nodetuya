import { describe, it, expect } from 'vitest';
import { contentHash, buildStringToSign, sign, withSortedQuery } from '../../src/cloud/signing.js';
import { createHmac } from 'node:crypto';

describe('contentHash', () => {
  it('hashes the empty body to the well-known SHA-256 value', () => {
    expect(contentHash('')).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    );
  });
});

describe('withSortedQuery', () => {
  it('sorts query params alphabetically', () => {
    expect(withSortedQuery('/v1.0/x', { size: 100, last_row_key: 'k', grant_type: 1 })).toBe(
      '/v1.0/x?grant_type=1&last_row_key=k&size=100',
    );
  });
  it('leaves a path without query untouched', () => {
    expect(withSortedQuery('/v1.0/token')).toBe('/v1.0/token');
  });
});

describe('buildStringToSign + sign', () => {
  it('builds the canonical 4-line string', () => {
    const s = buildStringToSign('GET', '/v1.0/token?grant_type=1', '');
    const [method, hash, headers, path] = s.split('\n');
    expect(method).toBe('GET');
    expect(hash).toBe(contentHash(''));
    expect(headers).toBe('');
    expect(path).toBe('/v1.0/token?grant_type=1');
  });

  it('signs clientId+t+nonce+stringToSign (no token) as upper-hex HMAC', () => {
    const s2s = buildStringToSign('GET', '/v1.0/token?grant_type=1', '');
    const out = sign('secret', { clientId: 'cid', t: '1700000000000', stringToSign: s2s });
    const expected = createHmac('sha256', 'secret')
      .update('cid' + '1700000000000' + s2s)
      .digest('hex')
      .toUpperCase();
    expect(out).toBe(expected);
    expect(out).toMatch(/^[0-9A-F]{64}$/);
  });

  it('includes the access token for business requests', () => {
    const s2s = buildStringToSign('GET', '/v1.0/devices/x', '');
    const withTok = sign('secret', {
      clientId: 'cid',
      accessToken: 'tok',
      t: '1',
      stringToSign: s2s,
    });
    const withoutTok = sign('secret', { clientId: 'cid', t: '1', stringToSign: s2s });
    expect(withTok).not.toBe(withoutTok);
  });
});
