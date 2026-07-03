import { describe, it, expect } from 'vitest';
import { crc32 } from '../../src/transport/crc.js';
import {
  md5,
  aesEcbEncrypt,
  aesEcbDecrypt,
  aesGcmEncrypt,
  aesGcmDecrypt,
  hmacSha256,
  UDP_KEY,
} from '../../src/transport/crypto.js';

const KEY = Buffer.from('0123456789abcdef');

describe('crc32', () => {
  it('matches the standard IEEE test vector', () => {
    expect(crc32(Buffer.from('123456789'))).toBe(0xcbf43926);
  });
});

describe('crypto primitives', () => {
  it('md5 length + UDP_KEY is md5("yGAdlopoPVldABfn")', () => {
    expect(md5('abc')).toHaveLength(16);
    expect(UDP_KEY.equals(md5('yGAdlopoPVldABfn'))).toBe(true);
  });

  it('AES-128-ECB round-trips with PKCS#7 padding', () => {
    const pt = Buffer.from('{"dps":{"1":true}}');
    const ct = aesEcbEncrypt(KEY, pt);
    expect(aesEcbDecrypt(KEY, ct).equals(pt)).toBe(true);
  });

  it('AES-128-ECB no-pad round-trips a block-aligned buffer', () => {
    const pt = Buffer.alloc(16, 7);
    expect(aesEcbDecrypt(KEY, aesEcbEncrypt(KEY, pt, false), false).equals(pt)).toBe(true);
  });

  it('AES-128-GCM round-trips with AAD', () => {
    const iv = Buffer.from('012345678901');
    const aad = Buffer.from('header');
    const pt = Buffer.from('hello world');
    const blob = aesGcmEncrypt(KEY, iv, pt, aad); // iv‖ct‖tag
    const ct = blob.subarray(12, blob.length - 16);
    const tag = blob.subarray(blob.length - 16);
    expect(aesGcmDecrypt(KEY, iv, ct, tag, aad).equals(pt)).toBe(true);
  });

  it('GCM auth fails with the wrong AAD', () => {
    const iv = Buffer.from('012345678901');
    const blob = aesGcmEncrypt(KEY, iv, Buffer.from('x'), Buffer.from('a'));
    const ct = blob.subarray(12, blob.length - 16);
    const tag = blob.subarray(blob.length - 16);
    expect(() => aesGcmDecrypt(KEY, iv, ct, tag, Buffer.from('b'))).toThrow();
  });

  it('hmacSha256 is 32 bytes', () => {
    expect(hmacSha256(KEY, Buffer.from('x'))).toHaveLength(32);
  });
});
