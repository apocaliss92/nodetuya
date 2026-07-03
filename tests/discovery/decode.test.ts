import { describe, it, expect } from 'vitest';
import { decodeDiscovery } from '../../src/discovery/decode.js';
import { encode55AA } from '../../src/protocol/frame.js';
import { CommandType } from '../../src/protocol/commands.js';
import { aesEcbEncrypt, UDP_KEY } from '../../src/transport/crypto.js';

/** A UDP broadcast frame: header | retcode(0) | body | crc | suffix (decodeDiscovery reads [20:-8]). */
function broadcast(body: Buffer): Buffer {
  return encode55AA(0, CommandType.DP_QUERY, Buffer.concat([Buffer.alloc(4, 0), body]));
}

describe('decodeDiscovery', () => {
  it('decodes an encrypted (6667) announce', () => {
    const json = {
      gwId: 'abc123',
      ip: '192.168.1.77',
      version: '3.3',
      productKey: 'pk',
      active: 2,
      encrypt: true,
    };
    const dg = broadcast(aesEcbEncrypt(UDP_KEY, Buffer.from(JSON.stringify(json))));
    expect(decodeDiscovery(dg)).toMatchObject({
      id: 'abc123',
      ip: '192.168.1.77',
      version: '3.3',
      productKey: 'pk',
      active: 2,
      encrypted: true,
    });
  });

  it('decodes a plaintext (6666, 3.1) announce', () => {
    const json = { gwId: 'plain1', ip: '10.0.0.5', version: '3.1' };
    const dg = broadcast(Buffer.from(JSON.stringify(json)));
    expect(decodeDiscovery(dg)).toMatchObject({ id: 'plain1', ip: '10.0.0.5', version: '3.1' });
  });

  it('returns null for a datagram without id/ip', () => {
    const dg = broadcast(Buffer.from(JSON.stringify({ foo: 'bar' })));
    expect(decodeDiscovery(dg)).toBeNull();
  });

  it('returns null for garbage', () => {
    expect(decodeDiscovery(Buffer.from('not a tuya frame at all yada yada'))).toBeNull();
  });
});
