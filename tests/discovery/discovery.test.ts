import { describe, it, expect } from 'vitest';
import { discoverDevices, type UdpBinder } from '../../src/discovery/discovery.js';
import { encode55AA } from '../../src/protocol/frame.js';
import { CommandType } from '../../src/protocol/commands.js';
import { aesEcbEncrypt, UDP_KEY } from '../../src/transport/crypto.js';

function broadcast(json: object): Buffer {
  const body = aesEcbEncrypt(UDP_KEY, Buffer.from(JSON.stringify(json)));
  return encode55AA(0, CommandType.DP_QUERY, Buffer.concat([Buffer.alloc(4, 0), body]));
}

/** Fake binder that replays preset datagrams to every bound port. */
function fakeBinder(datagrams: Buffer[]): UdpBinder {
  return {
    async bind(_port, onMessage) {
      for (const d of datagrams) onMessage(d);
    },
    async closeAll() {
      /* no-op */
    },
  };
}

describe('discoverDevices', () => {
  it('collects announced devices, deduped by id', async () => {
    const binder = fakeBinder([
      broadcast({ gwId: 'a', ip: '1.1.1.1', version: '3.3' }),
      broadcast({ gwId: 'a', ip: '1.1.1.1', version: '3.3' }), // dup
      broadcast({ gwId: 'b', ip: '2.2.2.2', version: '3.4' }),
    ]);
    const seen: string[] = [];
    const found = await discoverDevices(
      { timeoutMs: 10, onDevice: (d) => seen.push(d.id) },
      binder,
    );
    // one bind per port (6666+6667) → each datagram delivered twice, but deduped
    expect(found.map((d) => d.id).sort()).toEqual(['a', 'b']);
    expect(seen.sort()).toEqual(['a', 'b']);
  });

  it('resolves an empty array when nothing is heard', async () => {
    const found = await discoverDevices({ timeoutMs: 10 }, fakeBinder([]));
    expect(found).toEqual([]);
  });
});
