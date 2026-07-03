import { describe, it, expect, afterEach } from 'vitest';
import { createServer, type Server } from 'node:net';
import { TuyaDevice } from '../../src/device/tuya-device.js';
import { TuyaCodec } from '../../src/protocol/codec.js';
import { splitFrames } from '../../src/protocol/frame.js';
import { CommandType } from '../../src/protocol/commands.js';
import { aesEcbEncrypt, hmacSha256 } from '../../src/transport/crypto.js';

const KEY = '0123456789abcdef';
const LOCAL_NONCE = Buffer.from('0123456789abcdef');
const REMOTE_NONCE = Buffer.from('fedcba9876543210');

/** A minimal in-process Tuya device (3.3 or 3.4) over TCP loopback, for integration tests. */
function fakeDevice(
  version: string,
  dps: Record<string, unknown>,
): Promise<{ port: number; server: Server }> {
  const server = createServer((socket) => {
    const codec = new TuyaCodec(version, Buffer.from(KEY));
    let seq = 1;
    const send = (command: number, data: Record<string, unknown> | Buffer): void => {
      socket.write(codec.encode(seq++, command, data));
    };
    let buffer = Buffer.alloc(0);
    socket.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      const { frames, rest } = splitFrames(buffer);
      buffer = Buffer.concat([rest]);
      for (const frame of frames) {
        const msg = codec.decode(frame);
        switch (frame.command) {
          case CommandType.SESS_KEY_NEG_START: {
            const body = Buffer.concat([REMOTE_NONCE, hmacSha256(Buffer.from(KEY), LOCAL_NONCE)]);
            send(CommandType.SESS_KEY_NEG_RESP, body);
            break;
          }
          case CommandType.SESS_KEY_NEG_FINISH: {
            const xored = Buffer.alloc(16);
            for (let i = 0; i < 16; i += 1) xored[i] = LOCAL_NONCE[i]! ^ REMOTE_NONCE[i]!;
            codec.setSessionKey(aesEcbEncrypt(Buffer.from(KEY), xored, false));
            break;
          }
          case CommandType.DP_QUERY:
          case CommandType.DP_QUERY_NEW:
            send(frame.command, version >= '3.4' ? { data: { dps } } : { dps });
            break;
          case CommandType.CONTROL:
          case CommandType.CONTROL_NEW:
            send(frame.command, Buffer.alloc(0)); // ACK
            break;
          default:
            break;
        }
        expect(msg).toBeDefined();
      }
    });
  });
  return new Promise((resolve) =>
    server.listen(0, '127.0.0.1', () => {
      resolve({ port: (server.address() as { port: number }).port, server });
    }),
  );
}

let active: { device?: TuyaDevice; server?: Server } = {};
afterEach(() => {
  active.device?.disconnect();
  active.server?.close();
  active = {};
});

describe('TuyaDevice (loopback integration)', () => {
  it('3.3: connect → get returns the device dps', async () => {
    const { port, server } = await fakeDevice('3.3', { '1': true, '2': 50 });
    const device = new TuyaDevice({
      id: 'dev123456789abc',
      key: KEY,
      host: '127.0.0.1',
      port,
      version: '3.3',
      timeoutMs: 2000,
    });
    active = { device, server };
    let connected = false;
    device.on('connected', () => {
      connected = true;
    });
    await device.connect();
    expect(connected).toBe(true);
    const dps = await device.get();
    expect(dps).toEqual({ '1': true, '2': 50 });
  });

  it('3.3: set resolves on the device ACK', async () => {
    const { port, server } = await fakeDevice('3.3', { '1': false });
    const device = new TuyaDevice({
      id: 'd',
      key: KEY,
      host: '127.0.0.1',
      port,
      version: '3.3',
      timeoutMs: 2000,
    });
    active = { device, server };
    await device.connect();
    await expect(device.setDp(1, true)).resolves.toBeUndefined();
  });

  it('3.4: connect runs the session-key handshake, then get works', async () => {
    const { port, server } = await fakeDevice('3.4', { '1': 'auto' });
    const device = new TuyaDevice({
      id: 'd',
      key: KEY,
      host: '127.0.0.1',
      port,
      version: '3.4',
      timeoutMs: 2000,
    });
    active = { device, server };
    await device.connect();
    const dps = await device.get();
    expect(dps).toEqual({ '1': 'auto' });
  });

  it('reports a connect failure as a rejected promise', async () => {
    const device = new TuyaDevice({
      id: 'd',
      key: KEY,
      host: '127.0.0.1',
      port: 1,
      version: '3.3',
      timeoutMs: 500,
    });
    await expect(device.connect()).rejects.toThrow();
  });
});
