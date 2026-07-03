import { describe, it, expect } from 'vitest';
import { TuyaCodec } from '../../src/protocol/codec.js';
import { splitFrames } from '../../src/protocol/frame.js';
import { CommandType } from '../../src/protocol/commands.js';
import { TuyaProtocolError } from '../../src/transport/errors.js';

const KEY = '0123456789abcdef';
const SESSION = Buffer.alloc(16, 0x5a);

/** Encode with `enc`, carve the frame, decode with `dec`. */
function roundTrip(enc: TuyaCodec, dec: TuyaCodec, command: number, data: any) {
  const frame = enc.encode(1, command, data);
  const { frames } = splitFrames(frame);
  return dec.decode(frames[0]!);
}

describe('TuyaCodec round-trips', () => {
  it('3.3 CONTROL (with version header) round-trips the dps payload', () => {
    const codec = new TuyaCodec('3.3', Buffer.from(KEY));
    const msg = roundTrip(codec, codec, CommandType.CONTROL, { dps: { '1': true } });
    expect(msg.payload).toEqual({ dps: { '1': true } });
  });

  it('3.3 DP_QUERY (no header) round-trips', () => {
    const codec = new TuyaCodec('3.3', Buffer.from(KEY));
    const msg = roundTrip(codec, codec, CommandType.DP_QUERY, { gwId: 'x', t: '1' });
    expect(msg.payload).toMatchObject({ gwId: 'x' });
  });

  it('3.1 CONTROL round-trips (base64 + md5 signature)', () => {
    const codec = new TuyaCodec('3.1', Buffer.from(KEY));
    const frame = codec.encode(1, CommandType.CONTROL, { dps: { '1': 50 } });
    // the 3.1 payload carries the "3.1" version tag + 16-char md5 signature
    const region = frame.subarray(16, frame.length - 8).toString('ascii');
    expect(region.startsWith('3.1')).toBe(true);
    const msg = codec.decode(splitFrames(frame).frames[0]!);
    expect(msg.payload).toEqual({ dps: { '1': 50 } });
  });

  it('3.4 CONTROL_NEW round-trips with a session key + HMAC trailer', () => {
    const codec = new TuyaCodec('3.4', Buffer.from(KEY));
    codec.setSessionKey(SESSION);
    const msg = roundTrip(codec, codec, CommandType.CONTROL_NEW, {
      protocol: 5,
      t: 1,
      data: { dps: { '1': true } },
    });
    expect(msg.payload).toMatchObject({ data: { dps: { '1': true } } });
  });

  it('3.5 CONTROL_NEW round-trips over GCM (6699 framing)', () => {
    const codec = new TuyaCodec('3.5', Buffer.from(KEY));
    codec.setSessionKey(SESSION);
    const msg = roundTrip(codec, codec, CommandType.CONTROL_NEW, {
      protocol: 5,
      t: 1,
      data: { dps: { '2': 25 } },
    });
    expect(msg.payload).toMatchObject({ data: { dps: { '2': 25 } } });
  });

  it('decodes an empty ACK payload as null', () => {
    const codec = new TuyaCodec('3.3', Buffer.from(KEY));
    const msg = roundTrip(codec, codec, CommandType.HEART_BEAT, Buffer.alloc(0));
    expect(msg.payload).toBeNull();
  });

  it('throws on an HMAC/trailer mismatch (wrong session key)', () => {
    // 3.4's trailer is a keyed HMAC, so a wrong key is detected at the frame layer.
    const enc4 = new TuyaCodec('3.4', Buffer.from(KEY));
    enc4.setSessionKey(SESSION);
    const dec4 = new TuyaCodec('3.4', Buffer.from(KEY));
    dec4.setSessionKey(Buffer.alloc(16, 0x11));
    const frame = enc4.encode(1, CommandType.CONTROL_NEW, { data: { dps: {} } });
    expect(() => dec4.decode(splitFrames(frame).frames[0]!)).toThrow(TuyaProtocolError);
  });
});
