import { describe, it, expect } from 'vitest';
import { encode55AA, splitFrames } from '../../src/protocol/frame.js';
import { CommandType } from '../../src/protocol/commands.js';

describe('encode55AA + splitFrames', () => {
  it('round-trips a single frame with a CRC trailer', () => {
    const payload = Buffer.from('payload-bytes');
    const frame = encode55AA(5, CommandType.DP_QUERY, payload);
    const { frames, rest } = splitFrames(frame);
    expect(frames).toHaveLength(1);
    expect(frames[0]).toMatchObject({ seqno: 5, command: CommandType.DP_QUERY });
    expect(rest).toHaveLength(0);
  });

  it('splits two concatenated frames', () => {
    const a = encode55AA(1, CommandType.CONTROL, Buffer.from('aaa'));
    const b = encode55AA(2, CommandType.HEART_BEAT, Buffer.from('bb'));
    const { frames } = splitFrames(Buffer.concat([a, b]));
    expect(frames.map((f) => f.seqno)).toEqual([1, 2]);
  });

  it('holds back an incomplete trailing frame as rest', () => {
    const full = encode55AA(1, CommandType.CONTROL, Buffer.from('hello'));
    const partial = full.subarray(0, full.length - 3);
    const { frames, rest } = splitFrames(partial);
    expect(frames).toHaveLength(0);
    expect(rest.length).toBe(partial.length);
  });

  it('uses a 32-byte HMAC trailer when a key is given (length grows by 28)', () => {
    const p = Buffer.from('x');
    const crcFrame = encode55AA(1, CommandType.CONTROL, p);
    const hmacFrame = encode55AA(1, CommandType.CONTROL, p, Buffer.alloc(16, 1));
    expect(hmacFrame.length - crcFrame.length).toBe(28); // 32 - 4
  });
});
