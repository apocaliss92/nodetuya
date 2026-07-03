import { crc32 } from '../transport/crc.js';
import { hmacSha256 } from '../transport/crypto.js';
import { PREFIX_55AA, PREFIX_6699, SUFFIX_55AA } from './commands.js';

/** A complete frame carved out of a TCP stream, plus its parsed header fields. */
export interface RawFrame {
  prefix: number;
  seqno: number;
  command: number;
  /** Full frame bytes (prefix … suffix), for trailer verification / GCM AAD. */
  bytes: Buffer;
}

const HEADER_LEN_55AA = 16;
const HEADER_LEN_6699 = 18;

/**
 * Pack a 3.1–3.4 frame: `prefix | seqno | cmd | length | payload | (crc32|hmac) | suffix`.
 * `length = payload + trailer + suffix`. Pass `hmacKey` for the 3.4 HMAC-SHA256 trailer.
 */
export function encode55AA(
  seqno: number,
  command: number,
  payload: Buffer,
  hmacKey?: Buffer,
): Buffer {
  const trailerLen = hmacKey ? 32 : 4;
  const length = payload.length + trailerLen + 4;
  const header = Buffer.alloc(HEADER_LEN_55AA);
  header.writeUInt32BE(PREFIX_55AA, 0);
  header.writeUInt32BE(seqno >>> 0, 4);
  header.writeUInt32BE(command >>> 0, 8);
  header.writeUInt32BE(length >>> 0, 12);
  const preTrailer = Buffer.concat([header, payload]);
  const trailer = hmacKey
    ? hmacSha256(hmacKey, preTrailer)
    : (() => {
        const b = Buffer.alloc(4);
        b.writeUInt32BE(crc32(preTrailer), 0);
        return b;
      })();
  const suffix = Buffer.alloc(4);
  suffix.writeUInt32BE(SUFFIX_55AA, 0);
  return Buffer.concat([preTrailer, trailer, suffix]);
}

/**
 * Carve complete frames out of a (possibly partial, possibly multi-frame) TCP buffer. Returns the
 * frames found and any trailing bytes belonging to an incomplete frame.
 */
export function splitFrames(buffer: Buffer): { frames: RawFrame[]; rest: Buffer } {
  const frames: RawFrame[] = [];
  let offset = 0;
  while (offset + 20 <= buffer.length) {
    const prefix = buffer.readUInt32BE(offset);
    if (prefix !== PREFIX_55AA && prefix !== PREFIX_6699) {
      // Resync: advance to the next possible prefix.
      offset += 1;
      continue;
    }
    const is6699 = prefix === PREFIX_6699;
    const headerLen = is6699 ? HEADER_LEN_6699 : HEADER_LEN_55AA;
    const lengthPos = is6699 ? 14 : 12;
    if (offset + lengthPos + 4 > buffer.length) break;
    const length = buffer.readUInt32BE(offset + lengthPos);
    const total = headerLen + length;
    if (offset + total > buffer.length) break; // incomplete — wait for more bytes
    const bytes = buffer.subarray(offset, offset + total);
    const seqno = is6699 ? bytes.readUInt32BE(6) : bytes.readUInt32BE(4);
    const command = is6699 ? bytes.readUInt32BE(10) : bytes.readUInt32BE(8);
    frames.push({ prefix, seqno, command, bytes });
    offset += total;
  }
  return { frames, rest: buffer.subarray(offset) };
}
