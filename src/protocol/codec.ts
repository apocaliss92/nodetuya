import {
  aesEcbEncrypt,
  aesEcbDecrypt,
  aesGcmEncrypt,
  aesGcmDecrypt,
  md5,
  hmacSha256,
} from '../transport/crypto.js';
import { crc32 } from '../transport/crc.js';
import { TuyaProtocolError } from '../transport/errors.js';
import {
  CommandType,
  NO_HEADER_COMMANDS,
  PREFIX_6699,
  SUFFIX_6699,
  versionHeader,
} from './commands.js';
import { encode55AA, type RawFrame } from './frame.js';

const VERSION_PREFIXES = ['3.1', '3.2', '3.3', '3.4', '3.5'];

/** Decoded device message: the JSON payload (or null for an empty ACK) + protocol metadata. */
export interface DecodedMessage {
  command: number;
  seqno: number;
  retcode: number;
  payload: Record<string, unknown> | null;
  /** Raw decrypted bytes (used by the session-key handshake, which sends nonces not JSON). */
  raw: Buffer;
}

/**
 * Per-connection Tuya codec: applies the right encryption + framing for a protocol version, and
 * decodes device replies. For 3.4/3.5 call {@link setSessionKey} after the handshake — the session
 * key then becomes both the AES key and the HMAC/GCM key.
 */
export class TuyaCodec {
  private sessionKey: Buffer | undefined;
  constructor(
    private readonly version: string,
    private readonly localKey: Buffer,
  ) {}

  setSessionKey(key: Buffer): void {
    this.sessionKey = key;
  }
  get key(): Buffer {
    return this.sessionKey ?? this.localKey;
  }
  private get isV34(): boolean {
    return this.version === '3.4';
  }
  private get isV35(): boolean {
    return this.version === '3.5';
  }
  private get useHmac(): boolean {
    return this.isV34;
  }

  /** Encode a command + payload (a JS object → JSON, or a raw Buffer for handshake nonces). */
  encode(seqno: number, command: number, data: Record<string, unknown> | Buffer): Buffer {
    const json = Buffer.isBuffer(data) ? data : Buffer.from(JSON.stringify(data), 'utf8');
    const withHeader = !NO_HEADER_COMMANDS.has(command);

    if (this.version === '3.1') return this.encodeV31(seqno, command, json);
    if (this.isV35)
      return this.encode6699(seqno, command, this.withVersionHeader(json, withHeader));
    if (this.isV34) {
      const ct = aesEcbEncrypt(this.key, this.withVersionHeader(json, withHeader));
      return encode55AA(seqno, command, ct, this.key);
    }
    // 3.2 / 3.3: encrypt json, prepend the version header to the CIPHERTEXT.
    const ct = aesEcbEncrypt(this.localKey, json);
    const payload = withHeader ? Buffer.concat([versionHeader(this.version), ct]) : ct;
    return encode55AA(seqno, command, payload);
  }

  private withVersionHeader(json: Buffer, withHeader: boolean): Buffer {
    return withHeader ? Buffer.concat([versionHeader(this.version), json]) : json;
  }

  private encodeV31(seqno: number, command: number, json: Buffer): Buffer {
    if (command !== CommandType.CONTROL) {
      return encode55AA(seqno, command, json); // DP_QUERY etc: plaintext json
    }
    const b64 = aesEcbEncrypt(this.localKey, json).toString('base64');
    const sig = md5(Buffer.concat([Buffer.from(`data=${b64}||lpv=3.1||`), this.localKey]))
      .toString('hex')
      .slice(8, 24);
    const payload = Buffer.concat([Buffer.from('3.1'), Buffer.from(sig), Buffer.from(b64)]);
    return encode55AA(seqno, command, payload);
  }

  private encode6699(seqno: number, command: number, plain: Buffer): Buffer {
    const iv = Buffer.from(
      String(Math.floor(Date.now() * 10))
        .slice(0, 12)
        .padEnd(12, '0'),
    );
    const length = 12 + plain.length + 16 + 4; // iv + ct + tag + suffix
    const header = Buffer.alloc(18);
    header.writeUInt32BE(PREFIX_6699, 0);
    header.writeUInt16BE(0, 4);
    header.writeUInt32BE(seqno >>> 0, 6);
    header.writeUInt32BE(command >>> 0, 10);
    header.writeUInt32BE(length >>> 0, 14);
    const gcm = aesGcmEncrypt(this.key, iv, plain, header.subarray(4)); // iv‖ct‖tag
    const suffix = Buffer.alloc(4);
    suffix.writeUInt32BE(SUFFIX_6699, 0);
    return Buffer.concat([header, gcm, suffix]);
  }

  /** Decode a carved frame into its command + JSON payload, verifying the trailer. */
  decode(frame: RawFrame): DecodedMessage {
    const raw = frame.prefix === PREFIX_6699 ? this.decode6699(frame) : this.decode55AA(frame);
    return {
      command: frame.command,
      seqno: frame.seqno,
      retcode: raw.retcode,
      raw: raw.plain,
      payload: parseJson(raw.plain),
    };
  }

  private decode55AA(frame: RawFrame): { retcode: number; plain: Buffer } {
    const bytes = frame.bytes;
    const trailerLen = this.useHmac ? 32 : 4;
    const end = bytes.length - 4; // strip suffix
    const preTrailer = bytes.subarray(0, end - trailerLen);
    const trailer = bytes.subarray(end - trailerLen, end);
    const expected = this.useHmac ? hmacSha256(this.key, preTrailer) : u32(crc32(preTrailer));
    if (!expected.equals(trailer))
      throw new TuyaProtocolError('frame trailer mismatch (wrong key?)');

    let region = bytes.subarray(16, end - trailerLen); // after header, before trailer
    let retcode = 0;
    if (region.length >= 4 && (region.readUInt32BE(0) & 0xffffff00) === 0) {
      retcode = region.readUInt32BE(0);
      region = region.subarray(4);
    }
    return { retcode, plain: this.decryptPayload(region) };
  }

  private decode6699(frame: RawFrame): { retcode: number; plain: Buffer } {
    const bytes = frame.bytes;
    const body = bytes.subarray(18, bytes.length - 4); // iv + ct + tag
    const iv = body.subarray(0, 12);
    const tag = body.subarray(body.length - 16);
    const ct = body.subarray(12, body.length - 16);
    let plain: Buffer;
    try {
      plain = aesGcmDecrypt(this.key, iv, ct, tag, bytes.subarray(4, 18));
    } catch {
      throw new TuyaProtocolError('GCM auth failed (wrong session key?)');
    }
    let retcode = 0;
    if (plain.length >= 4 && (plain.readUInt32BE(0) & 0xffffff00) === 0) {
      retcode = plain.readUInt32BE(0);
      plain = plain.subarray(4);
    }
    return { retcode, plain: stripVersionHeader(plain) };
  }

  /** Decrypt a 3.1–3.4 payload region into plaintext bytes (already-decrypted for 3.4 vs raw ECB). */
  private decryptPayload(region: Buffer): Buffer {
    if (region.length === 0) return region;
    if (this.version === '3.1') {
      if (region[0] === 0x7b) return region; // '{' → plaintext json
      const b64 = startsWithVersion(region) ? region.subarray(3 + 16) : region;
      return aesEcbDecrypt(this.localKey, Buffer.from(b64.toString('ascii'), 'base64'));
    }
    if (this.isV34) {
      const pt = aesEcbDecrypt(this.key, region);
      return stripVersionHeader(pt);
    }
    // 3.2 / 3.3: strip a version header off the ciphertext, then ECB-decrypt.
    const ct = startsWithVersion(region) ? region.subarray(15) : region;
    return aesEcbDecrypt(this.localKey, ct);
  }
}

function u32(n: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0, 0);
  return b;
}

function startsWithVersion(buf: Buffer): boolean {
  const head = buf.subarray(0, 3).toString('ascii');
  return VERSION_PREFIXES.includes(head);
}

function stripVersionHeader(buf: Buffer): Buffer {
  return startsWithVersion(buf) ? buf.subarray(15) : buf;
}

function parseJson(buf: Buffer): Record<string, unknown> | null {
  if (buf.length === 0) return null;
  try {
    const obj = JSON.parse(buf.toString('utf8'));
    return obj && typeof obj === 'object' ? (obj as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}
