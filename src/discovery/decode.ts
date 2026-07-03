import { aesEcbDecrypt, aesGcmDecrypt, UDP_KEY } from '../transport/crypto.js';
import { PREFIX_6699 } from '../protocol/commands.js';
import { splitFrames } from '../protocol/frame.js';

/** A Tuya device announced on the LAN via a UDP broadcast. `localKey` is NOT broadcast. */
export interface DiscoveredDevice {
  /** Device id (`gwId`). */
  id: string;
  ip: string;
  /** Protocol version string (e.g. `3.3`). */
  version: string;
  productKey?: string;
  /** Whether the device is bound/active. */
  active?: number;
  encrypted?: boolean;
  /** Raw announce JSON. */
  raw: Record<string, unknown>;
}

/**
 * Decode a raw UDP discovery datagram (one 55AA or 6699 frame) into a {@link DiscoveredDevice}.
 * The broadcast body is AES-encrypted with the well-known key `md5("yGAdlopoPVldABfn")` (or, on
 * some 3.1 devices, plaintext JSON). Returns `null` if the datagram is not a parseable announce.
 */
export function decodeDiscovery(datagram: Buffer): DiscoveredDevice | null {
  const { frames } = splitFrames(datagram);
  const frame = frames[0];
  if (!frame) return null;

  let json: Record<string, unknown> | null = null;
  if (frame.prefix === PREFIX_6699) {
    const body = frame.bytes.subarray(18, frame.bytes.length - 4);
    const iv = body.subarray(0, 12);
    const tag = body.subarray(body.length - 16);
    const ct = body.subarray(12, body.length - 16);
    try {
      json = parse(aesGcmDecrypt(UDP_KEY, iv, ct, tag, frame.bytes.subarray(4, 18)));
    } catch {
      return null;
    }
  } else {
    // 55AA: payload sits between header+retcode (offset 20) and crc32+suffix (last 8).
    const payload = frame.bytes.subarray(20, frame.bytes.length - 8);
    json = parse(payload) ?? tryDecrypt(payload);
  }
  if (!json) return null;

  const id = String(json.gwId ?? json.devId ?? '');
  const ip = String(json.ip ?? '');
  if (!id || !ip) return null;
  return {
    id,
    ip,
    version: String(json.version ?? ''),
    ...(json.productKey !== undefined ? { productKey: String(json.productKey) } : {}),
    ...(typeof json.active === 'number' ? { active: json.active } : {}),
    ...(json.encrypt !== undefined ? { encrypted: Boolean(json.encrypt) } : {}),
    raw: json,
  };
}

function tryDecrypt(payload: Buffer): Record<string, unknown> | null {
  try {
    return parse(aesEcbDecrypt(UDP_KEY, payload));
  } catch {
    return null;
  }
}

function parse(buf: Buffer): Record<string, unknown> | null {
  const text = buf.toString('utf8').trim();
  if (!text.startsWith('{')) return null;
  try {
    const obj = JSON.parse(text);
    return obj && typeof obj === 'object' ? (obj as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}
