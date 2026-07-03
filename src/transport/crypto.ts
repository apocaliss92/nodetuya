import { createCipheriv, createDecipheriv, createHash, createHmac } from 'node:crypto';

/** The well-known AES-128-ECB key for Tuya UDP discovery broadcasts: md5("yGAdlopoPVldABfn"). */
export const UDP_KEY: Buffer = createHash('md5').update('yGAdlopoPVldABfn').digest();

export function md5(data: Buffer | string): Buffer {
  return createHash('md5').update(data).digest();
}

export function hmacSha256(key: Buffer, data: Buffer): Buffer {
  return createHmac('sha256', key).update(data).digest();
}

/** AES-128-ECB encrypt. PKCS#7 padding by default (3.4 session traffic passes `pad: false`). */
export function aesEcbEncrypt(key: Buffer, data: Buffer, pad = true): Buffer {
  const cipher = createCipheriv('aes-128-ecb', key, null);
  cipher.setAutoPadding(pad);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

/** AES-128-ECB decrypt. Unpads (PKCS#7) by default. */
export function aesEcbDecrypt(key: Buffer, data: Buffer, unpad = true): Buffer {
  const decipher = createDecipheriv('aes-128-ecb', key, null);
  decipher.setAutoPadding(unpad);
  return Buffer.concat([decipher.update(data), decipher.final()]);
}

/** AES-128-GCM encrypt (protocol 3.5). Returns iv‖ciphertext‖tag as a single buffer. */
export function aesGcmEncrypt(key: Buffer, iv: Buffer, plaintext: Buffer, aad: Buffer): Buffer {
  const cipher = createCipheriv('aes-128-gcm', key, iv);
  cipher.setAAD(aad);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([iv, ct, cipher.getAuthTag()]);
}

/** AES-128-GCM decrypt (protocol 3.5). `data` is ciphertext (no iv/tag); pass iv, tag, aad. */
export function aesGcmDecrypt(
  key: Buffer,
  iv: Buffer,
  data: Buffer,
  tag: Buffer,
  aad: Buffer,
): Buffer {
  const decipher = createDecipheriv('aes-128-gcm', key, iv);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data), decipher.final()]);
}
