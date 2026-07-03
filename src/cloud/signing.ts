import { createHash, createHmac } from 'node:crypto';

/**
 * Tuya OpenAPI v2 request signing (HMAC-SHA256).
 *
 * The signature is `HMAC-SHA256(str, secret)` upper-hex, where
 *   str = clientId + [accessToken] + t + nonce + stringToSign
 *   stringToSign = METHOD "\n" sha256(body) "\n" signHeaders "\n" path?sortedQuery
 * The access token is included only for business requests (not the token request itself).
 */

/** Lowercase-hex SHA-256 of the request body (empty string hashes to the well-known e3b0… value). */
export function contentHash(body: string): string {
  return createHash('sha256').update(body, 'utf8').digest('hex');
}

/** Build the canonical `stringToSign`. `path` must already include the sorted query string. */
export function buildStringToSign(
  method: string,
  path: string,
  body: string,
  signHeaders = '',
): string {
  return [method.toUpperCase(), contentHash(body), signHeaders, path].join('\n');
}

/** Compose the full message and HMAC-sign it (upper-hex). */
export function sign(
  secret: string,
  parts: {
    clientId: string;
    accessToken?: string;
    t: string;
    nonce?: string;
    stringToSign: string;
  },
): string {
  const message =
    parts.clientId + (parts.accessToken ?? '') + parts.t + (parts.nonce ?? '') + parts.stringToSign;
  return createHmac('sha256', secret).update(message, 'utf8').digest('hex').toUpperCase();
}

/** Append a query object as a sorted `?k=v&…` string (Tuya requires alphabetical order in the sign). */
export function withSortedQuery(
  path: string,
  query?: Record<string, string | number | undefined>,
): string {
  const entries = Object.entries(query ?? {}).filter(([, v]) => v !== undefined) as [
    string,
    string | number,
  ][];
  if (entries.length === 0) return path;
  entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  const qs = entries.map(([k, v]) => `${k}=${v}`).join('&');
  return `${path}?${qs}`;
}
