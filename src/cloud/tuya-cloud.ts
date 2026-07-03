import { TuyaCloudError } from '../transport/errors.js';
import { buildStringToSign, sign, withSortedQuery } from './signing.js';
import { TUYA_REGIONS, type TuyaCloudOptions, type CloudDevice, type CloudFetch } from './types.js';

const SIGN_METHOD = 'HMAC-SHA256';

/* v8 ignore start — real network I/O; unit tests inject a CloudFetch. */
const defaultFetch: CloudFetch = async (url, options) => {
  const res = await fetch(url, {
    method: options.method,
    headers: options.headers,
    ...(options.body !== undefined ? { body: options.body } : {}),
  });
  return { statusCode: res.status, json: () => res.json() };
};
/* v8 ignore stop */

/**
 * Tuya IoT Cloud client. Given a cloud project's Access ID + Access Secret (with your Smart Life /
 * Tuya app account linked to the project), it fetches your devices **including their `localKey`** —
 * the missing piece needed to control them over the LAN with {@link TuyaDevice}.
 *
 * The app email/password alone is NOT enough: Tuya only exposes `localKey` through the IoT project
 * API. Create a free project at iot.tuya.com, link your app account, and use its Access ID/Secret.
 */
export class TuyaCloud {
  private readonly baseUrl: string;
  private readonly fetchImpl: CloudFetch;
  private token: { value: string; uid?: string; expiresAt: number } | null = null;

  constructor(private readonly opts: TuyaCloudOptions) {
    this.baseUrl = opts.baseUrl ?? TUYA_REGIONS[opts.region ?? 'eu'];
    this.fetchImpl = opts.fetchImpl ?? defaultFetch;
  }

  /** Obtain (and cache) an access token via `GET /v1.0/token?grant_type=1`. */
  async getToken(now: number = Date.now()): Promise<string> {
    if (this.token && this.token.expiresAt > now + 30_000) return this.token.value;
    const path = withSortedQuery('/v1.0/token', { grant_type: 1 });
    const result = (await this.call('GET', path, undefined, false, now)) as {
      access_token?: string;
      expire_time?: number;
      uid?: string;
    };
    if (!result?.access_token) throw new TuyaCloudError('token request returned no access_token');
    this.token = {
      value: result.access_token,
      ...(result.uid ? { uid: result.uid } : {}),
      expiresAt: now + (result.expire_time ?? 7200) * 1000,
    };
    return this.token.value;
  }

  /** List every device linked to the project (paginated), mapped to {@link CloudDevice}. */
  async getDevices(): Promise<CloudDevice[]> {
    const devices: CloudDevice[] = [];
    let lastRowKey: string | undefined;
    // Paginate through the associated-users devices endpoint.
    for (let page = 0; page < 50; page += 1) {
      const path = withSortedQuery('/v1.0/iot-01/associated-users/devices', {
        size: 100,
        ...(lastRowKey ? { last_row_key: lastRowKey } : {}),
      });
      const result = (await this.call('GET', path)) as {
        devices?: Array<Record<string, unknown>>;
        has_more?: boolean;
        last_row_key?: string;
      };
      for (const d of result?.devices ?? []) devices.push(toCloudDevice(d));
      if (!result?.has_more || !result.last_row_key) break;
      lastRowKey = result.last_row_key;
    }
    return devices;
  }

  /** Fetch one device's detail (`GET /v1.0/devices/{id}`), including its `localKey`. */
  async getDevice(id: string): Promise<CloudDevice> {
    const result = (await this.call('GET', `/v1.0/devices/${id}`)) as Record<string, unknown>;
    return toCloudDevice(result);
  }

  private async call(
    method: 'GET' | 'POST',
    path: string,
    body?: string,
    withToken = true,
    now: number = Date.now(),
  ): Promise<unknown> {
    const t = String(now);
    const accessToken = withToken ? await this.getToken(now) : undefined;
    const stringToSign = buildStringToSign(method, path, body ?? '');
    const signature = sign(this.opts.accessSecret, {
      clientId: this.opts.accessId,
      ...(accessToken ? { accessToken } : {}),
      t,
      stringToSign,
    });
    const headers: Record<string, string> = {
      client_id: this.opts.accessId,
      sign: signature,
      t,
      sign_method: SIGN_METHOD,
      'Content-Type': 'application/json',
      ...(accessToken ? { access_token: accessToken } : {}),
    };
    const res = await this.fetchImpl(`${this.baseUrl}${path}`, {
      method,
      headers,
      ...(body !== undefined ? { body } : {}),
    });
    const envelope = (await res.json().catch(() => ({}))) as {
      success?: boolean;
      result?: unknown;
      code?: number;
      msg?: string;
    };
    if (
      envelope.success === false ||
      (envelope.code !== undefined && envelope.code !== 0 && envelope.result === undefined)
    ) {
      throw new TuyaCloudError(
        `Tuya cloud error: ${envelope.msg ?? 'unknown'} (code ${envelope.code ?? '?'})`,
        envelope.code,
      );
    }
    return envelope.result;
  }
}

function toCloudDevice(d: Record<string, unknown>): CloudDevice {
  return {
    id: String(d.id ?? ''),
    name: String(d.name ?? ''),
    localKey: String(d.local_key ?? ''),
    ...(d.ip ? { ip: String(d.ip) } : {}),
    ...(d.version ? { version: String(d.version) } : {}),
    ...(d.category ? { category: String(d.category) } : {}),
    ...(d.product_id ? { productId: String(d.product_id) } : {}),
    ...(d.product_name ? { productName: String(d.product_name) } : {}),
    ...(typeof d.online === 'boolean' ? { online: d.online } : {}),
    ...(d.uuid ? { uuid: String(d.uuid) } : {}),
    ...(d.gateway_id ? { gatewayId: String(d.gateway_id) } : {}),
    ...(d.node_id ? { nodeId: String(d.node_id) } : {}),
    raw: d,
  };
}
