/** Tuya IoT Cloud data-center regions → OpenAPI base URLs. */
export const TUYA_REGIONS = {
  eu: 'https://openapi.tuyaeu.com',
  us: 'https://openapi.tuyaus.com',
  cn: 'https://openapi.tuyacn.com',
  in: 'https://openapi.tuyain.com',
} as const;

export type TuyaRegion = keyof typeof TUYA_REGIONS;

export interface TuyaCloudOptions {
  /** Access ID / Client ID from your Tuya IoT Platform cloud project. */
  accessId: string;
  /** Access Secret / Client Secret from the same project. */
  accessSecret: string;
  /** Data-center region the project + app account live in (default `eu`). */
  region?: TuyaRegion;
  /** Optional explicit base URL (overrides `region`). */
  baseUrl?: string;
  /** Injected HTTP transport (defaults to global fetch). */
  fetchImpl?: CloudFetch;
}

/** A device as returned by the Tuya cloud — crucially including its `localKey` for LAN control. */
export interface CloudDevice {
  id: string;
  name: string;
  /** The local key needed to talk to the device over the LAN. */
  localKey: string;
  /** LAN IP, when the cloud knows it. */
  ip?: string;
  /** Protocol version string when reported (e.g. `3.3`). */
  version?: string;
  category?: string;
  productId?: string;
  productName?: string;
  online?: boolean;
  uuid?: string;
  /** For a Zigbee/BLE sub-device: the parent gateway's device id. */
  gatewayId?: string;
  /** For a sub-device: its node id / cid behind the gateway. */
  nodeId?: string;
  /** Raw cloud object. */
  raw: Record<string, unknown>;
}

export interface CloudResponse {
  readonly statusCode: number;
  readonly json: () => Promise<unknown>;
}
export interface CloudFetchOptions {
  readonly method: 'GET' | 'POST';
  readonly headers: Record<string, string>;
  readonly body?: string;
}
export type CloudFetch = (url: string, options: CloudFetchOptions) => Promise<CloudResponse>;
