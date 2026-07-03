import { CommandType } from './commands.js';

/** Unix time in seconds, as the device expects in the `t` field. */
export function nowSeconds(at: number = Date.now()): number {
  return Math.floor(at / 1000);
}

function isNew(version: string): boolean {
  return version === '3.4' || version === '3.5';
}

/**
 * Build the command + JSON body for a get(status) or set(control) request, per protocol version.
 * 3.4/3.5 route through CONTROL_NEW / DP_QUERY_NEW with the `{protocol,t,data}` envelope; older
 * versions use CONTROL / DP_QUERY with a flat `{devId,uid,t,dps}` / `{gwId,devId,uid,t}` body.
 */
export function buildRequest(
  version: string,
  kind: 'get' | 'set',
  deviceId: string,
  dps: Record<string, unknown> | undefined,
  at: number = Date.now(),
): { command: number; body: Record<string, unknown> } {
  const t = nowSeconds(at);
  if (isNew(version)) {
    if (kind === 'set') {
      return {
        command: CommandType.CONTROL_NEW,
        body: { protocol: 5, t, data: { dps: dps ?? {} } },
      };
    }
    return { command: CommandType.DP_QUERY_NEW, body: { protocol: 4, t, data: { dps: {} } } };
  }
  if (kind === 'set') {
    return {
      command: CommandType.CONTROL,
      body: { devId: deviceId, uid: deviceId, t: String(t), dps: dps ?? {} },
    };
  }
  return {
    command: CommandType.DP_QUERY,
    body: { gwId: deviceId, devId: deviceId, uid: deviceId, t: String(t) },
  };
}

/** Heartbeat body. */
export function heartbeatBody(deviceId: string): Record<string, unknown> {
  return { gwId: deviceId, devId: deviceId };
}

/**
 * Normalize a decoded status object to a flat `{ dps }` map. 3.4/3.5 wrap it as
 * `{ data: { dps } }`; older versions expose `dps` at the top level.
 */
export function normalizeStatus(obj: Record<string, unknown>): Record<string, unknown> {
  if (obj && typeof obj === 'object') {
    if (obj.dps && typeof obj.dps === 'object') return obj.dps as Record<string, unknown>;
    const data = obj.data;
    if (data && typeof data === 'object' && (data as Record<string, unknown>).dps) {
      return (data as Record<string, unknown>).dps as Record<string, unknown>;
    }
  }
  return {};
}
