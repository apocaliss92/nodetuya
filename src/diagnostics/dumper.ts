import type { TuyaDevice } from '../device/tuya-device.js';

export interface DeviceDump {
  id: string;
  host: string;
  version: string;
  connected: boolean;
  dps: Record<string, unknown>;
}
export interface DumperOptions {
  redact?: boolean;
}

/**
 * Build a JSON-safe snapshot of a device for logs / bug reports. With `redact` (default) the device
 * id is masked (all but the last 4 chars) so dumps can be shared without exposing the id.
 */
export function createDumper(device: TuyaDevice, opts: DumperOptions = {}): { dump(): DeviceDump } {
  const redact = opts.redact ?? true;
  return {
    dump(): DeviceDump {
      return {
        id: redact ? mask(device.id) : device.id,
        host: device.host,
        version: device.protocolVersion,
        connected: device.connected,
        dps: { ...device.dps },
      };
    },
  };
}

function mask(v: string): string {
  if (v.length <= 4) return '*'.repeat(v.length);
  return '*'.repeat(v.length - 4) + v.slice(-4);
}
