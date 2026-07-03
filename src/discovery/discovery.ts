import { createSocket, type Socket } from 'node:dgram';
import { decodeDiscovery, type DiscoveredDevice } from './decode.js';

/** The UDP ports Tuya devices broadcast on: 6666 (3.1 plaintext), 6667 (encrypted 3.2+). */
export const DISCOVERY_PORTS = [6666, 6667] as const;

export interface DiscoverOptions {
  /** How long to listen before resolving, in ms (default 6000). */
  timeoutMs?: number;
  /** Ports to bind (default 6666 + 6667). */
  ports?: readonly number[];
  /** Called for each device as it is first seen. */
  onDevice?: (device: DiscoveredDevice) => void;
}

/** Minimal UDP surface used by discovery (real impl wraps `node:dgram`; tests inject a fake). */
export interface UdpBinder {
  bind(port: number, onMessage: (data: Buffer) => void): Promise<void>;
  closeAll(): Promise<void>;
}

/** Default binder over `node:dgram` (one reuse-addr socket per port). */
export function createDgramBinder(): UdpBinder {
  const sockets: Socket[] = [];
  return {
    bind(port, onMessage) {
      return new Promise((resolve, reject) => {
        const socket = createSocket({ type: 'udp4', reuseAddr: true });
        socket.once('error', reject);
        socket.on('message', (data) => onMessage(data));
        socket.bind(port, () => {
          socket.removeListener('error', reject);
          sockets.push(socket);
          resolve();
        });
      });
    },
    closeAll() {
      return Promise.all(sockets.map((s) => new Promise<void>((res) => s.close(() => res())))).then(
        () => undefined,
      );
    },
  };
}

/**
 * Passively listen for Tuya UDP broadcasts and collect the announcing devices (deduped by id).
 * Tuya devices broadcast every few seconds, so a ~6s window catches the whole LAN. Note the
 * announce does NOT include the `localKey` — obtain that from the Tuya cloud out-of-band.
 */
export async function discoverDevices(
  options: DiscoverOptions = {},
  binder: UdpBinder = createDgramBinder(),
): Promise<DiscoveredDevice[]> {
  const timeoutMs = options.timeoutMs ?? 6000;
  const ports = options.ports ?? DISCOVERY_PORTS;
  const byId = new Map<string, DiscoveredDevice>();

  const onMessage = (data: Buffer): void => {
    const device = decodeDiscovery(data);
    if (device && !byId.has(device.id)) {
      byId.set(device.id, device);
      options.onDevice?.(device);
    }
  };

  await Promise.all(ports.map((p) => binder.bind(p, onMessage).catch(() => undefined)));
  await new Promise((resolve) => setTimeout(resolve, timeoutMs));
  await binder.closeAll().catch(() => undefined);
  return [...byId.values()];
}
