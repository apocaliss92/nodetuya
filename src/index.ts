// Public API surface of nodetuya. Protocol internals (codec, frame, crypto) stay private to keep the
// published surface small and stable.

export { LIBRARY_NAME } from './support/version.js';

// Errors
export {
  TuyaError,
  TuyaProtocolError,
  TuyaTransportError,
  TuyaAuthError,
} from './transport/errors.js';

// Device
export { TuyaDevice } from './device/tuya-device.js';
export type { TuyaDeviceOptions, TuyaDeviceEvents } from './device/tuya-device.js';

// Discovery
export { discoverDevices, DISCOVERY_PORTS, createDgramBinder } from './discovery/discovery.js';
export type { DiscoverOptions, UdpBinder } from './discovery/discovery.js';
export { decodeDiscovery } from './discovery/decode.js';
export type { DiscoveredDevice } from './discovery/decode.js';

// Protocol constants (useful for advanced/direct use)
export { CommandType } from './protocol/commands.js';

// Diagnostics
export { createDumper } from './diagnostics/dumper.js';
export type { DeviceDump, DumperOptions } from './diagnostics/dumper.js';
