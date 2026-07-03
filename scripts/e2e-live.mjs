// Live smoke test against a real Tuya device on your LAN.
// Create a .env with TUYA_DEVICE_ID / TUYA_LOCAL_KEY / TUYA_HOST (and optional TUYA_VERSION), then:
//   npm run test:e2e:live
//
// READ-ONLY: connect + one status query + a redacted dump. It never sets any datapoint.

import { TuyaDevice, createDumper } from '../dist/index.js';

const id = process.env.TUYA_DEVICE_ID;
const key = process.env.TUYA_LOCAL_KEY;
const host = process.env.TUYA_HOST;
const version = process.env.TUYA_VERSION || '3.3';
if (!id || !key || !host) {
  console.error('Set TUYA_DEVICE_ID, TUYA_LOCAL_KEY and TUYA_HOST in .env');
  process.exit(1);
}

const device = new TuyaDevice({ id, key, host, version, timeoutMs: 6000 });
device.on('dps', (changed) => console.log('push:', changed));

console.log(`Connecting to ${host} (protocol ${version})…`);
await device.connect();
console.log('✓ connected');

const dps = await device.get();
console.log('✓ datapoints:', JSON.stringify(dps, null, 2));
console.log('\ndump:', JSON.stringify(createDumper(device).dump(), null, 2));

device.disconnect();
console.log('\nDone.');
