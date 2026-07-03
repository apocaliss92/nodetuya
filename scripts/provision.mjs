// Fetch all your devices (with localKeys) from a Tuya IoT Cloud project.
// Needs a .env with TUYA_ACCESS_ID / TUYA_ACCESS_SECRET / TUYA_REGION (eu|us|cn|in):
//   npm run build && node --env-file=.env scripts/provision.mjs
//
// Create a free project at https://iot.tuya.com, then "Link Tuya App Account"
// (scan the QR with your Smart Life app) so your devices show up here.

import { TuyaCloud } from '../dist/index.js';

const accessId = process.env.TUYA_ACCESS_ID;
const accessSecret = process.env.TUYA_ACCESS_SECRET;
const region = process.env.TUYA_REGION || 'eu';
if (!accessId || !accessSecret) {
  console.error('Set TUYA_ACCESS_ID, TUYA_ACCESS_SECRET (and TUYA_REGION) in .env');
  process.exit(1);
}

const cloud = new TuyaCloud({ accessId, accessSecret, region });
console.log(`Fetching devices from Tuya cloud (region ${region})…`);
const devices = await cloud.getDevices();
console.log(`\n${devices.length} device(s):\n`);
for (const d of devices) {
  console.log(`- ${d.name}`);
  console.log(
    `    id=${d.id} key=${d.localKey}${d.ip ? ' ip=' + d.ip : ''}${d.nodeId ? ' node_id=' + d.nodeId : ''} category=${d.category ?? ''} online=${d.online}`,
  );
}
