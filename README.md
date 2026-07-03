# nodetuya

Node.js / TypeScript client for **Tuya / Smart Life smart devices** over the **local network** (no cloud for control).

Spiritual successor to [tinytuya](https://github.com/jasonacox/tinytuya) / the [localtuya](https://github.com/rospogrigio/localtuya) protocol core — same encrypted LAN protocol, TypeScript-native. Supports protocol versions **3.1, 3.2, 3.3, 3.4 and 3.5** (AES-ECB, HMAC session keys, and AES-GCM), plus UDP discovery.

> **Node only, local only.** Speaks the Tuya binary protocol over TCP on your LAN. You still need each device's **`localKey`** (obtained once from the Tuya cloud / your HA localtuya config) — it is never broadcast.

---

## Install

```bash
npm i @apocaliss92/nodetuya
```

**Requires Node 20 or later.**

---

## Quick start

```ts
import { TuyaDevice } from '@apocaliss92/nodetuya';

const device = new TuyaDevice({
  id: 'bfxxxxxxxxxxxxxxxxxxxx', // device id (gwId)
  key: 'xxxxxxxxxxxxxxxx', // 16-char local key
  host: '192.168.1.50', // device IP
  version: '3.3', // 3.1 | 3.2 | 3.3 | 3.4 | 3.5
});

// 1. Connect (runs the 3.4/3.5 session-key handshake automatically)
await device.connect();

// 2. Read current datapoints
const dps = await device.get(); // → { '1': true, '2': 50, ... }

// 3. React to unsolicited status pushes
device.on('dps', (changed) => console.log('changed:', changed));

// 4. Control datapoints
await device.setDp(1, true); // turn on DP 1
await device.set({ '2': 75 }); // set DP 2 to 75

// 5. Clean up
device.disconnect();
```

Datapoint (DP) indexes and value types are device-specific — e.g. for a plug DP `1` is usually the
on/off boolean. Discover them by reading `get()` and toggling the device in the Smart Life app.

---

## Discovery

Tuya devices broadcast themselves over UDP (ports 6666 / 6667, encrypted with a well-known key).
`discoverDevices()` listens and returns what it hears — **id, IP and protocol version** — so you can
pair them with the `localKey` you hold:

```ts
import { discoverDevices } from '@apocaliss92/nodetuya';

const devices = await discoverDevices({ timeoutMs: 6000 });
// → [{ id, ip, version, productKey?, active?, encrypted? }]
```

> The broadcast does **not** include the `localKey`. Get it from the Tuya IoT cloud, `tinytuya wizard`,
> or your existing localtuya/Home Assistant configuration.

---

## Getting device keys from the cloud (`TuyaCloud`)

You need each device's **`localKey`** to control it locally. Tuya only exposes it through the IoT
project API — so the library ships a `TuyaCloud` helper that fetches all your devices (id, `localKey`,
IP, category, sub-device node ids) in one call.

```ts
import { TuyaCloud, TuyaDevice } from '@apocaliss92/nodetuya';

const cloud = new TuyaCloud({ accessId: 'xxxx', accessSecret: 'yyyy', region: 'eu' });
const devices = await cloud.getDevices();
// → [{ id, name, localKey, ip?, category, productId, online, nodeId?, ... }]

// Pipe straight into a local connection:
const d = devices.find((x) => x.name === 'Kitchen plug');
const device = new TuyaDevice({
  id: d.id,
  key: d.localKey,
  host: d.ip ?? '192.168.1.50',
  version: '3.3',
});
await device.connect();
```

> **What credentials?** Not your app email/password — those can't retrieve `localKey` via any stable
> API. Create a **free Tuya IoT project** at [iot.tuya.com](https://iot.tuya.com), then
> _Cloud → Development → your project → Link Tuya App Account_ and scan the QR with your Smart Life /
> Tuya app. The project's **Access ID** and **Access Secret** (+ its data-center region) are what
> `TuyaCloud` uses. This is the same one-time setup that tinytuya / localtuya require.

## Supported protocol versions

| Version   | Encryption                                | Framing            | Status    |
| --------- | ----------------------------------------- | ------------------ | --------- |
| 3.1       | AES-128-ECB + base64 + md5 signature      | 55AA / CRC32       | supported |
| 3.2 / 3.3 | AES-128-ECB (raw) + version header        | 55AA / CRC32       | supported |
| 3.4       | AES-128-ECB with a negotiated session key | 55AA / HMAC-SHA256 | supported |
| 3.5       | AES-128-GCM with a negotiated session key | 6699 / GCM tag     | supported |

For 3.4 / 3.5 the session key is negotiated on connect (a 3-step nonce/HMAC handshake); after that
it becomes both the AES key and the HMAC/GCM key.

---

## API reference

### `TuyaDevice`

```ts
new TuyaDevice({ id, key, host, version?, port?, timeoutMs? })
```

| Member                                       | Description                                          |
| -------------------------------------------- | ---------------------------------------------------- |
| `connect()`                                  | Open TCP + (3.4/3.5) negotiate the session key       |
| `get()`                                      | Query and return the datapoint map                   |
| `set(dps)`                                   | Set multiple datapoints, e.g. `{ '1': true }`        |
| `setDp(index, value)`                        | Set a single datapoint                               |
| `dps`                                        | Last datapoint map seen                              |
| `disconnect()`                               | Close the connection                                 |
| event `dps`                                  | Emitted on status pushes (`Record<string, unknown>`) |
| event `connected` / `disconnected` / `error` | Connection lifecycle                                 |

### `discoverDevices(options?)`

Passive UDP listen; returns `DiscoveredDevice[]` (`{ id, ip, version, productKey?, active?, encrypted? }`).

---

## Diagnostics dumper

```ts
import { createDumper } from '@apocaliss92/nodetuya';
const snap = createDumper(device).dump();
// { id: '**************cdef', host, version, connected, dps }
```

`redact: true` (default) masks the device id so dumps can be shared safely.

---

## Error types

| Class                | Thrown when                                                |
| -------------------- | ---------------------------------------------------------- |
| `TuyaError`          | Base class                                                 |
| `TuyaProtocolError`  | Framing / CRC / HMAC / decrypt failure (often a wrong key) |
| `TuyaTransportError` | TCP connect / timeout / socket failure                     |
| `TuyaAuthError`      | 3.4/3.5 session-key negotiation failure (wrong local key)  |

---

## Credits & scope

Reverse-engineered from [`tinytuya`](https://github.com/jasonacox/tinytuya) and the
[`localtuya`](https://github.com/rospogrigio/localtuya) protocol core. See
[`docs/tuya-local-protocol-spec.md`](./docs/tuya-local-protocol-spec.md) for the full protocol notes
this port is built from. Not affiliated with or endorsed by Tuya.

## License

MIT — see [LICENSE](./LICENSE).
