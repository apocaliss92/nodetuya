# Tuya Local (LAN) Binary Protocol — Source-Accurate Spec for a TypeScript Reimplementation

Derived by reading the actual source of:

- **tinytuya** (`jasonacox/tinytuya`, master) — refactored into `tinytuya/core/*.py`. This is the most complete reference and is the primary source below (it has full 3.5/GCM support).
- **localtuya** (`rospogrigio/localtuya`, master) — its bundled `pytuya` at `custom_components/localtuya/pytuya/__init__.py`, plus `custom_components/localtuya/discovery.py`.

Both share the same wire protocol (both credit codetheweb/tuyapi for the reverse-engineering). Where they differ it is called out. **Key structural difference:** tinytuya supports 3.1/3.2/3.3/3.4/3.5; localtuya's bundled pytuya only implements up to **3.4** (no GCM/3.5, no `0x6699` framing). For 3.5 you must follow tinytuya.

Citations are `file:line` into the downloaded sources. tinytuya files are cited as `tinytuya/core/<file>.py`; localtuya as `pytuya/__init__.py`.

---

## 1. Transport & Ports

| Purpose | Port | Proto | Source |
|---|---|---|---|
| Device control/status | **6668** | TCP | `TCPPORT = 6668` — `tinytuya/core/const.py:10`; `port=6668` — `pytuya/__init__.py:1176` |
| UDP discovery (3.1, unencrypted-ish) | **6666** | UDP | `UDPPORT = 6666` — `const.py:7`; `local_addr=("0.0.0.0", 6666)` — `pytuya/discovery.py:47` |
| UDP discovery (3.2+/3.3 encrypted) | **6667** | UDP | `UDPPORTS = 6667` — `const.py:8`; port 6667 — `pytuya/discovery.py:49` |
| UDP app / v3.5 pull discovery | **7000** | UDP | `UDPPORTAPP = 7000` — `const.py:9`; broadcast target — `scanner.py:247` |

The TCP socket sets `TCP_NODELAY` (`XenonDevice.py:389`) and connects with `AF_INET6` if the address contains `:`, else `AF_INET` (`XenonDevice.py:386`).

---

## 2. Message Framing (TCP)

There are **two frame formats**, selected by the 4-byte prefix magic:

- **`0x000055AA`** ("55AA") — used for **all versions 3.1–3.4** and for 3.5 *receive-desync search*. Trailer is CRC32 (3.1/3.2/3.3) or HMAC-SHA256 (3.4).
- **`0x00006699`** ("6699") — used **only for protocol 3.5** (AES-GCM). Entire payload after the header is GCM-encrypted; the "trailer" is the 16-byte GCM tag.

### 2.1 struct formats (exact, from `tinytuya/core/header.py`)

```python
MESSAGE_HEADER_FMT_55AA = ">4I"     # 4×uint32: prefix, seqno, cmd, length         (header.py:15)
MESSAGE_HEADER_FMT_6699 = ">IHIII"  # uint32 prefix, uint16 unknown, uint32 seqno, uint32 cmd, uint32 length  (header.py:16)
MESSAGE_RETCODE_FMT     = ">I"      # uint32 retcode (received messages)             (header.py:17)
MESSAGE_END_FMT_55AA    = ">2I"     # uint32 crc, uint32 suffix                     (header.py:18)
MESSAGE_END_FMT_HMAC    = ">32sI"   # 32-byte hmac, uint32 suffix                   (header.py:19)
MESSAGE_END_FMT_6699    = ">16sI"   # 16-byte GCM tag, uint32 suffix                (header.py:20)

PREFIX_55AA_VALUE = 0x000055AA   PREFIX_55AA_BIN = b"\x00\x00U\xaa"     (header.py:21-22)
SUFFIX_55AA_VALUE = 0x0000AA55   SUFFIX_55AA_BIN = b"\x00\x00\xaaU"     (header.py:23-24)
PREFIX_6699_VALUE = 0x00006699   PREFIX_6699_BIN = b"\x00\x00\x66\x99"  (header.py:25-26)
SUFFIX_6699_VALUE = 0x00009966   SUFFIX_6699_BIN = b"\x00\x00\x99\x66"  (header.py:27-28)
```

All fields are **big-endian** (`>`).

### 2.2 55AA layout (3.1 / 3.2 / 3.3 / 3.4)

```
+--------+--------+--------+--------+---------------------------+----------------+--------+
| prefix | seqno  |  cmd   | length |          payload          |  crc / hmac    | suffix |
| u32    | u32    | u32    | u32    |  (length - end_len bytes) |  4B or 32B     | u32    |
| 55AA   |        |        |        |  [retcode u32 on RX]      |                | AA55   |
+--------+--------+--------+--------+---------------------------+----------------+--------+
   4        4        4        4         variable                  4 or 32          4
```

- `length` = `len(payload) + sizeof(end_fmt)`. With CRC32 `end_fmt=">2I"` → +8; with HMAC `end_fmt=">32sI"` → +36. (`message_helper.py:32-34`, pytuya `__init__.py:266-286`)
- **On received messages** the first 4 bytes of the payload region are a **retcode** (`uint32`), stripped before decode (`message_helper.py:129-130`, pytuya `:317-323`). Sent messages set retcode = 0 (`XenonDevice.py:1004`).
- **CRC** (3.1/3.2/3.3): `binascii.crc32(header_through_payload) & 0xFFFFFFFF` over everything *before* the crc field — i.e. `data[:header_len + length - end_len]` (`message_helper.py:63,139`).
- **HMAC** (3.4): `HMAC-SHA256(key = session_local_key, msg = header_through_payload)` — 32 bytes (`message_helper.py:61,137`; pytuya `:281,327`). The HMAC key is the **negotiated session key** (see §5), not the raw local_key.

### 2.3 6699 layout (3.5, AES-GCM)

```
+--------+---------+--------+--------+--------+------------------------------+---------+--------+
| prefix | unknown | seqno  |  cmd   | length |   iv(12) + ciphertext        |  GCM tag| suffix |
| u32    | u16     | u32    | u32    | u32    |   (AAD = header bytes[4:])    |  16B    | u32    |
| 6699   |  0x0000 |        |        |        |                              |         | 9966   |
+--------+---------+--------+--------+--------+------------------------------+---------+--------+
   4        2         4        4        4        12 + N                          16        4
```

- `length` = `len(payload) + (sizeof(end_fmt) - 4) + 12` = `len(payload) + 12 + 12`; if a retcode int is present add +4 (`message_helper.py:40-42`).
- GCM: the **12-byte IV/nonce is prepended** to the ciphertext, the **16-byte tag is appended** (before the suffix). The GCM **AAD (additional authenticated data)** is the header **from byte 4 onward** — i.e. `unknown|seqno|cmd|length` (`message_helper.py:56` passes `header=data[4:]`; decrypt `:156` passes `header=data[4:header_len]`).
- The plaintext that gets GCM-encrypted is `retcode(u32) + payload` on the way out when a retcode int is supplied, else just `payload` (`message_helper.py:52-55`). On receive, tinytuya conditionally strips a retcode if the decrypted plaintext doesn't start with `{` but does after 4 bytes (`message_helper.py:161-170`).

### 2.4 Pack pseudocode (both formats)

```
pack_message(prefix, seqno, cmd, payload, key?):
  if prefix == 55AA:
    end_fmt = ">32sI" if key else ">2I"
    length  = len(payload) + sizeof(end_fmt)
    header  = pack(">4I", 0x55AA, seqno, cmd, length)
    body    = header + payload
    crc     = key ? HMAC_SHA256(key, body) : crc32(body)&0xFFFFFFFF
    return body + pack(end_fmt, crc, 0x0000AA55)
  if prefix == 6699:                       # key REQUIRED
    length  = len(payload) + 12 + 12  (+4 if retcode int)
    header  = pack(">IHIII", 0x6699, 0, seqno, cmd, length)
    iv      = 12-byte nonce
    raw     = (pack(">I",retcode)+payload) if retcode-int else payload
    ct+tag  = AES_GCM_encrypt(key, iv, raw, aad = header[4:])
    return header + iv + ct + tag + pack(">I", 0x00009966)
```
(`message_helper.py:28-67`)

### 2.5 Parsing / stream reassembly

- `parse_header` reads the 4-byte prefix, picks the fmt, unpacks, and computes `total_length` = `payload_len + header_len` (55AA) or `payload_len + header_len + 4` (6699, for the suffix) (`message_helper.py:70-99`).
- Sanity ceiling: reject if `payload_len > MAX_PAYLOAD_LENGTH` (`1440` in tinytuya `const.py:19`; `1000` in pytuya `:369`).
- The reader searches the buffer for either prefix (`PREFIX_55AA_BIN` / `PREFIX_6699_BIN`) and discards leading garbage until a prefix sits at offset 0, refilling from the socket (`XenonDevice.py:472-491`).
- localtuya's streaming buffer advances by `header_len - 4 + header.length` per message (note it uses `MESSAGE_RECV_HEADER_FMT = ">5I"` = 20 bytes for the header-len calc; `header_len - 4` = 16, so it consumes `16 + length`) — `pytuya/__init__.py:463-475`.

---

## 3. Command Code Constants

From `tinytuya/core/command_types.py` (cross-checked identical in `pytuya/__init__.py:114-135`):

| Name | Value | Notes |
|---|---|---|
| `AP_CONFIG` | `1` | AP 3.0 network config |
| `ACTIVE` | `2` | work-mode (discard) |
| `SESS_KEY_NEG_START` | `3` | session-key negotiate start |
| `SESS_KEY_NEG_RESP` | `4` | session-key negotiate response |
| `SESS_KEY_NEG_FINISH` | `5` | session-key negotiate finish |
| `UNBIND` | `6` | |
| `CONTROL` | `7` | set DPs (0x07) |
| `STATUS` | `8` | async state upload from device (0x08) |
| `HEART_BEAT` | `9` | heartbeat (0x09) |
| `DP_QUERY` | `0x0a` (10) | get datapoints |
| `QUERY_WIFI` | `0x0b` (11) | |
| `TOKEN_BIND` | `0x0c` (12) | |
| `CONTROL_NEW` | `0x0d` (13) | set DPs, 3.4/3.5 + device22 |
| `ENABLE_WIFI` | `0x0e` (14) | |
| `WIFI_INFO` | `0x0f` (15) | |
| `DP_QUERY_NEW` | `0x10` (16) | get datapoints, 3.4/3.5 |
| `SCENE_EXECUTE` | `0x11` (17) | |
| `UPDATEDPS` | `0x12` (18) | request DP refresh |
| `UDP_NEW` | `0x13` (19) | FR_TYPE_ENCRYPTION |
| `AP_CONFIG_NEW` | `0x14` (20) | |
| `BOARDCAST_LPV34` | `0x23` (35) | |
| `REQ_DEVINFO` | `0x25` (37) | broadcast to port 7000 to get v3.5 devices to announce (tinytuya only) |
| `LAN_EXT_STREAM` | `0x40` (64) | sub-device query etc. |

Reference header these map to: Tuya `lan_protocol.h` (`command_types.py:5`).

### 3.1 Commands that do NOT get the version header

```python
NO_PROTOCOL_HEADER_CMDS = [DP_QUERY, DP_QUERY_NEW, UPDATEDPS, HEART_BEAT,
                           SESS_KEY_NEG_START, SESS_KEY_NEG_RESP, SESS_KEY_NEG_FINISH,
                           LAN_EXT_STREAM]   # header.py:30
```
(localtuya's list is the same minus `LAN_EXT_STREAM` — `pytuya/__init__.py:154-162`.) Every other command gets the version header prepended (see §4).

---

## 4. Encryption Per Protocol Version

The AES **key is the `local_key` used directly as the AES-128 key** for 3.1/3.2/3.3 (16 ASCII bytes, `.encode("latin1")` — `XenonDevice.py:304`). For 3.4/3.5 the AES key is the **negotiated session key** (§5), which is also 16 bytes. There is **no KDF/hash of local_key** — the raw 16-byte key is fed to AES. `_get_socket` enforces `len(local_key) == 16` for version > 3.1 (`XenonDevice.py:379`).

Version header bytes (`header.py:7-14`):
```
PROTOCOL_VERSION_BYTES_31 = b"3.1"   PROTOCOL_VERSION_BYTES_33 = b"3.3"
PROTOCOL_VERSION_BYTES_34 = b"3.4"   PROTOCOL_VERSION_BYTES_35 = b"3.5"
PROTOCOL_3x_HEADER  = 12 * b"\x00"                     # 12 zero bytes
version_header      = str(version).encode('latin1') + PROTOCOL_3x_HEADER   # e.g. b"3.3" + 12×\x00 = 15 bytes
```
(`version_header` built in `set_version`, `XenonDevice.py:1137-1142`.) So for 3.3 the header is exactly **15 bytes**: `b"3.3\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"`.

### 4.1 Protocol 3.1 — AES-128-ECB + base64 + MD5 signature

Only `CONTROL` (0x07) is encrypted; `DP_QUERY` and others go plaintext JSON on 3.1. Exact logic (`XenonDevice.py:982-1001`, identical `pytuya/__init__.py:1051-1070`):

```python
elif msg.cmd == CONTROL:                     # 3.1 branch
    payload = cipher.encrypt(payload)         # AES-128-ECB, PKCS-style pad, base64-encoded
    preMd5String = (b"data=" + payload + b"||lpv=" + b"3.1" + b"||" + self.local_key)
    m = md5(); m.update(preMd5String); hexdigest = m.hexdigest()
    payload = b"3.1" + hexdigest[8:][:16].encode("latin1") + payload
```

So a 3.1 CONTROL payload on the wire (inside the 55AA frame) is:
```
b"3.1" + md5hex[8:24] (16 ASCII chars) + base64( AES-ECB( pad(json) ) )
```
- `cipher.encrypt(payload)` here uses **`use_base64=True`** default and pads (`crypto_helper.py:84,93,97`), so the ciphertext is base64.
- The MD5 is `md5(b"data=" + b64ct + b"||lpv=3.1||" + local_key)`, and `hexdigest[8:][:16]` = characters 8..23 of the 32-char hex digest.
- **Decrypt (RX):** if payload `startswith(b"3.1")`, strip the 3 version bytes, strip the next 16 (MD5), then `cipher.decrypt(rest)` with base64 (`XenonDevice.py:776-782`).

### 4.2 Protocol 3.2 / 3.3 — AES-128-ECB, raw bytes, 15-byte version header

`crypto_helper.encrypt` with `use_base64=False` → **raw AES-ECB ciphertext, no base64** (`XenonDevice.py:978`). Then the 15-byte version header is prepended **unless** the command is in `NO_PROTOCOL_HEADER_CMDS`:

```python
elif self.version >= 3.2:                              # XenonDevice.py:976-981
    payload = self.cipher.encrypt(payload, False)      # AES-128-ECB raw (padded)
    if msg.cmd not in NO_PROTOCOL_HEADER_CMDS:
        payload = self.version_header + payload         # b"3.3"+12×\x00 + ciphertext
```

**Which commands get the header:** every command **except** `DP_QUERY (0x0a)`, `DP_QUERY_NEW`, `UPDATEDPS`, `HEART_BEAT`, and the sess-key ones. So `CONTROL (0x07)` gets `3.3`+header; **`DP_QUERY (0x0a)` does NOT** (this is the exact "but NOT for DP_QUERY 0x0a" rule). The frame trailer for 3.2/3.3 is **CRC32** (no hmac_key passed — `_encode_message` leaves `hmac_key=None` for <3.4).

- **3.2 quirk:** tinytuya/pytuya treat `version==3.2` as **device22 / type_0d** and immediately run available-DPS detection (`XenonDevice.py:1144-1147`, `pytuya:599-601`). Wire crypto is the same as 3.3.
- **Decrypt (RX):** if payload starts with `version_bytes` (e.g. `b"3.3"`), strip `len(version_header)` (15) bytes, then `cipher.decrypt(rest, use_base64=False)` (`XenonDevice.py:783-798`). A device22 header can also appear when `len(payload) & 0x0F != 0` (`XenonDevice.py:788`).
- **device22 detection:** if a decrypted reply contains `b"data unvalid"`, switch `dev_type` to `"device22"` and retry with a DP list (`XenonDevice.py:807-815`).

### 4.3 Protocol 3.4 — AES-128-ECB with negotiated session key + HMAC-SHA256 trailer

- Commands `CONTROL`→`CONTROL_NEW`, `DP_QUERY`→`DP_QUERY_NEW` (command_override, §6). Payload JSON is wrapped as `{"protocol":5,"t":<int>,"data":{"dps":...}}` (§6).
- Encrypt (`XenonDevice.py:959-975`):
```python
if self.version >= 3.4:
    hmac_key = self.local_key                          # = session key
    if msg.cmd not in NO_PROTOCOL_HEADER_CMDS:
        payload = self.version_header + payload         # b"3.4"+12×\x00 + json
    # (3.5 branch handled separately, below)
    payload = self.cipher.encrypt(payload, False)       # AES-128-ECB raw, key=session key
```
- The frame is packed **with `hmac_key = session key`**, so the trailer is **HMAC-SHA256(session_key, header..payload)** (32 bytes) — `pack_message` `message_helper.py:60-61`.
- **Decrypt (RX):** 3.4 encrypts the version header too, so decrypt the *entire* payload first (`cipher.decrypt(payload, False)`), then strip the 15-byte header if present (`XenonDevice.py:764-771`, then `:783-790`). The receive HMAC key is the session key (`XenonDevice.py:494`).

### 4.4 Protocol 3.5 — AES-GCM, session key, 6699 framing

- Same session-key negotiation as 3.4 (§5). Same `CONTROL_NEW`/`DP_QUERY_NEW` + `{"protocol":5,...}` payload shape.
- Encrypt (`XenonDevice.py:966-973`):
```python
if self.version >= 3.5:
    iv = True                                           # → real nonce generated in cipher
    msg = TuyaMessage(seqno, cmd, None, payload, 0, True, PREFIX_6699_VALUE, True)
    data = pack_message(msg, hmac_key=self.local_key)   # session key
```
  The version header **is** prepended for non-`NO_PROTOCOL_HEADER_CMDS` commands (the `payload = version_header + payload` at `:961-963` runs before the 3.5 branch).
- GCM in `pack_message` (§2.3): `AES-GCM(key=session_key, iv=12B, aad=header[4:])`, output = `iv(12) + ciphertext + tag(16)`, framed with `0x6699 … 0x9966`.
- **Nonce (IV) generation** (`crypto_helper.py:50-58`): if `iv is True`, use `str(time.time()*10)[:12]` (12 ASCII digits) in production; a fixed `b'0123456789ab'` when debug logging is on. **Reimplementation note:** any 12-byte value works as long as it's unique per key; Tuya uses a timestamp-derived ASCII string. On the wire the IV is sent in-band (first 12 bytes of the encrypted region), so the receiver just reads it.
- **Decrypt (RX):** the 6699 unpack path reads `iv = payload[:12]`, then `AES-GCM decrypt(key, iv, ciphertext, aad=header[4:header_len], tag)` (`message_helper.py:151-159`). Then the 15-byte `3.5` version header is stripped like 3.4.

### 4.5 AES cipher details (crypto_helper.py)

- **ECB:** `AES.new(key, MODE_ECB)`. Padding = PKCS#7-style: `padnum = 16 - len%16; data + padnum*chr(padnum)` (`crypto_helper.py:70-72`). Unpad reads the last byte as pad length (`:74-81`). base64 wrapping toggled by `use_base64`.
- **GCM:** `AES.new(key, MODE_GCM, nonce=iv)`, `.update(header)` for AAD, `encrypt_and_digest` → `(ciphertext, tag)`; output arranged `nonce + ciphertext + tag` (`crypto_helper.py:121-128`). Decrypt uses `decrypt_and_verify(ct, tag)` (`:144-148`).
- pyaes fallback cannot do GCM → 3.5 requires a GCM-capable lib (`crypto_helper.py:159-161`). In TS use Node `crypto` `createCipheriv('aes-128-gcm', key, iv)` + `setAAD` + `getAuthTag`.

---

## 5. Session-Key Negotiation (3.4 & 3.5)

3-step handshake performed **immediately after TCP connect**, before any command (`XenonDevice.py:394-397` calls `_negotiate_session_key()` on connect for `version >= 3.4`). tinytuya reference: `XenonDevice.py:875-947`; localtuya reference (3.4 only): `pytuya/__init__.py:970-1031`.

Fixed local nonce: `self.local_nonce = b'0123456789abcdef'` (16 bytes, "not-so-random random key" — `XenonDevice.py:286`, `pytuya:591`). Reimplementations may randomize it.

**Step 1 — client → device (`SESS_KEY_NEG_START` = 3):**
- Payload = `local_nonce` (16 bytes), sent through the normal `_encode_message` path (so for 3.4 it is AES-ECB-encrypted with the raw local_key + HMAC trailer keyed by the raw local_key; for 3.5 it is GCM with the raw local_key). At this point `self.local_key == real_local_key` (`XenonDevice.py:887`, `pytuya:971`).

**Step 2 — device → client (`SESS_KEY_NEG_RESP` = 4):**
- Response payload (after frame decrypt) is **≥ 48 bytes** = `remote_nonce(16) || HMAC-SHA256(local_key, local_nonce)(32)`.
- For **3.4**, the payload must additionally be **AES-ECB-decrypted with `real_local_key`** first (`XenonDevice.py:902-906`). For **3.5**, the 6699 frame decrypt already yields plaintext, so no extra ECB step.
- Client extracts `remote_nonce = payload[:16]` and verifies `payload[16:48] == HMAC-SHA256(local_key, local_nonce)` (`XenonDevice.py:918-922`, `pytuya:1007-1010`).

**Step 3 — client → device (`SESS_KEY_NEG_FINISH` = 5):**
- Payload = `HMAC-SHA256(local_key, remote_nonce)` (32 bytes) (`XenonDevice.py:927-928`, `pytuya:1018-1019`).

**Session-key derivation (finalize) — `XenonDevice.py:930-947`:**
```python
# 1. XOR the two 16-byte nonces
self.local_key = bytes([a ^ b for (a, b) in zip(self.local_nonce, self.remote_nonce)])

cipher = AESCipher(self.real_local_key)                  # cipher keyed by ORIGINAL local_key
if self.version == 3.4:
    # 2a. 3.4: AES-ECB-encrypt the XOR result with real_local_key, NO padding
    self.local_key = cipher.encrypt(self.local_key, use_base64=False, pad=False)          # 16 bytes
else:  # 3.5
    # 2b. 3.5: AES-GCM-encrypt the XOR result, iv = first 12 bytes of local_nonce,
    #     then take bytes [12:28] of (iv+ct+tag) = the 16-byte ciphertext
    iv = self.local_nonce[:12]
    self.local_key = cipher.encrypt(self.local_key, use_base64=False, pad=False, iv=iv)[12:28]
```
The resulting 16-byte `local_key` is the **session key** used as the AES key AND the HMAC key for all subsequent 3.4/3.5 traffic. (localtuya only implements the 3.4 ECB branch — `pytuya:1021-1029`.)

**Seqno note for 3.4:** the device returns the starting seqno in the `SESS_KEY_NEG_RESP`; the client adopts it (`self.seqno = msg.seqno` — `pytuya:725`).

**Connection lifecycle summary:**
```
3.1–3.3:  TCP connect → (optionally DP refresh) → DP_QUERY / CONTROL directly
3.4/3.5:  TCP connect → SESS_KEY_NEG_START → RESP → FINISH → derive session key → normal commands
```

---

## 6. Datapoints (DPs) & Command Payloads

`generate_payload(command, data, …)` builds the JSON, then `json.dumps(...).replace(" ", "")` — **spaces MUST be stripped or the device won't respond** — and UTF-8 encodes (`XenonDevice.py:1338-1345`; comment "if spaces are not removed device does not respond!"). `"t"` is the current unix time (`int(time.time())`, or string form).

### 6.1 Payload dicts (tinytuya `XenonDevice.py:144-234`)

**`default` device (3.1/3.3, "type_0a"):**
```python
CONTROL      → {"devId":"", "uid":"", "t":""}          # + "dps": {index: value}
STATUS       → {"gwId":"", "devId":""}
HEART_BEAT   → {"gwId":"", "devId":""}
DP_QUERY     → {"gwId":"", "devId":"", "uid":"", "t":""}
CONTROL_NEW  → {"devId":"", "uid":"", "t":""}
DP_QUERY_NEW → {"devId":"", "uid":"", "t":""}
UPDATEDPS    → {"dpId":[18,19,20]}
LAN_EXT_STREAM → {"reqType":"", "data":{}}
```

**`device22` / `type_0d` (22-char IDs, and 3.2):**
```python
DP_QUERY → command_override = CONTROL_NEW,  command = {"devId":"","uid":"","t":""}, plus "dps": dps_to_request
```
i.e. these devices answer DP_QUERY only via the `0x0d` command, and you must send the list of DP indices (each `None`) in the request.

**`v3.4` / `v3.5`:**
```python
CONTROL      → command_override = CONTROL_NEW,  command = {"protocol":5, "t":"int", "data":{}}
CONTROL_NEW  → {"protocol":5, "t":"int", "data":{}}
DP_QUERY     → command_override = DP_QUERY_NEW, command = {}      # empty object → "{}"
DP_QUERY_NEW → {}
```
For `data`, the DPs go into `json_data["data"]["dps"] = {index: value}` (`XenonDevice.py:1330`). So a 3.4/3.5 CONTROL body is:
```json
{"protocol":5,"t":1699999999,"data":{"dps":{"1":true}}}
```
(localtuya builds `{"protocol":5,"t":<int>,"data":{"dps": <data>}}` — `pytuya:214, 1147-1148`.)

**`zigbee` sub-devices:** add `"cid"` at top level, and for 3.4/3.5 also `data.cid` + `data.ctype=0` (`XenonDevice.py:212-233, 1312-1316`).

### 6.2 Set / Get semantics

- **Set one DP:** `CONTROL` (or `CONTROL_NEW` on 3.4/3.5) with `{"dps":{index:value}}`. tinytuya `set_value(index,value)`; localtuya `set_dp(value, dp_index) → exchange(CONTROL, {str(dp_index): value})` (`pytuya:834-842`).
- **Set multiple DPs:** `set_dps(dps)` → `CONTROL` with a full `{"dps":{...}}` dict (`pytuya:844-846`).
- **Get status:** `DP_QUERY` (→ `DP_QUERY_NEW` on 3.4/3.5). `status()` = `exchange(DP_QUERY)` (`pytuya:793-798`).
- **Request DP refresh:** `UPDATEDPS` (0x12) with `{"dpId":[...]}`. Whitelist `[18,19,20]` (Wi-Fi sockets) (`pytuya:167, 813-832`).

### 6.3 Status decode → `{"dps":{...}}`

- 3.1/3.2/3.3: decrypted JSON is directly `{"dps":{"1":true,"2":50,...}, "devId":..., "t":...}`.
- 3.4/3.5: device wraps it as `{"protocol":5,"t":...,"data":{"dps":{...}}}` or `{"data":{"dps":{...}}}`. The decoder normalizes: `if "dps" not in json and "data" in json and "dps" in json["data"]: json["dps"] = json["data"]["dps"]` (`XenonDevice.py:850-852`, `pytuya:960-966`).
- `dps` keys are **strings** ("1","2",…); values are bool/int/float/string per the device's DP schema.

### 6.4 Heartbeat

- Command `HEART_BEAT` (9), body `{"gwId":"","devId":""}`. It is in `NO_PROTOCOL_HEADER_CMDS` (no version header).
- **Cadence:** `HEARTBEAT_INTERVAL = 10` seconds (`pytuya:164`); localtuya's `heartbeat_loop` sends every 10s and disconnects on timeout (`pytuya:642-663`). tinytuya sends on demand / persistent-socket keepalive.
- Heartbeat/CONTROL replies are frequently **empty-payload ACKs** — treat a 0-length payload for `HEART_BEAT`/`CONTROL`/`CONTROL_NEW` as an ACK, not data (`pytuya:775-779`; tinytuya `_send_receive` treats a 28-byte null response as ACK).

---

## 7. Sequence Numbers, Retcode, Response Matching

- `seqno` starts at 1 and increments per sent message (`XenonDevice.py:280, 1005`; `pytuya:584, 1074`).
- **Matching:** localtuya keys pending requests by seqno in a dispatcher; special negative sentinels for messages the device answers with seqno 0 or a fresh seqno: `HEARTBEAT_SEQNO=-100`, `RESET_SEQNO=-101` (UPDATEDPS), `SESS_KEY_SEQNO=-102` (`pytuya:418-420, 442-458`). Unsolicited `STATUS` (0x08) pushes are routed to the async listener (`pytuya:507-515`).
- **Retcode:** received 55AA messages carry a `uint32` retcode right after the header (0 = OK). tinytuya matches it to the sent cmd, and for `< 3.5` also requires `sent.seqno == msg.seqno`; **3.5 devices reply with a global incrementing seqno, not the sent one**, so seqno matching is skipped (`XenonDevice.py:1010-1020`).
- Devices may emit a **null/ACK packet before the real response**; readers retry receive up to the socket retry limit before giving up (`XenonDevice.py:605-611`).

---

## 8. UDP Discovery

### 8.1 The well-known UDP key

```python
udpkey = md5(b"yGAdlopoPVldABfn").digest()      # 16 bytes, AES-128-ECB key for UDP broadcasts
```
`tinytuya/core/crypto_helper.py`-adjacent `udp_helper.py:21`; localtuya `UDP_KEY = md5(b"yGAdlopoPVldABfn").digest()` — `pytuya/discovery.py:17`. (Credit: tuya-convert.)

### 8.2 Passive listen (devices auto-broadcast)

Devices periodically broadcast their presence. Bind UDP:
- **6666** (unencrypted-ish, older 3.1) and **6667** (encrypted, 3.2+/3.3). tinytuya also binds **7000** (app / 3.5) — `scanner.py:1202,1213,1224`. localtuya binds 6666 + 6667 with `reuse_port` — `discovery.py:47-49`.

**Frame:** the broadcast is a **standard 55AA frame** (or 6699 for 3.5). Two decode approaches:

- **localtuya (fixed offsets):** `data = data[20:-8]` (strip 20-byte header incl. retcode, strip 8-byte crc+suffix), then AES-ECB-decrypt with `udpkey` and `_unpad`, then `json.loads`. If decrypt throws, fall back to `data.decode()` (unencrypted 6666 packets) — `discovery.py:61-69`.
- **tinytuya (`decrypt_udp`, robust):** parse the header; if 55AA, `unpack_message(msg).payload`; if the payload already looks like JSON (`{`…`}`) return it as-is, else AES-ECB-decrypt with `udpkey`; if 6699, `unpack_message(msg, hmac_key=udpkey, no_retcode=None)` (GCM) and strip trailing NULs — `udp_helper.py:23-45`. The scanner just calls `decrypt_udp(data)` then `json.loads` — `scanner.py:1534-1535`.

### 8.3 Active pull for v3.5 (tinytuya)

Some v3.5 devices only respond when asked. Broadcast a `REQ_DEVINFO` (0x25) **6699/GCM** packet to `<broadcast>:7000`, keyed by `udpkey`, payload `{"from":"app","ip":"<my-ip>"}` (`scanner.py:242-251`). Devices then reply on 7000. Rebroadcast every `BROADCASTTIME = 6` s (`scanner.py:81`).

### 8.4 Announced JSON fields

Discovery JSON contains (all optional except `gwId`):
```
gwId, ip, active, ability (often misspelled "ablilty"), encrypt, productKey, version, token, wf_cfg, mac, name
```
- Field list: `devinfo_keys = ('ip','mac','name','key','gwId','active','ability','encrypt','productKey','version','token','wf_cfg')` — `scanner.py:86`. The typo `"ablilty"` is normalized to `"ability"` (`scanner.py:309-312`).
- `gwId` is the device ID (required; packets without it are dropped — `scanner.py:1554-1558`, localtuya keys `devices[gwId]` — `discovery.py:73-74`).
- `version` is the protocol version string (`"3.1"`,`"3.3"`,`"3.4"`,`"3.5"`); missing → default `3.1` (`scanner.py:318-319`). The **local_key is NOT in the broadcast** — you must supply it out-of-band (Tuya cloud / manual).
- App-origin packets carry `{"from":"app",...}` and are filtered out (`scanner.py:1547-1552`).

---

## 9. TypeScript Reimplementation Checklist

1. **Frame codec:** implement 55AA (`>4I` header, CRC32 or 32-byte HMAC trailer, `AA55` suffix) and 6699 (`>IHIII` header, 12B IV + GCM ct + 16B tag, `9966` suffix). Big-endian throughout.
2. **On RX 55AA:** strip 4-byte retcode after header before decrypt.
3. **Crypto:** AES-128-ECB (raw key, PKCS7 pad) for 3.1/3.2/3.3/3.4 payloads; AES-128-GCM for 3.5 + 6699 frames (AAD = header bytes `[4:]`). Node: `aes-128-ecb`, `aes-128-gcm`.
4. **Version header:** `"<ver>" + 12×0x00` (15 bytes) prepended to every command **except** the `NO_PROTOCOL_HEADER_CMDS` set. 3.4/3.5 encrypt the header along with the payload.
5. **3.1 CONTROL only:** base64 ECB + `"3.1" + md5(b"data="+b64+"||lpv=3.1||"+key)[8:24] + b64`.
6. **3.4/3.5:** run the 3-step session-key handshake right after connect; derive session key by XOR of nonces then ECB-encrypt (3.4) / GCM-encrypt-and-take-`[12:28]` (3.5) with the raw local_key; use the session key as both AES key and HMAC key thereafter.
7. **Payloads:** `JSON.stringify` then remove ALL spaces; `t` = unix seconds; 3.4/3.5 wrap DPs in `{"protocol":5,"t":…,"data":{"dps":{…}}}`.
8. **Get** = `DP_QUERY`/`DP_QUERY_NEW`; **Set** = `CONTROL`/`CONTROL_NEW` `{"dps":{i:v}}`; heartbeat = `HEART_BEAT` every 10 s; tolerate empty-payload ACKs.
9. **Discovery:** listen UDP 6666/6667(/7000); decrypt with `md5("yGAdlopoPVldABfn")` (AES-128-ECB, or GCM for 6699); parse `gwId/ip/version/productKey/active/ability`; obtain local_key separately.

---

## Appendix: Source File Map

| Concern | tinytuya | localtuya pytuya |
|---|---|---|
| Command constants | `core/command_types.py` | `__init__.py:114-135` |
| Ports / consts | `core/const.py` | (inline / `discovery.py`) |
| Prefixes, formats, headers | `core/header.py` | `__init__.py:138-162` |
| pack/unpack/parse frame | `core/message_helper.py` | `__init__.py:266-375` |
| AES ECB + GCM | `core/crypto_helper.py` | `__init__.py:378-409` (ECB only) |
| UDP key + decrypt_udp | `core/udp_helper.py` | `discovery.py:17-30` |
| Device logic, payloads, session key, encode/decode | `core/XenonDevice.py` | `__init__.py:412-1197` |
| UDP scan / v3.5 pull | `scanner.py` | `discovery.py` |
</content>
</invoke>
