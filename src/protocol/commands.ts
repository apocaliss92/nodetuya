// Command codes + framing constants, transcribed from tinytuya core/command_types.py + header.py.

export const CommandType = {
  AP_CONFIG: 1,
  ACTIVE: 2,
  SESS_KEY_NEG_START: 3,
  SESS_KEY_NEG_RESP: 4,
  SESS_KEY_NEG_FINISH: 5,
  UNBIND: 6,
  CONTROL: 7,
  STATUS: 8,
  HEART_BEAT: 9,
  DP_QUERY: 0x0a,
  QUERY_WIFI: 0x0b,
  TOKEN_BIND: 0x0c,
  CONTROL_NEW: 0x0d,
  ENABLE_WIFI: 0x0e,
  DP_QUERY_NEW: 0x10,
  SCENE_EXECUTE: 0x11,
  UPDATEDPS: 0x12,
  REQ_DEVINFO: 0x25,
  LAN_EXT_STREAM: 0x40,
} as const;

export type Command = (typeof CommandType)[keyof typeof CommandType];

// Frame prefixes/suffixes (big-endian uint32).
export const PREFIX_55AA = 0x000055aa;
export const SUFFIX_55AA = 0x0000aa55;
export const PREFIX_6699 = 0x00006699;
export const SUFFIX_6699 = 0x00009966;

/** Commands that do NOT get the version header prepended (header.py NO_PROTOCOL_HEADER_CMDS). */
export const NO_HEADER_COMMANDS: ReadonlySet<number> = new Set([
  CommandType.DP_QUERY,
  CommandType.DP_QUERY_NEW,
  CommandType.UPDATEDPS,
  CommandType.HEART_BEAT,
  CommandType.SESS_KEY_NEG_START,
  CommandType.SESS_KEY_NEG_RESP,
  CommandType.SESS_KEY_NEG_FINISH,
  CommandType.LAN_EXT_STREAM,
]);

/** 15-byte version header: `"<ver>" + 12×0x00` (e.g. `b"3.3\x00…"`). */
export function versionHeader(version: string): Buffer {
  return Buffer.concat([Buffer.from(version, 'ascii'), Buffer.alloc(12, 0)]);
}
