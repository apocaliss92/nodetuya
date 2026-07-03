import { Socket } from 'node:net';
import { TypedEmitter } from '../transport/typed-emitter.js';
import { hmacSha256, aesEcbEncrypt, aesGcmEncrypt } from '../transport/crypto.js';
import { TuyaAuthError, TuyaTransportError } from '../transport/errors.js';
import { CommandType } from '../protocol/commands.js';
import { TuyaCodec, type DecodedMessage } from '../protocol/codec.js';
import { splitFrames } from '../protocol/frame.js';
import { buildRequest, heartbeatBody, normalizeStatus } from '../protocol/payloads.js';

const TUYA_PORT = 6668;
const HEARTBEAT_MS = 10_000;
const DEFAULT_TIMEOUT_MS = 5_000;
const LOCAL_NONCE = Buffer.from('0123456789abcdef');

export interface TuyaDeviceOptions {
  /** Device id (`gwId`/`devId`). */
  id: string;
  /** 16-char local key from the Tuya cloud. */
  key: string;
  /** Device IP / host on the LAN. */
  host: string;
  /** Protocol version: `3.1` | `3.2` | `3.3` | `3.4` | `3.5` (default `3.3`). */
  version?: string;
  /** TCP port (default 6668). */
  port?: number;
  /** Per-request timeout in ms (default 5000). */
  timeoutMs?: number;
}

export interface TuyaDeviceEvents extends Record<string, unknown> {
  /** Latest datapoint map (from a status reply or an unsolicited push). */
  dps: Record<string, unknown>;
  connected: void;
  disconnected: void;
  error: Error;
}

interface Pending {
  match: (m: DecodedMessage) => boolean;
  resolve: (m: DecodedMessage) => void;
  reject: (e: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

/**
 * A single Tuya device on the LAN. Open the connection with {@link connect} (which runs the 3.4/3.5
 * session-key handshake automatically), then {@link get} / {@link set}. Unsolicited status pushes
 * are emitted as `dps` events.
 */
export class TuyaDevice extends TypedEmitter<TuyaDeviceEvents> {
  private readonly version: string;
  private readonly port: number;
  private readonly timeoutMs: number;
  private readonly codec: TuyaCodec;
  private socket: Socket | null = null;
  private buffer = Buffer.alloc(0);
  private seqno = 1;
  private readonly pending: Pending[] = [];
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private lastDps: Record<string, unknown> = {};

  constructor(private readonly opts: TuyaDeviceOptions) {
    super();
    this.version = opts.version ?? '3.3';
    this.port = opts.port ?? TUYA_PORT;
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.codec = new TuyaCodec(this.version, Buffer.from(opts.key, 'utf8'));
  }

  /** Open the TCP connection and (for 3.4/3.5) negotiate the session key. */
  async connect(): Promise<void> {
    await this.openSocket();
    if (this.version === '3.4' || this.version === '3.5') await this.negotiateSessionKey();
    this.startHeartbeat();
    this.emit('connected', undefined);
  }

  /** Query the device and return its current datapoint map. */
  async get(): Promise<Record<string, unknown>> {
    const { command, body } = buildRequest(this.version, 'get', this.opts.id, undefined);
    const reply = await this.request(command, body, (m) => hasDps(m));
    this.lastDps = normalizeStatus(reply.payload ?? {});
    return this.lastDps;
  }

  /** Set one or more datapoints, e.g. `set({ '1': true, '2': 50 })`. */
  async set(dps: Record<string, unknown>): Promise<void> {
    const { command, body } = buildRequest(this.version, 'set', this.opts.id, dps);
    await this.request(
      command,
      body,
      (m) =>
        m.command === CommandType.CONTROL || m.command === CommandType.CONTROL_NEW || hasDps(m),
    );
  }

  /** Set a single datapoint by index. */
  setDp(index: number | string, value: unknown): Promise<void> {
    return this.set({ [String(index)]: value });
  }

  /** The last datapoint map seen (from the most recent `get`/push). */
  get dps(): Readonly<Record<string, unknown>> {
    return this.lastDps;
  }

  get id(): string {
    return this.opts.id;
  }
  get host(): string {
    return this.opts.host;
  }
  get protocolVersion(): string {
    return this.version;
  }
  get connected(): boolean {
    return this.socket !== null;
  }

  /** Close the connection. */
  disconnect(): void {
    this.stopHeartbeat();
    for (const p of this.pending.splice(0)) {
      clearTimeout(p.timer);
      p.reject(new TuyaTransportError('disconnected'));
    }
    this.socket?.destroy();
    this.socket = null;
    this.emit('disconnected', undefined);
  }

  // --- internals -------------------------------------------------------------

  private openSocket(): Promise<void> {
    return new Promise((resolve, reject) => {
      const socket = new Socket();
      socket.setNoDelay(true);
      const onError = (err: Error): void =>
        reject(new TuyaTransportError(`connect failed: ${err.message}`));
      socket.once('error', onError);
      socket.connect(this.port, this.opts.host, () => {
        socket.off('error', onError);
        socket.on('data', (chunk) => this.onData(chunk));
        socket.on('error', (err) => this.emit('error', err));
        socket.on('close', () => this.handleClose());
        this.socket = socket;
        resolve();
      });
    });
  }

  private onData(chunk: Buffer): void {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    const { frames, rest } = splitFrames(this.buffer);
    this.buffer = Buffer.concat([rest]); // normalize the Buffer generic (subarray widens it)
    for (const frame of frames) {
      let msg: DecodedMessage;
      try {
        msg = this.codec.decode(frame);
      } catch (err) {
        this.emit('error', err instanceof Error ? err : new Error(String(err)));
        continue;
      }
      this.dispatch(msg);
    }
  }

  private dispatch(msg: DecodedMessage): void {
    // Resolve the first matching pending request (seqno-agnostic: 3.5 uses a global seqno).
    const idx = this.pending.findIndex((p) => p.match(msg));
    if (idx >= 0) {
      const [p] = this.pending.splice(idx, 1);
      clearTimeout(p!.timer);
      p!.resolve(msg);
    }
    if (hasDps(msg)) {
      const dps = normalizeStatus(msg.payload!);
      if (Object.keys(dps).length > 0) {
        this.lastDps = { ...this.lastDps, ...dps };
        this.emit('dps', dps);
      }
    }
  }

  private request(
    command: number,
    data: Record<string, unknown> | Buffer,
    match: (m: DecodedMessage) => boolean,
  ): Promise<DecodedMessage> {
    return new Promise((resolve, reject) => {
      if (!this.socket) {
        reject(new TuyaTransportError('not connected'));
        return;
      }
      const timer = setTimeout(() => {
        const i = this.pending.findIndex((p) => p.timer === timer);
        if (i >= 0) this.pending.splice(i, 1);
        reject(new TuyaTransportError(`request 0x${command.toString(16)} timed out`));
      }, this.timeoutMs);
      this.pending.push({ match, resolve, reject, timer });
      this.write(command, data);
    });
  }

  private write(command: number, data: Record<string, unknown> | Buffer): void {
    const frame = this.codec.encode(this.seqno, command, data);
    this.seqno += 1;
    this.socket?.write(frame);
  }

  private async negotiateSessionKey(): Promise<void> {
    const resp = await this.request(
      CommandType.SESS_KEY_NEG_START,
      LOCAL_NONCE,
      (m) => m.command === CommandType.SESS_KEY_NEG_RESP,
    );
    const body = resp.raw;
    if (body.length < 48) throw new TuyaAuthError('session negotiation: short response');
    const remoteNonce = body.subarray(0, 16);
    const remoteHmac = body.subarray(16, 48);
    const localKey = Buffer.from(this.opts.key, 'utf8');
    if (!hmacSha256(localKey, LOCAL_NONCE).equals(remoteHmac)) {
      throw new TuyaAuthError('session negotiation: HMAC mismatch (wrong local key?)');
    }
    this.write(CommandType.SESS_KEY_NEG_FINISH, hmacSha256(localKey, remoteNonce));

    const xored = Buffer.alloc(16);
    for (let i = 0; i < 16; i += 1) xored[i] = LOCAL_NONCE[i]! ^ remoteNonce[i]!;
    const sessionKey =
      this.version === '3.4'
        ? aesEcbEncrypt(localKey, xored, false)
        : aesGcmEncrypt(localKey, LOCAL_NONCE.subarray(0, 12), xored, Buffer.alloc(0)).subarray(
            12,
            28,
          );
    this.codec.setSessionKey(sessionKey);
  }

  private startHeartbeat(): void {
    this.heartbeatTimer = setInterval(() => {
      try {
        this.write(CommandType.HEART_BEAT, heartbeatBody(this.opts.id));
      } catch {
        /* ignore */
      }
    }, HEARTBEAT_MS);
  }
  private stopHeartbeat(): void {
    if (this.heartbeatTimer) clearInterval(this.heartbeatTimer);
    this.heartbeatTimer = null;
  }

  private handleClose(): void {
    this.stopHeartbeat();
    this.socket = null;
    // Fail any in-flight requests fast instead of waiting for their timeout. A reset right after
    // connect usually means the device is already connected elsewhere (Tuya allows one TCP client).
    for (const p of this.pending.splice(0)) {
      clearTimeout(p.timer);
      p.reject(
        new TuyaTransportError(
          'connection closed by device (already connected elsewhere, e.g. Home Assistant?)',
        ),
      );
    }
    this.emit('disconnected', undefined);
  }
}

function hasDps(m: DecodedMessage): boolean {
  const p = m.payload;
  if (!p) return false;
  if (p.dps && typeof p.dps === 'object') return true;
  const data = p.data as Record<string, unknown> | undefined;
  return !!(data && typeof data === 'object' && data.dps);
}
