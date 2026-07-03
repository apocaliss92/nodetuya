export class TuyaError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TuyaError';
  }
}
/** Framing / decrypt / CRC / HMAC failure while parsing a device message. */
export class TuyaProtocolError extends TuyaError {
  constructor(message: string) {
    super(message);
    this.name = 'TuyaProtocolError';
  }
}
/** TCP connect / timeout / socket failure. */
export class TuyaTransportError extends TuyaError {
  constructor(message: string) {
    super(message);
    this.name = 'TuyaTransportError';
  }
}
/** Session-key negotiation (3.4/3.5) failure or wrong local key. */
export class TuyaAuthError extends TuyaError {
  constructor(message: string) {
    super(message);
    this.name = 'TuyaAuthError';
  }
}
/** Tuya IoT Cloud API failure (bad credentials, region mismatch, or a non-success response). */
export class TuyaCloudError extends TuyaError {
  /** Tuya application error code (e.g. 1004 = sign invalid, 1106 = permission), when available. */
  readonly code?: number;
  constructor(message: string, code?: number) {
    super(message);
    this.name = 'TuyaCloudError';
    this.code = code;
  }
}
