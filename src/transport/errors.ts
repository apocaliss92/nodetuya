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
