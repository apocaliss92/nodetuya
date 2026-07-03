import { describe, it, expect } from 'vitest';
import * as pkg from '../src/index.js';

describe('public API surface', () => {
  it('exports device, discovery, errors, helpers', () => {
    const names = [
      'LIBRARY_NAME',
      'TuyaDevice',
      'discoverDevices',
      'DISCOVERY_PORTS',
      'createDgramBinder',
      'decodeDiscovery',
      'TuyaError',
      'TuyaProtocolError',
      'TuyaTransportError',
      'TuyaAuthError',
      'CommandType',
      'createDumper',
    ];
    for (const n of names) expect(pkg, `missing export: ${n}`).toHaveProperty(n);
    expect(pkg.LIBRARY_NAME).toBe('nodetuya');
  });
  it('does not leak protocol internals', () => {
    expect(pkg).not.toHaveProperty('TuyaCodec');
    expect(pkg).not.toHaveProperty('encode55AA');
    expect(pkg).not.toHaveProperty('aesEcbEncrypt');
  });
});
