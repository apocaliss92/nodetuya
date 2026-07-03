import { describe, it, expect } from 'vitest';
import { createDumper } from '../../src/diagnostics/dumper.js';
import { TuyaDevice } from '../../src/device/tuya-device.js';

describe('createDumper', () => {
  it('redacts the device id by default and reports fields', () => {
    const device = new TuyaDevice({
      id: 'bf1234567890abcdef',
      key: '0123456789abcdef',
      host: '192.168.1.9',
      version: '3.3',
    });
    const dump = createDumper(device).dump();
    expect(dump.id).toBe('**************cdef');
    expect(dump.host).toBe('192.168.1.9');
    expect(dump.version).toBe('3.3');
    expect(dump.connected).toBe(false);
    expect(dump.dps).toEqual({});
  });
  it('keeps the id when redact is false', () => {
    const device = new TuyaDevice({ id: 'abc', key: 'k', host: 'h', version: '3.3' });
    expect(createDumper(device, { redact: false }).dump().id).toBe('abc');
  });
});
