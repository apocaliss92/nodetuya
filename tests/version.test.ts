import { describe, it, expect } from 'vitest';
import { LIBRARY_NAME } from '../src/support/version.js';
describe('version', () => {
  it('name', () => {
    expect(LIBRARY_NAME).toBe('nodetuya');
  });
});
