import { describe, it, expect } from 'vitest';
import { buildRequest, normalizeStatus, nowSeconds } from '../../src/protocol/payloads.js';
import { CommandType } from '../../src/protocol/commands.js';

describe('buildRequest', () => {
  it('3.3 get → DP_QUERY with the flat gwId body', () => {
    const { command, body } = buildRequest('3.3', 'get', 'devId1', undefined, 1_700_000_000_000);
    expect(command).toBe(CommandType.DP_QUERY);
    expect(body).toMatchObject({ gwId: 'devId1', devId: 'devId1', uid: 'devId1' });
  });
  it('3.3 set → CONTROL with the dps map', () => {
    const { command, body } = buildRequest('3.3', 'set', 'devId1', { '1': true });
    expect(command).toBe(CommandType.CONTROL);
    expect(body.dps).toEqual({ '1': true });
  });
  it('3.4 get → DP_QUERY_NEW with the protocol envelope', () => {
    const { command, body } = buildRequest('3.4', 'get', 'd', undefined);
    expect(command).toBe(CommandType.DP_QUERY_NEW);
    expect(body).toMatchObject({ protocol: 4, data: { dps: {} } });
  });
  it('3.5 set → CONTROL_NEW with the protocol envelope', () => {
    const { command, body } = buildRequest('3.5', 'set', 'd', { '2': 25 });
    expect(command).toBe(CommandType.CONTROL_NEW);
    expect(body).toMatchObject({ protocol: 5, data: { dps: { '2': 25 } } });
  });
});

describe('normalizeStatus', () => {
  it('reads a flat dps map', () => {
    expect(normalizeStatus({ dps: { '1': true } })).toEqual({ '1': true });
  });
  it('unwraps the 3.4/3.5 data.dps envelope', () => {
    expect(normalizeStatus({ data: { dps: { '2': 50 } } })).toEqual({ '2': 50 });
  });
  it('returns {} when there is no dps', () => {
    expect(normalizeStatus({ t: 1 })).toEqual({});
  });
});

describe('nowSeconds', () => {
  it('converts ms to whole seconds', () => {
    expect(nowSeconds(1_700_000_000_000)).toBe(1_700_000_000);
  });
});
