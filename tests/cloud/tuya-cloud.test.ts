import { describe, it, expect } from 'vitest';
import { TuyaCloud } from '../../src/cloud/tuya-cloud.js';
import { TuyaCloudError } from '../../src/transport/errors.js';
import type { CloudFetch } from '../../src/cloud/types.js';

function routed(handlers: Array<{ match: string; body: unknown }>, calls: any[] = []): CloudFetch {
  return async (url, options) => {
    calls.push({ url, method: options.method, headers: options.headers });
    const hit = handlers.find((h) => url.includes(h.match));
    return {
      statusCode: 200,
      json: async () => hit?.body ?? { success: false, msg: 'no route', code: 404 },
    };
  };
}

const TOKEN_OK = {
  match: '/v1.0/token',
  body: { success: true, result: { access_token: 'TKN', expire_time: 7200, uid: 'u1' } },
};

describe('TuyaCloud', () => {
  it('getToken signs without a token, caches, and returns it', async () => {
    const calls: any[] = [];
    const cloud = new TuyaCloud({
      accessId: 'aid',
      accessSecret: 'sec',
      region: 'eu',
      fetchImpl: routed([TOKEN_OK], calls),
    });
    const t1 = await cloud.getToken(1_000_000);
    const t2 = await cloud.getToken(1_000_000); // cached — no second token call
    expect(t1).toBe('TKN');
    expect(t2).toBe('TKN');
    expect(calls.filter((c) => c.url.includes('/v1.0/token'))).toHaveLength(1);
    // token request carries the signing headers but NO access_token
    expect(calls[0].headers.sign).toMatch(/^[0-9A-F]{64}$/);
    expect(calls[0].headers.access_token).toBeUndefined();
    expect(calls[0].url).toContain('openapi.tuyaeu.com');
  });

  it('getDevices maps local_key + fields and attaches the access token', async () => {
    const calls: any[] = [];
    const cloud = new TuyaCloud({
      accessId: 'aid',
      accessSecret: 'sec',
      fetchImpl: routed(
        [
          TOKEN_OK,
          {
            match: 'associated-users/devices',
            body: {
              success: true,
              result: {
                has_more: false,
                devices: [
                  {
                    id: 'dev1',
                    name: 'Switch',
                    local_key: 'KEY123456789abc',
                    ip: '192.168.1.5',
                    category: 'kg',
                    product_id: 'p1',
                    online: true,
                    node_id: 'n1',
                  },
                ],
              },
            },
          },
        ],
        calls,
      ),
    });
    const devices = await cloud.getDevices();
    expect(devices).toHaveLength(1);
    expect(devices[0]).toMatchObject({
      id: 'dev1',
      name: 'Switch',
      localKey: 'KEY123456789abc',
      ip: '192.168.1.5',
      category: 'kg',
      online: true,
      nodeId: 'n1',
    });
    const devCall = calls.find((c) => c.url.includes('associated-users/devices'));
    expect(devCall.headers.access_token).toBe('TKN');
  });

  it('paginates when has_more is set', async () => {
    let page = 0;
    const fetchImpl: CloudFetch = async (url) => {
      if (url.includes('/v1.0/token')) return { statusCode: 200, json: async () => TOKEN_OK.body };
      page += 1;
      const body =
        page === 1
          ? {
              success: true,
              result: {
                has_more: true,
                last_row_key: 'RK',
                devices: [{ id: 'a', local_key: 'k' }],
              },
            }
          : { success: true, result: { has_more: false, devices: [{ id: 'b', local_key: 'k' }] } };
      return { statusCode: 200, json: async () => body };
    };
    const cloud = new TuyaCloud({ accessId: 'aid', accessSecret: 'sec', fetchImpl });
    const devices = await cloud.getDevices();
    expect(devices.map((d) => d.id)).toEqual(['a', 'b']);
  });

  it('throws TuyaCloudError on a non-success envelope', async () => {
    const cloud = new TuyaCloud({
      accessId: 'aid',
      accessSecret: 'bad',
      fetchImpl: routed([
        { match: '/v1.0/token', body: { success: false, code: 1004, msg: 'sign invalid' } },
      ]),
    });
    await expect(cloud.getToken()).rejects.toBeInstanceOf(TuyaCloudError);
  });
});
