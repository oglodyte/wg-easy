import { createApp, createRouter, toWebHandler } from 'h3';
import { afterEach, describe, expect, test, vi } from 'vitest';

import { policyDatabase, syntheticKey } from '../helpers/policyDatabase';

import { ClientUpdateSchema } from '#db/repositories/client/types';
import { deriveClientPublicKey } from '#server/utils/clientCredentials';
import createClient from '#server/api/client/index.post';
import updateClient from '#server/api/client/[clientId]/index.post';
import getClient from '#server/api/client/[clientId]/index.get';

const state = vi.hoisted(() => ({
  database: null as unknown,
  user: { id: 1, role: 1 },
}));
vi.mock('#server/utils/config', () => ({
  WG_ENV: { WG_EXECUTABLE: 'awg', PORT: 51821 },
}));
vi.mock('#server/utils/Database', () => ({
  default: new Proxy(
    {},
    { get: (_, key) => Reflect.get(state.database as object, key) }
  ),
}));
vi.mock('#server/utils/session', () => ({
  getCurrentUser: async () => state.user,
}));
vi.mock('@intlify/h3', () => ({
  useTranslation: async () => (key: string) => key,
}));
vi.mock('#server/utils/WireGuard', () => ({
  default: {
    requestReconcile: vi.fn(async () => ({
      success: true,
      revision: 1,
      runtime: { status: 'pending', appliedRevision: 0 },
    })),
    dumpClient: vi.fn(async () => undefined),
  },
}));
const databases: Awaited<ReturnType<typeof policyDatabase>>[] = [];
afterEach(async () => {
  for (const db of databases.splice(0)) await db.close();
  vi.restoreAllMocks();
  state.user = { id: 1, role: 1 };
});
async function fixture() {
  const f = await policyDatabase();
  databases.push(f);
  state.database = f;
  const router = createRouter()
      .post('/api/client', createClient)
      .post('/api/client/:clientId', updateClient)
      .get('/api/client/:clientId', getClient),
    handler = toWebHandler(createApp().use(router));
  return {
    ...f,
    async request(method: string, url: string, body?: unknown) {
      return handler(
        new Request(`http://fixture.test${url}`, {
          method,
          ...(body === undefined
            ? {}
            : {
                headers: { 'content-type': 'application/json' },
                body: JSON.stringify(body),
              }),
        })
      );
    },
  };
}
describe('permission-protected complete client routes', () => {
  test('creates from a supplied key through the existing permission gate and exposes no saved secrets in the response or detail editor', async () => {
    const f = await fixture(),
      privateKey = syntheticKey(),
      psk = syntheticKey(),
      response = await f.request('POST', '/api/client', {
        name: 'API supplied',
        privateKey,
        preSharedKey: psk,
      });
    expect(response.status).toBe(200);
    const result = await response.json(),
      row = (await f.clients.get(result.clientId))!;
    expect(
      row.privateKey === privateKey &&
        row.publicKey === deriveClientPublicKey(privateKey) &&
        row.preSharedKey === psk
    ).toBe(true);
    expect(
      JSON.stringify(result).includes(privateKey) ||
        JSON.stringify(result).includes(psk)
    ).toBe(false);
    const detailResponse = await f.request('GET', `/api/client/${row.id}`),
      detail = await detailResponse.json();
    expect(detailResponse.status).toBe(200);
    expect(
      Object.hasOwn(detail, 'privateKey') ||
        Object.hasOwn(detail, 'preSharedKey')
    ).toBe(false);
    expect(detail.hasPreSharedKey).toBe(true);
    expect(detail.publicKey === row.publicKey).toBe(true);
  });
  test('denies creation and another owner’s replacement before writes, but permits replacement of an owned client', async () => {
    const f = await fixture(),
      row = await f.createClient('owned'),
      privateKey = syntheticKey(),
      data = { ...ClientUpdateSchema.parse(row), privateKey };
    state.user = { id: 9, role: 2 };
    expect(
      (
        await f.request('POST', '/api/client', {
          name: 'forbidden',
          privateKey,
        })
      ).status
    ).toBe(403);
    expect(
      (await f.request('POST', `/api/client/${row.id}`, data)).status
    ).toBe(403);
    expect((await f.clients.get(row.id))!.privateKey === row.privateKey).toBe(
      true
    );
    expect((await f.clients.getAllPublic()).length).toBe(1);
    state.user = { id: row.userId, role: 2 };
    expect(
      (await f.request('POST', `/api/client/${row.id}`, data)).status
    ).toBe(200);
    expect((await f.clients.get(row.id))!.privateKey === privateKey).toBe(true);
  });
  test('returns safe conflict/mismatch and backend-error responses without persisting partial credentials', async () => {
    const f = await fixture(),
      row = await f.createClient('stable'),
      privateKey = syntheticKey();
    const mismatch = await f.request('POST', `/api/client/${row.id}`, {
      ...ClientUpdateSchema.parse(row),
      privateKey,
      publicKey: deriveClientPublicKey(syntheticKey()),
    });
    expect(mismatch.status).toBe(400);
    expect((await mismatch.json()).data.code).toBe('key_mismatch');
    vi.spyOn(f.clients, 'update').mockRejectedValue(
      new Error(`driver private bind ${privateKey}`)
    );
    const failed = await f.request('POST', `/api/client/${row.id}`, {
        ...ClientUpdateSchema.parse(row),
        privateKey,
      }),
      body = await failed.text();
    expect(failed.status).toBe(500);
    expect(
      body.includes(privateKey) || body.includes('driver private bind')
    ).toBe(false);
    expect((await f.clients.get(row.id))!.privateKey === row.privateKey).toBe(
      true
    );
  });
});
