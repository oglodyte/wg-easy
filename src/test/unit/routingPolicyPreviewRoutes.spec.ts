import { createApp, createRouter, toWebHandler } from 'h3';
import { afterEach, describe, expect, test, vi } from 'vitest';

import { policyDatabase } from '../helpers/policyDatabase';

import previewRoute from '#server/api/admin/routing-groups/preview.post';
import createRoute from '#server/api/admin/routing-groups/index.post';
import updateRoute from '#server/api/admin/routing-groups/[groupId]/index.post';
import statusRoute from '#server/api/admin/routing-groups/index.get';
import WireGuard from '#server/utils/WireGuard';
import type { RoutingGroupInput } from '#db/repositories/routingGroup/types';

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
  },
}));
const databases: Awaited<ReturnType<typeof policyDatabase>>[] = [];
afterEach(async () => {
  for (const f of databases.splice(0)) await f.close();
  state.user = { id: 1, role: 1 };
  vi.clearAllMocks();
});
async function fixture(version = 2) {
  const f = await policyDatabase(version);
  databases.push(f);
  state.database = { ...f, routingGroups: f.groups };
  await f.addInterface('awg1', '10.9.0.0/24');
  const member = await f.clients.create({
      name: 'member',
      interfaceId: 'wg0',
      expiresAt: null,
    }),
    exit = await f.clients.create({
      name: 'exit',
      interfaceId: 'awg1',
      expiresAt: null,
    });
  // Defaults keep legacy v1 fixture requests unchanged; valid exits are explicit.
  await f.db
    .update((await import('#db/schema')).client)
    .set({ persistentKeepalive: 25 })
    .execute();
  const group: RoutingGroupInput = {
      name: 'default',
      enabled: true,
      natEnabled: true,
      allExitsDownPolicy: 'block',
      routedIpv4Prefixes: ['0.0.0.0/0'],
      memberClientIds: [member[0]!.clientId],
      exits: [{ clientId: exit[0]!.clientId, priority: 0, enabled: true }],
    },
    created = await f.groups.createAggregate(group),
    router = createRouter()
      .post('/api/admin/routing-groups/preview', previewRoute)
      .post('/api/admin/routing-groups', createRoute)
      .post('/api/admin/routing-groups/:groupId', updateRoute)
      .get('/api/admin/routing-groups', statusRoute),
    handler = toWebHandler(createApp().use(router));
  return {
    ...f,
    group,
    groupId: created.group.id,
    memberId: member[0]!.clientId,
    exitId: exit[0]!.clientId,
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
describe('admin preview and fresh save contracts', () => {
  test('preview reads the compiler’s original rank, returns bounded safe diagnostics and makes no writes or runtime request', async () => {
    const f = await fixture(),
      before = await f.groups.getStatus(),
      proposed = {
        ...f.group,
        routedIpv4Prefixes: ['0.0.0.0/0', '192.0.0.0/8'],
        excludedIpv4Prefixes: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'],
      };
    const response = await f.request(
        'POST',
        '/api/admin/routing-groups/preview',
        {
          groupId: f.groupId,
          group: proposed,
          memberClientId: f.memberId,
          destinationIpv4: '192.169.1.1',
        }
      ),
      body = await response.json();
    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(body.explanation.winner).toMatchObject({
      groupId: f.groupId,
      originalPrefix: '192.0.0.0/8',
      specificity: 8,
    });
    expect(body.canonicalInput.excludedIpv4Prefixes).toEqual(
      proposed.excludedIpv4Prefixes
    );
    expect(body.winnerExamples.length).toBeLessThanOrEqual(32);
    expect(body.counts.winnerWork).toBeGreaterThan(0);
    expect(await f.groups.getStatus()).toEqual(before);
    expect(WireGuard.requestReconcile).not.toHaveBeenCalled();
    const identities = [
      ...(await f.clients.getAll()),
      ...(await f.db.query.wgInterface.findMany()),
    ];
    expect(
      identities.every((row) => !JSON.stringify(body).includes(row.privateKey))
    ).toBe(true);
    expect(
      identities.every(
        (row) =>
          !('preSharedKey' in row) ||
          row.preSharedKey === null ||
          !JSON.stringify(body).includes(row.preSharedKey)
      )
    ).toBe(true);
  });
  test('a concurrent save invalidates the preview revision before any aggregate rows change', async () => {
    const f = await fixture(),
      preview = await (
        await f.request('POST', '/api/admin/routing-groups/preview', {
          groupId: f.groupId,
          group: f.group,
        })
      ).json();
    await f.clients.toggle(f.memberId, false);
    const before = await f.groups.getStatus(),
      response = await f.request(
        'POST',
        `/api/admin/routing-groups/${f.groupId}`,
        {
          ...f.group,
          name: 'stale save',
          expectedDesiredRevision: preview.desiredRevision,
          expectedDesiredFingerprint: preview.desiredFingerprint,
        }
      );
    expect(response.status).toBe(409);
    expect((await response.json()).data.code).toBe('desired_changed');
    expect(await f.groups.getStatus()).toEqual(before);
    expect(WireGuard.requestReconcile).not.toHaveBeenCalled();
    const fresh = await f.request(
      'POST',
      `/api/admin/routing-groups/${f.groupId}`,
      {
        ...f.group,
        name: 'fresh save',
        expectedDesiredRevision: before.desiredRevision,
        expectedDesiredFingerprint: before.desiredFingerprint,
      }
    );
    expect(fresh.status).toBe(200);
    expect((await fresh.json()).runtime.status).toBe('pending');
  });
  test('fresh fingerprint is checked even without a revision and complete advanced editor capability is available', async () => {
    const f = await fixture(),
      old = await f.groups.getStatus();
    await f.groups.updateAggregate(f.groupId, {
      ...f.group,
      excludedIpv4Prefixes: ['192.168.0.0/16'],
    });
    const before = await f.groups.getStatus(),
      response = await f.request(
        'POST',
        `/api/admin/routing-groups/${f.groupId}`,
        { ...f.group, expectedDesiredFingerprint: old.desiredFingerprint }
      );
    expect(response.status).toBe(409);
    expect(await f.groups.getStatus()).toEqual(before);
    const status = await (
      await f.request('GET', '/api/admin/routing-groups')
    ).json();
    expect(status.capabilities).toMatchObject({
      subnetPolicies: true,
      fullClientConfiguration: true,
      advancedGroupEditing: true,
    });
    expect(status.groups[0].baselineEditable).toBe(false);
    expect(status.groups[0].excludedIpv4Prefixes).toEqual(['192.168.0.0/16']);
    expect(status.guardStatus).toBe('no_pending_transition');
  });
  test('ordinary users cannot preview or save admin policy; version 1 reports activation unavailable', async () => {
    const f = await fixture(1),
      before = await f.groups.getStatus();
    expect(before.capabilities.advancedGroupEditing).toBe(false);
    state.user = { id: 1, role: 2 };
    expect(
      (
        await f.request('POST', '/api/admin/routing-groups/preview', {
          group: f.group,
        })
      ).status
    ).toBe(403);
    expect(
      (await f.request('POST', '/api/admin/routing-groups', f.group)).status
    ).toBe(403);
    expect(await f.groups.getStatus()).toEqual(before);
    state.user = { id: 1, role: 1 };
    const response = await f.request(
      'POST',
      '/api/admin/routing-groups/preview',
      { group: f.group }
    );
    expect(response.status).toBe(409);
    expect((await response.json()).data.code).toBe('policy_version_required');
    expect((await f.groups.getStatus()).capabilities.subnetPolicies).toBe(
      false
    );
  });
});
