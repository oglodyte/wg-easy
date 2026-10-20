import { eq } from 'drizzle-orm';
import { afterEach, describe, expect, test, vi } from 'vitest';

import { policyDatabase } from '../helpers/policyDatabase';

import { ClientUpdateSchema } from '#db/repositories/client/types';
import type { RoutingGroupInput } from '#db/repositories/routingGroup/types';
import { readProposedRoutingState } from '#db/repositories/runtime/policySnapshot';
import * as schema from '#db/schema';
import { specializeRoutingPolicy } from '#server/utils/routingPolicyRuntime';

vi.mock('#server/utils/config', () => ({
  WG_ENV: { WG_EXECUTABLE: 'awg', PORT: 51821 },
}));
const databases: Awaited<ReturnType<typeof policyDatabase>>[] = [];
afterEach(async () => {
  for (const db of databases.splice(0)) await db.close();
});
async function fixture() {
  const f = await policyDatabase();
  databases.push(f);
  await f.addInterface('awg1', '10.9.0.0/24');
  const member = await f.createClient('member'),
    other = await f.createClient('other'),
    internet = await f.createClient('internet', 'awg1'),
    lan = await f.createClient('LAN router', 'awg1', {
      serverAllowedIps: ['192.168.50.0/24'],
    });
  const lanInput: RoutingGroupInput = {
      name: 'LAN',
      enabled: true,
      natEnabled: false,
      allExitsDownPolicy: 'block',
      routedIpv4Prefixes: ['192.168.50.0/24'],
      memberClientIds: [member.id, other.id],
      exits: [{ clientId: lan.id, priority: 0, enabled: true }],
    },
    lanGroup = (await f.groups.createAggregate(lanInput)).group,
    defaultInput: RoutingGroupInput = {
      name: 'internet',
      enabled: true,
      natEnabled: true,
      allExitsDownPolicy: 'block',
      routedIpv4Prefixes: ['0.0.0.0/0'],
      memberClientIds: [member.id],
      exits: [{ clientId: internet.id, priority: 0, enabled: true }],
    },
    defaultGroup = (await f.groups.createAggregate(defaultInput)).group;
  return {
    ...f,
    member,
    other,
    internet,
    lan,
    lanInput,
    lanGroup,
    defaultInput,
    defaultGroup,
  };
}
async function publicState(f: Awaited<ReturnType<typeof policyDatabase>>) {
  return f.db.transaction(async (tx) => ({
    proposed: await readProposedRoutingState(tx),
    runtime: await tx.query.runtimeReconciliationState.findFirst(),
    interfaces: await tx.query.interfaceRuntimeState.findMany(),
    tombstones: await tx.query.routingSlotTombstone.findMany(),
    groupRuntime: await tx.query.routingGroupRuntimeState.findMany(),
  }));
}
describe('shared final-state proof in service transactions', () => {
  test.each(['delete', 'disable', 'member removal'])(
    'rejects LAN %s that exposes a conflicting legacy owner, then permits it after a safe exclusion',
    async (mutation) => {
      const f = await fixture(),
        before = await publicState(f);
      const apply = () =>
        mutation === 'delete'
          ? f.groups.delete(f.lanGroup.id)
          : f.groups.updateAggregate(
              f.lanGroup.id,
              mutation === 'disable'
                ? { ...f.lanInput, enabled: false }
                : { ...f.lanInput, memberClientIds: [f.other.id] }
            );
      await expect(apply()).rejects.toMatchObject({ code: 'peer_conflict' });
      expect(await publicState(f)).toEqual(before);
      await f.groups.updateAggregate(f.defaultGroup.id, {
        ...f.defaultInput,
        excludedIpv4Prefixes: ['192.168.50.0/24'],
      });
      await apply();
      expect((await publicState(f)).runtime!.desiredRevision).toBe(
        before.runtime!.desiredRevision + 2
      );
    }
  );
  test('rejects a backup-only ownership conflict, and omission preserves exclusions while explicit empty is re-proved', async () => {
    const f = await fixture(),
      before = await publicState(f);
    await expect(
      f.groups.updateAggregate(f.lanGroup.id, {
        ...f.lanInput,
        exits: [
          { clientId: f.lan.id, priority: 0, enabled: true },
          { clientId: f.internet.id, priority: 1, enabled: true },
        ],
      })
    ).rejects.toMatchObject({ code: 'peer_conflict' });
    expect(await publicState(f)).toEqual(before);
    await f.groups.updateAggregate(f.defaultGroup.id, {
      ...f.defaultInput,
      excludedIpv4Prefixes: ['192.168.50.0/24'],
    });
    await f.groups.delete(f.lanGroup.id);
    await f.groups.updateAggregate(f.defaultGroup.id, {
      ...f.defaultInput,
      name: 'renamed',
    });
    expect(
      (await f.groups.get(f.defaultGroup.id)).excludedIpv4Prefixes
    ).toEqual(['192.168.50.0/24']);
    const safe = await publicState(f);
    await expect(
      f.groups.updateAggregate(f.defaultGroup.id, {
        ...f.defaultInput,
        excludedIpv4Prefixes: [],
      })
    ).rejects.toMatchObject({ code: 'peer_conflict' });
    expect(await publicState(f)).toEqual(safe);
  });
  test('all-down preferences and current interface health never weaken a saved candidate proof', async () => {
    const f = await fixture();
    await f.db
      .update(schema.interfaceRuntimeState)
      .set({ observedUp: false, status: 'degraded' })
      .execute();
    const before = await publicState(f);
    await expect(
      f.groups.updateAggregate(f.lanGroup.id, {
        ...f.lanInput,
        enabled: false,
        allExitsDownPolicy: 'host',
      })
    ).rejects.toMatchObject({ code: 'peer_conflict' });
    expect(await publicState(f)).toEqual(before);
  });
  test('client legacy/identity edits and global health settings validate the final generation and preserve revisions on failure', async () => {
    const f = await fixture(),
      before = await publicState(f);
    await expect(
      f.clients.update(f.internet.id, {
        ...ClientUpdateSchema.parse(f.internet),
        serverAllowedIps: ['192.168.50.0/25'],
      })
    ).rejects.toThrow();
    await expect(
      f.clients.update(f.lan.id, {
        ...ClientUpdateSchema.parse(f.lan),
        persistentKeepalive: 0,
      })
    ).rejects.toThrow('persistent keepalive');
    const settings = await f.general.getRoutingHealthSettings();
    await expect(
      f.general.updateRoutingHealthSettings({
        ...settings,
        healthTimeoutSeconds: 30,
      })
    ).rejects.toThrow('persistent keepalive');
    await expect(
      f.interfaces.updateKeyPair('wg0', f.member.privateKey, f.member.publicKey)
    ).rejects.toMatchObject({ code: 'credential_conflict' });
    expect(await publicState(f)).toEqual(before);
    expect((await f.clients.get(f.internet.id))!.serverAllowedIps).toEqual([]);
  });
  test.each(['stage deletion', 'CIDR change'])(
    '%s proves loss of a disabled empty interface bypass before committing',
    async (mutation) => {
      const f = await fixture();
      await f.groups.updateAggregate(f.defaultGroup.id, {
        ...f.defaultInput,
        excludedIpv4Prefixes: ['192.168.50.0/24'],
      });
      await f.groups.delete(f.lanGroup.id);
      await f.addInterface('bypass0', '192.168.50.0/24', 62003);
      await f.db
        .update(schema.wgInterface)
        .set({ enabled: false })
        .where(eq(schema.wgInterface.name, 'bypass0'))
        .execute();
      await f.groups.updateAggregate(f.defaultGroup.id, {
        ...f.defaultInput,
        excludedIpv4Prefixes: [],
      });
      const before = await publicState(f),
        iface = await f.interfaces.getByName('bypass0');
      await expect(
        mutation === 'stage deletion'
          ? f.interfaces.stageDelete('bypass0')
          : f.interfaces.updateCidr('bypass0', {
              ipv4Cidr: '10.25.0.0/24',
              ipv6Cidr: null,
            })
      ).rejects.toMatchObject({ code: 'peer_conflict' });
      expect(await publicState(f)).toEqual(before);
      expect((await f.interfaces.getByName('bypass0')).ipv4Cidr).toBe(
        iface.ipv4Cidr
      );
      expect((await f.interfaces.getByName('bypass0')).pendingDelete).toBe(
        false
      );
    }
  );
  test('physical interface deletion requires staged verified cleanup and does not invent another desired revision', async () => {
    const f = await fixture();
    await f.addInterface('empty0', '10.26.0.0/24', 62003);
    await expect(f.interfaces.finalizeDelete('empty0')).rejects.toThrow(
      'verified staged runtime cleanup'
    );
    await f.interfaces.stageDelete('empty0');
    const state = await publicState(f),
      desiredRevision = state.runtime!.desiredRevision,
      proposed = state.proposed.snapshot,
      planned = specializeRoutingPolicy(proposed, {
        selectedExitClientIds: new Map(),
        enabledInterfaceIds: new Set(['wg0', 'awg1']),
        upInterfaceIds: new Set(),
        enableIpv6: false,
        clientFirewall: { enableIpv6: false, interfaces: [], entries: [] },
      });
    expect(proposed.interfaces.some((i) => i.interfaceId === 'empty0')).toBe(
      false
    );
    await f.db
      .update(schema.routingPolicyRuntime)
      .set({
        applied: {
          revision: desiredRevision,
          plan: planned.plan,
          fingerprint: planned.fingerprint,
        },
      })
      .execute();
    const runtime = (await f.db.query.interfaceRuntimeState.findFirst({
      where: eq(schema.interfaceRuntimeState.interfaceId, 'empty0'),
    }))!;
    await f.db
      .update(schema.interfaceRuntimeState)
      .set({
        status: 'disabled',
        observedUp: false,
        restartRequired: false,
        appliedRevision: runtime.desiredRevision,
      })
      .where(eq(schema.interfaceRuntimeState.interfaceId, 'empty0'))
      .execute();
    await f.interfaces.finalizeDelete('empty0');
    expect((await publicState(f)).runtime!.desiredRevision).toBe(
      desiredRevision
    );
    expect(
      (await f.db.query.wgInterface.findMany()).some((i) => i.name === 'empty0')
    ).toBe(false);
  });
});
