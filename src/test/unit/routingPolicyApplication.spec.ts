import fs from 'node:fs/promises';
import path from 'node:path';

import { eq } from 'drizzle-orm';
import { afterEach, describe, expect, test, vi } from 'vitest';

import { policyDatabase, syntheticKey } from '../helpers/policyDatabase';

import * as schema from '#db/schema';
import { ClientUpdateSchema } from '#db/repositories/client/types';
import { RoutingGenerationSnapshotService } from '#db/repositories/runtime/generationSnapshot';
import { RoutingPolicyRuntimeService } from '#db/repositories/runtime/policyService';
import {
  RuntimeStateService,
  bumpDesiredRevision,
} from '#db/repositories/runtime/service';
import {
  RoutingPolicyApplication,
  createRoutingPolicyApplicationPorts,
} from '#server/utils/routingPolicyApplication';
import { prepareDesiredRoutingConfigurations } from '#server/utils/routingPolicyGeneration';
import { publishRoutingNamespaceUnavailable } from '#server/utils/routingPolicyPublication';
import { parseManagedInterfaceConfig } from '#server/utils/managedInterfaceState';
import type { RoutingGuardPlan } from '#server/utils/routingGuard';

vi.mock('#server/utils/config', () => ({
  WG_ENV: { WG_EXECUTABLE: 'awg', PORT: 51821 },
}));
const cleanup: (() => Promise<void>)[] = [];
afterEach(async () => {
  for (const close of cleanup.splice(0)) await close();
});
const namespace = '01234567-89ab-cdef-0123-456789abcdef:4:100';

function observation(id: string, config: string) {
  const parsed = parseManagedInterfaceConfig(id, config),
    [address, prefix] = parsed.fields.get('address')!.split('/');
  return {
    showconf:
      '[Interface]\n' +
      [...parsed.fields]
        .filter(
          ([name]) =>
            ![
              'address',
              'mtu',
              'table',
              'preup',
              'postup',
              'predown',
              'postdown',
            ].includes(name)
        )
        .map(([name, value]) => `${name} = ${value}`)
        .join('\n') +
      '\n' +
      parsed.peers
        .map(
          (p) =>
            '[Peer]\n' +
            [...p].map(([name, value]) => `${name} = ${value}`).join('\n')
        )
        .join('\n'),
    addresses: JSON.stringify([
      {
        ifname: id,
        flags: ['UP'],
        mtu: Number(parsed.fields.get('mtu')),
        addr_info: [
          {
            family: 'inet',
            local: address,
            prefixlen: Number(prefix),
            scope: 'global',
          },
        ],
      },
    ]),
  };
}

async function application() {
  const fixture = await policyDatabase(1);
  cleanup.push(() => fixture.close());
  await fixture.addInterface('awg1', '10.9.0.0/24');
  await fixture.db
    .update(schema.hooks)
    .set({ preUp: '', postUp: '', preDown: '', postDown: '' })
    .execute();
  await fixture.clients.create({ name: 'member', interfaceId: 'wg0' });
  await fixture.clients.create({ name: 'exit', interfaceId: 'awg1' });
  const provider = {
      ...fixture,
      runtime: new RuntimeStateService(fixture.db),
      routingPolicy: new RoutingPolicyRuntimeService(fixture.db),
      routingGeneration: new RoutingGenerationSnapshotService(fixture.db),
    },
    ports = createRoutingPolicyApplicationPorts(fixture.root),
    devices = new Map<string, string>(),
    events: string[] = [];
  let guard: RoutingGuardPlan | null = null,
    failStart: string | null = null,
    failSync = false;
  ports.namespace = async () => namespace;
  ports.management = async () => [
    {
      direction: 'input',
      inputInterface: 'eth0',
      source: '192.0.2.0/24',
      destination: '192.0.2.2/32',
    },
  ];
  ports.dump = async () => [];
  ports.devices.observe = async (id) =>
    devices.has(id) ? observation(id, devices.get(id)!) : null;
  ports.devices.validate = async (id, text) => {
    parseManagedInterfaceConfig(id, text);
  };
  ports.devices.up = async (id, text) => {
    events.push(`up:${id}`);
    expect(guard).not.toBeNull();
    if (id === failStart) {
      failStart = null;
      throw new Error('injected start failure');
    }
    devices.set(id, text);
  };
  ports.devices.down = async (id) => {
    events.push(`down:${id}`);
    expect(guard).not.toBeNull();
    devices.delete(id);
  };
  ports.devices.sync = async (id, text) => {
    events.push(`sync:${id}`);
    expect(guard).not.toBeNull();
    devices.set(id, text);
    if (failSync) {
      failSync = false;
      throw new Error('injected post-sync interruption');
    }
  };
  ports.devices.verifyRecoverable = async () => {};
  ports.guard.verify = async (expected) => {
    expect(guard?.fingerprint ?? null).toBe(expected?.fingerprint ?? null);
  };
  ports.guard.prepare = async () => {};
  ports.guard.install = async (value) => {
    events.push('guard');
    guard = value;
  };
  ports.guard.ensure = async (value) => {
    guard = value;
  };
  ports.guard.remove = async () => {
    events.push('unguard');
    guard = null;
  };
  ports.firewall.prepare = async () => {};
  ports.firewall.apply = async () => {
    expect(guard).not.toBeNull();
    events.push('filter');
  };
  ports.firewall.verify = async () => {};
  ports.executor.prepare = async () => {};
  ports.executor.apply = async () => {
    expect(guard).not.toBeNull();
    events.push('policy');
  };
  ports.executor.verify = async () => {};
  const generation =
      await provider.routingGeneration.readPrivateDesiredGeneration(),
    prepared = prepareDesiredRoutingConfigurations(
      generation,
      new Map(),
      false
    );
  expect(prepared.failures.size).toBe(0);
  for (const [id, text] of prepared.configurations) {
    await fs.writeFile(path.join(fixture.root, `${id}.conf`), text!, {
      mode: 0o600,
    });
    devices.set(id, text!);
    await provider.runtime.markInterfaceApplied(id, true);
  }
  await provider.runtime.markGlobalApplied(
    generation.policy.runtime.desiredRevision
  );
  const app = new RoutingPolicyApplication(ports, false);
  return {
    ...fixture,
    provider,
    ports,
    app,
    events,
    devices,
    guard: () => guard,
    failStart: (id: string) => {
      failStart = id;
    },
    failSync: () => {
      failSync = true;
    },
  };
}

describe('existing-coordinator policy application with real SQLite/private backups', () => {
  test('promotes a verified v1 baseline, then performs a peer-only credential change', async () => {
    const f = await application();
    await f.app.promote(f.provider);
    expect(await f.provider.routingPolicy.get()).toMatchObject({
      version: 2,
      pending: null,
      runtime: { status: 'idle' },
    });
    f.events.length = 0;
    const client = (await f.clients.getAll()).find(
      (c) => c.interfaceId === 'wg0'
    )!;
    await f.clients.update(client.id, {
      ...ClientUpdateSchema.parse(client),
      privateKey: syntheticKey(),
      preSharedKey: null,
    });
    const result = await f.app.reconcile(f.provider, [
      { interfaceId: 'wg0', action: 'sync' },
    ]);
    expect(result.runtime.status).toBe('applied');
    expect(f.events.filter((e) => /^(up|down|sync):/.test(e))).toEqual([
      'sync:wg0',
    ]);
    expect(f.guard()).toBeNull();
  });

  test('a failed planned restart leaves a verified down baseline and the other device untouched', async () => {
    const f = await application();
    await f.app.promote(f.provider);
    f.events.length = 0;
    f.failStart('wg0');
    const result = await f.app.reconcile(f.provider, [
      { interfaceId: 'wg0', action: 'restart' },
    ]);
    expect(result.runtime.status).toBe('degraded');
    expect(f.events.filter((e) => /^(up|down|sync):/.test(e))).toEqual([
      'down:wg0',
      'up:wg0',
    ]);
    const state = await f.provider.routingPolicy.get();
    expect(state.pending).toBeNull();
    expect(
      state.applied!.plan.interfaces.find((i) => i.interfaceId === 'wg0')
    ).toMatchObject({ observedUp: false, hooksApplied: false });
    expect(f.devices.has('awg1')).toBe(true);
    expect(f.guard()).toBeNull();
    f.events.length = 0;
    expect((await f.app.reconcile(f.provider, [])).runtime.status).toBe(
      'applied'
    );
    expect(f.events.filter((e) => /^(up|down|sync):/.test(e))).toEqual([
      'up:wg0',
    ]);
  });

  test.each(['identity', 'preshared'])(
    'a post-sync %s interruption restores exact old credentials and never publishes the new revision',
    async (kind) => {
      const f = await application();
      await f.app.promote(f.provider);
      const before = await f.provider.routingPolicy.get(),
        oldFile = await fs.readFile(path.join(f.root, 'wg0.conf'), 'utf8'),
        client = (await f.clients.getAll()).find(
          (c) => c.interfaceId === 'wg0'
        )!;
      await f.clients.update(client.id, {
        ...ClientUpdateSchema.parse(client),
        ...(kind === 'identity' ? { privateKey: syntheticKey() } : {}),
        preSharedKey: syntheticKey(),
      });
      f.failSync();
      await expect(f.app.reconcile(f.provider, [])).rejects.toMatchObject({
        code: 'desired_generation_restored',
      });
      const after = await f.provider.routingPolicy.get();
      expect(after.pending).toBeNull();
      expect(after.applied).toEqual(before.applied);
      expect(after.runtime.appliedRevision).toBe(
        before.runtime.appliedRevision
      );
      expect(await fs.readFile(path.join(f.root, 'wg0.conf'), 'utf8')).toBe(
        oldFile
      );
      expect(f.devices.get('wg0')).toBe(oldFile);
      expect(f.guard()).toBeNull();
    }
  );

  test('a new desired revision during preflight aborts before guarded mutation', async () => {
    const f = await application();
    await f.app.promote(f.provider);
    f.events.length = 0;
    f.ports.executor.prepare = async () => {
      await f.db.transaction((tx) => bumpDesiredRevision(tx, []));
    };
    await expect(f.app.reconcile(f.provider, [])).rejects.toMatchObject({
      code: 'desired_changed',
    });
    expect(f.events).toEqual([]);
    expect((await f.provider.routingPolicy.get()).pending).toBeNull();
  });

  test('a lifecycle change arriving between withdrawal and fresh generation waits for a new Down baseline', async () => {
    const f = await application();
    await f.app.promote(f.provider);
    f.events.length = 0;
    const read = f.provider.routingGeneration.readPrivateDesiredGeneration.bind(
      f.provider.routingGeneration
    );
    let reads = 0;
    f.provider.routingGeneration.readPrivateDesiredGeneration = async () => {
      if (++reads === 3)
        await f.db.transaction(async (tx) => {
          await tx
            .update(schema.wgInterface)
            .set({ port: 62003 })
            .where(eq(schema.wgInterface.name, 'wg0'))
            .execute();
          await bumpDesiredRevision(tx, ['wg0']);
        });
      return read();
    };
    await expect(f.app.reconcile(f.provider, [])).rejects.toMatchObject({
      code: 'availability_withdrawal_required',
    });
    expect(f.events).toEqual([]);
    expect((await f.provider.routingPolicy.get()).pending).toBeNull();
    expect((await f.app.reconcile(f.provider, [])).runtime.status).toBe(
      'applied'
    );
    expect(f.events.filter((e) => /^(up|down):/.test(e))).toEqual([
      'down:wg0',
      'up:wg0',
    ]);
  });

  test('staged interface deletion removes only verified down state, without a second revision', async () => {
    const f = await application();
    await f.app.promote(f.provider);
    const client = (await f.clients.getAll()).find(
      (c) => c.interfaceId === 'awg1'
    )!;
    await f.clients.delete(client.id);
    await f.interfaces.stageDelete('awg1');
    const desired = (await f.provider.routingPolicy.get()).runtime
      .desiredRevision;
    expect((await f.app.reconcile(f.provider, [])).runtime.status).toBe(
      'applied'
    );
    expect(
      await f.db.query.wgInterface.findFirst({
        where: eq(schema.wgInterface.name, 'awg1'),
      })
    ).toBeUndefined();
    expect((await f.provider.routingPolicy.get()).runtime.desiredRevision).toBe(
      desired
    );
    expect(f.devices.has('wg0')).toBe(true);
    expect(f.devices.has('awg1')).toBe(false);
  });

  test('a cold namespace withdraws old availability before starting either device', async () => {
    const f = await application();
    await f.app.promote(f.provider);
    f.events.length = 0;
    f.devices.clear();
    f.ports.namespace = async () => namespace.replace(':100', ':101');
    f.ports.executor.observe = async () => ({
      policyRules: [],
      routes: [],
      chains: [],
      markUses: [],
    });
    f.ports.firewall.verifyAbsent = async () => {};
    const result = await new RoutingPolicyApplication(f.ports, false).reconcile(
      f.provider,
      []
    );
    expect(result.runtime.status).toBe('applied');
    const firstStart = f.events.indexOf('up:awg1'),
      firstPolicy = f.events.indexOf('policy');
    expect(firstPolicy).toBeLessThan(firstStart);
    expect(f.events.filter((e) => e.startsWith('down:'))).toEqual([]);
    expect(
      (await f.provider.routingPolicy.get()).applied!.plan.namespaceId
    ).toBe(namespace.replace(':100', ':101'));
  });

  test('a disabled group clears a healthy exit selection without stopping either interface', async () => {
    const f = await application();
    await f.app.promote(f.provider);
    const clients = await f.clients.getAll(),
      member = clients.find((c) => c.interfaceId === 'wg0')!,
      exit = clients.find((c) => c.interfaceId === 'awg1')!;
    await f.clients.update(exit.id, {
      ...ClientUpdateSchema.parse(exit),
      persistentKeepalive: 25,
    });
    const input = {
        name: 'LAN',
        enabled: true,
        natEnabled: true,
        allExitsDownPolicy: 'block' as const,
        routedIpv4Prefixes: ['192.168.44.0/24'],
        memberClientIds: [member.id],
        exits: [{ clientId: exit.id, priority: 0, enabled: true }],
      },
      { group } = await f.groups.createAggregate(input);
    f.ports.dump = async (id) =>
      id === 'awg1'
        ? [
            {
              publicKey: exit.publicKey,
              preSharedKey: exit.preSharedKey,
              endpoint: '192.0.2.30:62002',
              allowedIps: '',
              latestHandshakeAt: new Date(),
              transferRx: 1,
              transferTx: 1,
              persistentKeepalive: 25,
            },
          ]
        : [];
    await f.app.reconcile(f.provider, []);
    expect((await f.groups.get(group.id)).runtime).toMatchObject({
      status: 'active',
      appliedExitClientId: exit.id,
    });
    f.events.length = 0;
    await f.groups.updateAggregate(group.id, { ...input, enabled: false });
    expect((await f.app.reconcile(f.provider, [])).runtime.status).toBe(
      'applied'
    );
    expect((await f.groups.get(group.id)).runtime).toMatchObject({
      status: 'disabled',
      selectedExitClientId: null,
      appliedExitClientId: null,
    });
    expect(f.events.some((event) => /^(up|down):/.test(event))).toBe(false);
    expect([...f.devices.keys()].sort()).toEqual(['awg1', 'wg0']);
    expect(f.guard()).toBeNull();
    await f.groups.updateAggregate(group.id, input);
    expect((await f.app.reconcile(f.provider, [])).runtime.status).toBe(
      'applied'
    );
    expect((await f.groups.get(group.id)).runtime).toMatchObject({
      status: 'active',
      appliedExitClientId: exit.id,
    });
  });

  test('all-down group evidence becomes active only after a fresh healthy observation and whole publication', async () => {
    const f = await application();
    await f.app.promote(f.provider);
    const clients = await f.clients.getAll(),
      member = clients.find((c) => c.interfaceId === 'wg0')!,
      exit = clients.find((c) => c.interfaceId === 'awg1')!;
    await f.clients.update(exit.id, {
      ...ClientUpdateSchema.parse(exit),
      persistentKeepalive: 25,
    });
    const group = await f.groups.createAggregate({
      name: 'default',
      enabled: true,
      natEnabled: true,
      allExitsDownPolicy: 'block',
      routedIpv4Prefixes: ['0.0.0.0/0'],
      memberClientIds: [member.id],
      exits: [{ clientId: exit.id, priority: 0, enabled: true }],
    });
    await f.app.reconcile(f.provider, []);
    expect(await f.db.query.routingGroupRuntimeState.findFirst()).toMatchObject(
      { groupId: group.group.id, status: 'blocked', appliedExitClientId: null }
    );
    f.ports.dump = async (id) =>
      id === 'awg1'
        ? [
            {
              publicKey: exit.publicKey,
              preSharedKey: exit.preSharedKey,
              endpoint: '192.0.2.30:62002',
              allowedIps: '',
              latestHandshakeAt: new Date(),
              transferRx: 1,
              transferTx: 1,
              persistentKeepalive: 25,
            },
          ]
        : [];
    await f.app.reconcile(f.provider, []);
    expect(await f.db.query.routingGroupRuntimeState.findFirst()).toMatchObject(
      {
        status: 'active',
        selectedExitClientId: exit.id,
        appliedExitClientId: exit.id,
      }
    );
    expect(f.guard()).toBeNull();
    const applied = (await f.provider.routingPolicy.get()).runtime
      .appliedRevision;
    await f.db.transaction((tx) =>
      publishRoutingNamespaceUnavailable(tx, ['wg0', 'awg1'])
    );
    expect(await f.db.query.routingGroupRuntimeState.findFirst()).toMatchObject(
      {
        status: 'degraded',
        selectedExitClientId: null,
        appliedExitClientId: null,
      }
    );
    expect((await f.provider.routingPolicy.get()).runtime.appliedRevision).toBe(
      applied
    );
  });

  test('rollback restores private peer state after a desired exit deletion without violating runtime foreign keys', async () => {
    const f = await application();
    await f.app.promote(f.provider);
    const clients = await f.clients.getAll(),
      member = clients.find((c) => c.interfaceId === 'wg0')!,
      exit = clients.find((c) => c.interfaceId === 'awg1')!;
    await f.clients.update(exit.id, {
      ...ClientUpdateSchema.parse(exit),
      persistentKeepalive: 25,
    });
    const input = {
        name: 'default',
        enabled: true,
        natEnabled: true,
        allExitsDownPolicy: 'block' as const,
        routedIpv4Prefixes: ['0.0.0.0/0'],
        memberClientIds: [member.id],
        exits: [{ clientId: exit.id, priority: 0, enabled: true }],
      },
      group = await f.groups.createAggregate(input);
    f.ports.dump = async (id) =>
      id === 'awg1'
        ? [
            {
              publicKey: exit.publicKey,
              preSharedKey: exit.preSharedKey,
              endpoint: '192.0.2.30:62002',
              allowedIps: '',
              latestHandshakeAt: new Date(),
              transferRx: 1,
              transferTx: 1,
              persistentKeepalive: 25,
            },
          ]
        : [];
    await f.app.reconcile(f.provider, []);
    const previous = (await f.provider.routingPolicy.get()).applied;
    await f.groups.updateAggregate(group.group.id, {
      ...input,
      enabled: false,
      exits: [],
    });
    await f.clients.delete(exit.id);
    f.failSync();
    await expect(f.app.reconcile(f.provider, [])).rejects.toMatchObject({
      code: 'desired_generation_restored',
    });
    expect((await f.provider.routingPolicy.get()).pending).toBeNull();
    expect((await f.provider.routingPolicy.get()).applied).toEqual(previous);
    expect(await f.db.query.routingGroupRuntimeState.findFirst()).toMatchObject(
      {
        status: 'degraded',
        appliedExitClientId: null,
        reason: 'historical_exit_profile_unavailable',
      }
    );
    expect(f.guard()).toBeNull();
  });
});
