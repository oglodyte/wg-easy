import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { eq } from 'drizzle-orm';
import { afterEach, describe, expect, test, vi } from 'vitest';

import { ClientService } from '#db/repositories/client/service';
import type {
  ClientType,
  UpdateClientType,
} from '#db/repositories/client/types';
import { GeneralService } from '#db/repositories/general/service';
import { InterfaceService } from '#db/repositories/interface/service';
import { RoutingGroupService } from '#db/repositories/routingGroup/service';
import type { RoutingGroupInput } from '#db/repositories/routingGroup/types';
import { createNodeSqliteDatabase } from '#db/nodeSqlite';
import * as schema from '#db/schema';
import type { DBType } from '#db/sqlite';
import { RoutingValidationError } from '#server/utils/routing';

const keyState = vi.hoisted(() => ({ value: 0 }));
vi.mock('#server/utils/wgHelper', () => ({
  wg: {
    generatePrivateKey: vi.fn(async () => `private-${++keyState.value}`),
    getPublicKey: vi.fn(async (privateKey: string) => `public-${privateKey}`),
    generatePreSharedKey: vi.fn(async () => `psk-${++keyState.value}`),
  },
}));

const migrationsDirectory = fileURLToPath(
  new URL('../../server/database/migrations', import.meta.url)
);
const temporaryRoots: string[] = [];
const databases: Array<ReturnType<typeof createNodeSqliteDatabase>> = [];

afterEach(async () => {
  keyState.value = 0;
  await Promise.all(databases.splice(0).map((database) => database.close()));
  await Promise.all(
    temporaryRoots
      .splice(0)
      .map((root) => fs.rm(root, { recursive: true, force: true }))
  );
});

async function createServices() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'wg-easy-phase5-'));
  temporaryRoots.push(root);
  const database = createNodeSqliteDatabase(path.join(root, 'test.db'), schema);
  databases.push(database);
  await database.migrate({ migrationsFolder: migrationsDirectory });
  const rawClient = database.raw;
  const db = database.db;
  await rawClient.execute({
    sql: `INSERT INTO users_table
      (id, username, password, email, name, role, totp_key, totp_verified, enabled)
      VALUES (1, 'admin', 'hash', 'admin@example.test', 'Admin', 1, NULL, 0, 1)`,
    args: [],
  });
  const typedDb = db as DBType;
  return {
    rawClient,
    db: typedDb,
    clients: new ClientService(typedDb),
    general: new GeneralService(typedDb),
    interfaces: new InterfaceService(typedDb),
    routingGroups: new RoutingGroupService(typedDb),
  };
}

async function addInterface(
  interfaces: InterfaceService,
  name: string,
  index: number
) {
  return interfaces.create({
    name,
    device: 'eth0',
    port: 51820 + index,
    ipv4Cidr: `10.${8 + index}.0.0/24`,
    ipv6Cidr: `fd42:${250 + index}::/64`,
  });
}

async function addClient(
  clients: ClientService,
  db: DBType,
  name: string,
  interfaceId: string,
  persistentKeepalive = 0
) {
  const result = await clients.create({ name, expiresAt: null, interfaceId });
  const id = result[0]!.clientId;
  if (persistentKeepalive !== 0) {
    await db
      .update(schema.client)
      .set({ persistentKeepalive })
      .where(eq(schema.client.id, id))
      .execute();
  }
  return id;
}

function draft(
  name: string,
  overrides: Partial<RoutingGroupInput> = {}
): RoutingGroupInput {
  return {
    name,
    enabled: false,
    exits: [],
    natEnabled: true,
    allExitsDownPolicy: 'block',
    routedIpv4Prefixes: ['0.0.0.0/0'],
    memberClientIds: [],
    ...overrides,
  };
}

function updateData(
  client: ClientType,
  overrides: Partial<UpdateClientType> = {}
): UpdateClientType {
  return {
    name: client.name,
    enabled: client.enabled,
    expiresAt: client.expiresAt,
    ipv4Address: client.ipv4Address,
    ipv6Address: client.ipv6Address,
    preUp: client.preUp,
    postUp: client.postUp,
    preDown: client.preDown,
    postDown: client.postDown,
    allowedIps: client.allowedIps,
    serverAllowedIps: client.serverAllowedIps,
    firewallIps: client.firewallIps,
    mtu: client.mtu,
    jC: client.jC,
    jMin: client.jMin,
    jMax: client.jMax,
    i1: client.i1,
    i2: client.i2,
    i3: client.i3,
    i4: client.i4,
    i5: client.i5,
    persistentKeepalive: client.persistentKeepalive,
    serverEndpoint: client.serverEndpoint,
    dns: client.dns,
    ...overrides,
  };
}

describe('Phase 5 routing-group repository and service', () => {
  test('persists routing health settings and advances the desired revision', async () => {
    const { db, general } = await createServices();
    const before = await db.query.runtimeReconciliationState
      .findFirst()
      .execute();
    expect(before).not.toBeNull();

    const revision = await general.updateRoutingHealthSettings({
      healthCheckIntervalSeconds: 30,
      healthTimeoutSeconds: 120,
      minHoldSeconds: 15,
      failbackDelaySeconds: 45,
    });

    await expect(general.getRoutingHealthSettings()).resolves.toEqual({
      routingExitHealthCheckIntervalSeconds: 30,
      routingExitHealthTimeoutSeconds: 120,
      routingExitMinHoldSeconds: 15,
      routingExitFailbackDelaySeconds: 45,
    });
    expect(revision).toBe(before!.desiredRevision + 1);
  });

  test('stores disabled drafts and atomically enables complete aggregates', async () => {
    const { rawClient, db, clients, interfaces, routingGroups } =
      await createServices();
    await addInterface(interfaces, 'awg1', 1);
    const memberId = await addClient(clients, db, 'member', 'wg0');
    const exitId = await addClient(clients, db, 'exit', 'awg1', 25);

    const created = await routingGroups.createAggregate(draft('draft'));
    expect(created.group).toMatchObject({
      routingSlot: 1,
      enabled: false,
      execution: { available: true, active: false },
    });
    expect(created.group.validationWarnings).toContainEqual(
      expect.stringContaining('requires at least one member')
    );

    const enabledInput = draft('ready', {
      enabled: true,
      exits: [{ clientId: exitId, priority: 10, enabled: true }],
      memberClientIds: [memberId],
    });
    const updated = await routingGroups.updateAggregate(
      created.group.id,
      enabledInput
    );
    expect(updated.group).toMatchObject({
      name: 'ready',
      enabled: true,
      runtime: {
        selectedExitClientId: null,
        appliedExitClientId: null,
        appliedRevision: null,
        status: 'selected_pending',
      },
      execution: { available: true, active: false },
    });
    expect(updated.group.validationWarnings).toEqual([]);

    await rawClient.execute({
      sql: `CREATE TRIGGER phase5_abort_member_insert
        BEFORE INSERT ON routing_group_members_table
        BEGIN SELECT RAISE(ABORT, 'injected aggregate failure'); END`,
      args: [],
    });
    await expect(
      routingGroups.updateAggregate(
        created.group.id,
        draft('must-roll-back-mid-transaction', {
          enabled: true,
          exits: [{ clientId: exitId, priority: 20, enabled: true }],
          memberClientIds: [memberId],
        })
      )
    ).rejects.toThrow('routing_group_members_table');
    await expect(routingGroups.get(created.group.id)).resolves.toMatchObject({
      name: 'ready',
      exits: [expect.objectContaining({ clientId: exitId, priority: 10 })],
      members: [expect.objectContaining({ clientId: memberId })],
    });
    await rawClient.execute({
      sql: 'DROP TRIGGER phase5_abort_member_insert',
      args: [],
    });

    await expect(
      routingGroups.updateAggregate(
        created.group.id,
        draft('must-roll-back', {
          enabled: true,
          exits: [{ clientId: 9999, priority: 10, enabled: true }],
          memberClientIds: [memberId],
        })
      )
    ).rejects.toBeInstanceOf(RoutingValidationError);
    await expect(routingGroups.get(created.group.id)).resolves.toMatchObject({
      name: 'ready',
      exits: [expect.objectContaining({ clientId: exitId })],
      members: [expect.objectContaining({ clientId: memberId })],
    });
  });

  test('requires keepalive and enforces one routing group per member', async () => {
    const { db, clients, interfaces, routingGroups } = await createServices();
    await addInterface(interfaces, 'awg1', 1);
    const memberId = await addClient(clients, db, 'member', 'wg0');
    const exitId = await addClient(clients, db, 'exit', 'awg1');

    await expect(
      routingGroups.createAggregate(
        draft('no-keepalive', {
          enabled: true,
          exits: [{ clientId: exitId, priority: 10, enabled: true }],
          memberClientIds: [memberId],
        })
      )
    ).rejects.toThrow('persistent keepalive');

    await routingGroups.createAggregate(
      draft('first-draft', { memberClientIds: [memberId] })
    );
    await expect(
      routingGroups.createAggregate(
        draft('second-draft', { memberClientIds: [memberId] })
      )
    ).rejects.toThrow('client “member” (#1) already belongs to routing group');
  });

  test('identifies named clients in routing conflict errors', async () => {
    const { db, clients, interfaces, routingGroups } = await createServices();
    await addInterface(interfaces, 'awg1', 1);
    const memberId = await addClient(clients, db, 'member', 'wg0');
    const exitId = await addClient(clients, db, 'exit', 'awg1', 25);
    const siteClientId = await addClient(clients, db, 'site-route', 'awg1');
    const siteClient = (await clients.get(siteClientId))!;
    await clients.update(
      siteClientId,
      updateData(siteClient, { serverAllowedIps: ['198.51.100.0/24'] })
    );

    await expect(
      routingGroups.createAggregate(
        draft('conflict', {
          enabled: true,
          exits: [{ clientId: exitId, priority: 10, enabled: true }],
          memberClientIds: [memberId],
          routedIpv4Prefixes: ['198.51.100.0/24'],
        })
      )
    ).rejects.toThrow(
      'new routing group “conflict” prefix 198.51.100.0/24 conflicts with server allowed IP 198.51.100.0/24 on client “site-route” (#3)'
    );
  });

  test('keeps deleted routing slots tombstoned until a verified revision releases them', async () => {
    const { db, routingGroups } = await createServices();
    const first = await routingGroups.createAggregate(draft('first'));
    const second = await routingGroups.createAggregate(draft('second'));
    expect([first.group.routingSlot, second.group.routingSlot]).toEqual([1, 2]);

    const deleted = await routingGroups.delete(first.group.id);
    const third = await routingGroups.createAggregate(draft('third'));
    expect(third.group.routingSlot).toBe(3);

    await routingGroups.releaseTombstones(deleted.revision - 1);
    expect(
      await db.query.routingSlotTombstone.findMany().execute()
    ).toHaveLength(1);
    await routingGroups.releaseTombstones(deleted.revision);
    expect(await db.query.routingSlotTombstone.findMany().execute()).toEqual(
      []
    );
    const reused = await routingGroups.createAggregate(draft('reused'));
    expect(reused.group.routingSlot).toBe(1);
  });

  test('rejects same-interface peer overlap and allows different exit interfaces', async () => {
    const { db, clients, interfaces, routingGroups } = await createServices();
    await addInterface(interfaces, 'awg1', 1);
    await addInterface(interfaces, 'awg2', 2);
    const memberOne = await addClient(clients, db, 'member-1', 'wg0');
    const memberTwo = await addClient(clients, db, 'member-2', 'wg0');
    const exitOne = await addClient(clients, db, 'exit-1', 'awg1', 25);
    const exitTwo = await addClient(clients, db, 'exit-2', 'awg1', 25);
    const exitThree = await addClient(clients, db, 'exit-3', 'awg2', 25);

    await routingGroups.createAggregate(
      draft('first', {
        enabled: true,
        exits: [{ clientId: exitOne, priority: 10, enabled: true }],
        routedIpv4Prefixes: ['10.0.0.0/8'],
        memberClientIds: [memberOne],
      })
    );
    await expect(
      routingGroups.createAggregate(
        draft('same-interface', {
          enabled: true,
          exits: [{ clientId: exitTwo, priority: 10, enabled: true }],
          routedIpv4Prefixes: ['10.1.0.0/16'],
          memberClientIds: [memberTwo],
        })
      )
    ).rejects.toThrow('overlapping prefixes');

    await expect(
      routingGroups.createAggregate(
        draft('different-interface', {
          enabled: true,
          exits: [{ clientId: exitThree, priority: 10, enabled: true }],
          routedIpv4Prefixes: ['10.1.0.0/16'],
          memberClientIds: [memberTwo],
        })
      )
    ).resolves.toMatchObject({
      group: { name: 'different-interface' },
    });
  });

  test('rejects default and overlapping serverAllowedIps globally', async () => {
    const { clients, db } = await createServices();
    const firstId = await addClient(clients, db, 'site-1', 'wg0');
    const secondId = await addClient(clients, db, 'site-2', 'wg0');
    const first = (await clients.get(firstId))!;
    const second = (await clients.get(secondId))!;

    await expect(
      clients.update(
        firstId,
        updateData(first, { serverAllowedIps: ['0.0.0.0/0'] })
      )
    ).rejects.toThrow('use a routing group');

    await clients.update(
      firstId,
      updateData(first, { serverAllowedIps: ['192.0.2.7/24'] })
    );
    await expect(
      clients.update(
        secondId,
        updateData(second, { serverAllowedIps: ['192.0.2.128/25'] })
      )
    ).rejects.toBeInstanceOf(RoutingValidationError);
    expect((await clients.get(firstId))?.serverAllowedIps).toEqual([
      '192.0.2.0/24',
    ]);
    expect((await clients.get(secondId))?.serverAllowedIps).toEqual([]);
  });

  test('blocks exit deletion and requires explicit member-removal confirmation', async () => {
    const { db, clients, interfaces, routingGroups } = await createServices();
    await addInterface(interfaces, 'awg1', 1);
    const memberId = await addClient(clients, db, 'member', 'wg0');
    const exitId = await addClient(clients, db, 'exit', 'awg1', 25);
    const created = await routingGroups.createAggregate(
      draft('references', {
        enabled: true,
        exits: [{ clientId: exitId, priority: 10, enabled: true }],
        memberClientIds: [memberId],
      })
    );

    const exit = (await clients.get(exitId))!;
    await expect(
      clients.update(exitId, updateData(exit, { persistentKeepalive: 0 }))
    ).rejects.toThrow('persistent keepalive');

    await expect(clients.delete(exitId)).rejects.toThrow(
      'blocked while it is an exit'
    );
    await expect(clients.delete(memberId)).rejects.toThrow(
      'confirm membership removal'
    );
    await clients.delete(memberId, { removeRoutingMembership: true });
    await expect(routingGroups.get(created.group.id)).resolves.toMatchObject({
      members: [],
      runtime: { status: 'draft_invalid' },
      validationWarnings: [
        expect.stringContaining('requires at least one member'),
      ],
    });
  });
});
