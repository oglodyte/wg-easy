import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { eq } from 'drizzle-orm';
import { afterEach, expect, test } from 'vitest';

import { createNodeSqliteDatabase } from '#db/nodeSqlite';
import { readProposedRoutingState } from '#db/repositories/runtime/policySnapshot';
import * as schema from '#db/schema';

const roots: string[] = [],
  stores: ReturnType<typeof createNodeSqliteDatabase>[] = [];
afterEach(async () => {
  await Promise.all(stores.splice(0).map((s) => s.close()));
  await Promise.all(roots.splice(0).map((r) => fs.rm(r, { recursive: true })));
});

test('reads the complete final transaction state without credentials and preserves it on rollback', async () => {
  const root = await fs.mkdtemp(
    path.join(os.tmpdir(), 'wg-easy-policy-snapshot-')
  );
  roots.push(root);
  const store = createNodeSqliteDatabase(path.join(root, 'test.db'), schema);
  stores.push(store);
  await store.migrate({
    migrationsFolder: fileURLToPath(
      new URL('../../server/database/migrations', import.meta.url)
    ),
  });
  const db = store.db;
  await db
    .insert(schema.user)
    .values({
      id: 1,
      username: 'admin',
      password: 'private-user-fixture',
      email: 'admin@example.test',
      name: 'Admin',
      role: 1,
      totpVerified: false,
      enabled: true,
    })
    .execute();
  await db
    .insert(schema.client)
    .values(
      [1, 2, 3].map((id) => ({
        id,
        userId: 1,
        interfaceId: 'wg0',
        name: `profile ${id}`,
        ipv4Address: id === 3 ? '10.8.0.3' : `10.8.0.${id + 1}`,
        ipv6Address: null,
        privateKey: 'private-client-fixture',
        publicKey: id === 3 ? 'public-fixture-2' : `public-fixture-${id}`,
        preSharedKey: 'private-psk-fixture',
        serverAllowedIps: [],
        enabled: id !== 3,
        persistentKeepalive: 21,
        mtu: 1420,
      }))
    )
    .execute();
  await db
    .insert(schema.routingGroup)
    .values([
      {
        id: 1,
        routingSlot: 1,
        name: 'default',
        routedIpv4Prefixes: ['0.0.0.0/0'],
        excludedIpv4Prefixes: ['192.168.0.0/16'],
      },
      {
        id: 2,
        routingSlot: 2,
        name: 'LAN',
        routedIpv4Prefixes: ['192.168.1.0/24'],
      },
    ])
    .execute();
  await db
    .insert(schema.routingGroupMember)
    .values([
      { groupId: 1, clientId: 1 },
      { groupId: 2, clientId: 1 },
    ])
    .execute();
  await db
    .insert(schema.routingGroupExit)
    .values([
      { groupId: 1, clientId: 2, priority: 2, enabled: true },
      { groupId: 1, clientId: 3, priority: 0, enabled: true },
    ])
    .execute();
  const initial = await db.transaction((tx) => readProposedRoutingState(tx));
  expect(initial.snapshot.groups.map((g) => g.memberClientIds)).toEqual([
    [1],
    [1],
  ]);
  expect(initial.snapshot.groups[0]!.exits.map((e) => e.clientId)).toEqual([
    3, 2,
  ]);
  expect(initial.snapshot.clients.find((c) => c.id === 3)?.enabled).toBe(false);
  expect(JSON.stringify(initial)).not.toMatch(
    /private-|sessionPassword|preSharedKey|privateKey|preUp|postUp/
  );
  await expect(
    db.transaction(async (tx) => {
      await tx
        .delete(schema.routingGroup)
        .where(eq(schema.routingGroup.id, 2))
        .execute();
      await tx
        .update(schema.routingGroup)
        .set({ excludedIpv4Prefixes: [] })
        .where(eq(schema.routingGroup.id, 1))
        .execute();
      const final = await readProposedRoutingState(tx);
      expect(final.snapshot.groups).toHaveLength(1);
      expect(final.snapshot.groups[0]!.excludedIpv4Prefixes).toEqual([]);
      throw new Error('rollback requested');
    })
  ).rejects.toThrow('rollback requested');
  expect(await db.transaction((tx) => readProposedRoutingState(tx))).toEqual(
    initial
  );
});
