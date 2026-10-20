import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { eq } from 'drizzle-orm';
import { afterEach, expect, test } from 'vitest';

import { createNodeSqliteDatabase } from '#db/nodeSqlite';
import { RoutingGenerationSnapshotService } from '#db/repositories/runtime/generationSnapshot';
import * as schema from '#db/schema';
import type { DBType } from '#db/sqlite';

const roots: string[] = [],
  stores: ReturnType<typeof createNodeSqliteDatabase>[] = [];
afterEach(async () => {
  for (const store of stores.splice(0)) await store.close();
  for (const root of roots.splice(0))
    await fs.rm(root, { recursive: true, force: true });
});
async function fixture() {
  const root = await fs.mkdtemp(
    path.join(os.tmpdir(), 'wge-private-generation-')
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
    .update(schema.wgInterface)
    .set({
      privateKey: 'private-server-fixture',
      publicKey: 'public-server-fixture',
    })
    .where(eq(schema.wgInterface.name, 'wg0'))
    .execute();
  await db
    .update(schema.general)
    .set({
      sessionPassword: 'private-session-fixture',
      metricsPassword: 'private-metrics-fixture',
    })
    .execute();
  await db
    .insert(schema.user)
    .values({
      id: 1,
      username: 'admin',
      password: 'private-auth-fixture',
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
      [1, 2].map((id) => ({
        id,
        userId: 1,
        interfaceId: 'wg0',
        name: `profile ${id}`,
        privateKey: 'private-client-fixture',
        publicKey: 'public-client-fixture',
        preSharedKey: 'private-psk-fixture',
        ipv4Address: '10.8.0.2',
        ipv6Address: null,
        enabled: id === 1,
        serverAllowedIps: [],
        persistentKeepalive: 21,
        mtu: 1420,
        preUp: 'private-client-hook-fixture',
      }))
    )
    .execute();
  await db
    .insert(schema.routingGroup)
    .values({
      id: 1,
      routingSlot: 1,
      name: 'LAN',
      routedIpv4Prefixes: ['192.168.1.0/24'],
      excludedIpv4Prefixes: ['192.168.1.128/25'],
    })
    .execute();
  await db
    .insert(schema.routingGroupMember)
    .values({ groupId: 1, clientId: 1 })
    .execute();
  await db
    .insert(schema.routingGroupExit)
    .values({ groupId: 1, clientId: 2, priority: 0, enabled: true })
    .execute();
  return { store, db, service: new RoutingGenerationSnapshotService(db) };
}

test('captures one complete internal generation, preserving disabled alternatives without loading unrelated secrets', async () => {
  const f = await fixture(),
    state = await f.service.readPrivateDesiredGeneration();
  expect(state.policy.runtime.desiredRevision).toBe(1);
  expect(state.policy.version).toBe(1);
  expect(state.policy.applied).toBeNull();
  expect(state.policy.pending).toBeNull();
  expect(state.interfaces[0]?.privateKey === 'private-server-fixture').toBe(
    true
  );
  expect(state.clients[0]?.preSharedKey === 'private-psk-fixture').toBe(true);
  expect(state.clients.map((c) => c.enabled)).toEqual([true, false]);
  expect(state.snapshot.groups[0]?.memberClientIds).toEqual([1]);
  expect(state.snapshot.groups[0]?.excludedIpv4Prefixes).toEqual([
    '192.168.1.128/25',
  ]);
  expect(state.snapshot.groups[0]?.exits[0]?.clientId).toBe(2);
  for (const client of state.clients) {
    expect(Object.hasOwn(client, 'privateKey')).toBe(false);
    expect(Object.hasOwn(client, 'preUp')).toBe(false);
  }
  expect(Object.hasOwn(state.settings, 'sessionPassword')).toBe(false);
  expect(Object.hasOwn(state.settings, 'metricsPassword')).toBe(false);
  const all = JSON.stringify(state);
  for (const secret of [
    'private-session-fixture',
    'private-metrics-fixture',
    'private-auth-fixture',
    'private-client-fixture',
    'private-client-hook-fixture',
  ])
    expect(all.includes(secret)).toBe(false);
});

test('holds the single SQLite generation through concurrent desired-state changes', async () => {
  const f = await fixture();
  let entered!: () => void, release!: () => void;
  const ready = new Promise<void>((resolve) => {
      entered = resolve;
    }),
    resume = new Promise<void>((resolve) => {
      release = resolve;
    });
  const wrapped = new Proxy(f.db, {
    get(target, property, receiver) {
      if (property !== 'transaction')
        return Reflect.get(target, property, receiver);
      return (callback: Parameters<DBType['transaction']>[0]) =>
        target.transaction(async (tx) => {
          const snapshot = await callback(tx);
          entered();
          await resume;
          return snapshot;
        });
    },
  });
  const reading = new RoutingGenerationSnapshotService(
    wrapped
  ).readPrivateDesiredGeneration();
  await ready;
  let written = false;
  const writing = f.db
    .transaction(async (tx) => {
      await tx
        .update(schema.client)
        .set({
          ipv4Address: '10.8.0.3',
          preSharedKey: 'private-replacement-fixture',
        })
        .where(eq(schema.client.id, 1))
        .execute();
      await tx
        .update(schema.runtimeReconciliationState)
        .set({ desiredRevision: 2 })
        .execute();
      await tx
        .update(schema.interfaceRuntimeState)
        .set({ desiredRevision: 2 })
        .execute();
    })
    .then(() => {
      written = true;
    });
  await new Promise<void>((resolve) => setImmediate(resolve));
  expect(written).toBe(false);
  release();
  const old = await reading;
  await writing;
  expect(old.policy.runtime.desiredRevision).toBe(1);
  expect(old.clients[0]?.ipv4Address).toBe('10.8.0.2');
  expect(old.clients[0]?.preSharedKey === 'private-psk-fixture').toBe(true);
  const next = await f.service.readPrivateDesiredGeneration();
  expect(next.policy.runtime.desiredRevision).toBe(2);
  expect(next.clients[0]?.ipv4Address).toBe('10.8.0.3');
  expect(next.snapshot.clients[0]?.ipv4Address).toBe('10.8.0.3');
  expect(next.clients[0]?.preSharedKey === 'private-replacement-fixture').toBe(
    true
  );
});

test('does not expose SQL bind or JSON diagnostics from a failed private snapshot', async () => {
  const f = await fixture(),
    secret = 'private-database-bind-fixture',
    wrapped = new Proxy(f.db, {
      get(target, property, receiver) {
        if (property === 'transaction')
          return async () => {
            throw new Error(secret);
          };
        return Reflect.get(target, property, receiver);
      },
    }),
    service = new RoutingGenerationSnapshotService(wrapped);
  try {
    await service.readPrivateDesiredGeneration();
    throw new Error('unexpected successful read');
  } catch (error) {
    expect(error).toMatchObject({ code: 'snapshot_unavailable' });
    expect(String(error).includes(secret)).toBe(false);
    expect(Object.hasOwn(error as object, 'cause')).toBe(false);
  }
});
