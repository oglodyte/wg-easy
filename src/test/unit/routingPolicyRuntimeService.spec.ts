import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { eq, sql } from 'drizzle-orm';
import { afterEach, describe, expect, test, vi } from 'vitest';

import { createNodeSqliteDatabase } from '#db/nodeSqlite';
import { RoutingPolicyRuntimeService } from '#db/repositories/runtime/policyService';
import * as schema from '#db/schema';
import { routingPolicyRuntimeFingerprint } from '#server/utils/routingPolicyRuntime';
import type {
  AppliedRoutingPolicyPlan,
  PendingPolicyTransition,
  RoutingPolicyJournal,
} from '#shared/types/routingPolicy';

const roots: string[] = [];
const stores: ReturnType<typeof createNodeSqliteDatabase>[] = [];
afterEach(async () => {
  await Promise.all(stores.splice(0).map((store) => store.close()));
  await Promise.all(
    roots.splice(0).map((root) => fs.rm(root, { recursive: true }))
  );
});
function record(revision = 1): RoutingPolicyJournal {
  const plan: AppliedRoutingPolicyPlan = {
    version: 2,
    interfaces: [
      { interfaceId: 'wg0', ipv4Cidr: '10.8.0.0/24', enabled: true },
    ],
    siteRoutes: [],
    bypassPrefixes: ['10.8.0.0/24'],
    programs: [],
    groups: [
      {
        id: 37,
        routingSlot: 37,
        enabled: false,
        natEnabled: true,
        allExitsDownPolicy: 'block',
        selectedExitClientId: null,
        exitInterfaceId: null,
        serverIpv4Address: null,
        effectivePrefixes: [],
      },
    ],
    peers: [
      {
        clientId: 73,
        interfaceId: 'wg0',
        peerId: 'a'.repeat(64),
        prefixes: ['10.8.0.2/32'],
      },
    ],
  };
  return { revision, fingerprint: routingPolicyRuntimeFingerprint(plan), plan };
}
function transition(revision = 2): PendingPolicyTransition {
  return {
    ...record(revision),
    stage: 'prepared',
    guardScopes: [],
    backupBasenames: ['policy-00000000-0000-0000-0000-000000000001.json'],
    errorCode: null,
  };
}
async function fixture({ version = 2, applied = true } = {}) {
  const root = await fs.mkdtemp(
    path.join(os.tmpdir(), 'wg-easy-policy-journal-')
  );
  roots.push(root);
  const databasePath = path.join(root, 'test.db');
  const store = createNodeSqliteDatabase(databasePath, schema);
  stores.push(store);
  await store.migrate({
    migrationsFolder: fileURLToPath(
      new URL('../../server/database/migrations', import.meta.url)
    ),
  });
  const db = store.db;
  await db
    .update(schema.general)
    .set({ routingPolicyVersion: version })
    .execute();
  await db
    .update(schema.runtimeReconciliationState)
    .set({ desiredRevision: 2, appliedRevision: 1, status: 'pending' })
    .execute();
  if (applied)
    await db
      .update(schema.routingPolicyRuntime)
      .set({ applied: record() })
      .execute();
  return {
    store,
    db,
    databasePath,
    service: new RoutingPolicyRuntimeService(db),
  };
}
async function verified(
  service: RoutingPolicyRuntimeService,
  pending: PendingPolicyTransition
) {
  let from = 'prepared' as PendingPolicyTransition['stage'];
  for (const to of ['guarded', 'peers', 'classified', 'verified'] as const) {
    await service.advance(pending, from, to);
    from = to;
  }
}
function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

describe('inactive durable policy transition service', () => {
  test('version 1 never fabricates applied evidence and unknown versions cannot mutate', async () => {
    const { db, service } = await fixture({ version: 1, applied: false });
    expect(await service.get()).toMatchObject({
      version: 1,
      applied: null,
      pending: null,
    });
    await expect(service.prepare(transition(), null)).rejects.toThrow(
      'version_unavailable'
    );
    await db.update(schema.general).set({ routingPolicyVersion: 3 }).execute();
    await expect(service.get()).rejects.toThrow('version_unavailable');
    expect(
      (await db.query.routingPolicyRuntime.findFirst())?.pending
    ).toBeNull();
  });

  test('preparation compares fresh revisions and applied identity without overwriting recovery', async () => {
    const { service } = await fixture();
    await expect(service.prepare(transition(3), record())).rejects.toThrow(
      'desired_changed'
    );
    await expect(service.prepare(transition(), null)).rejects.toThrow(
      'applied_changed'
    );
    await expect(
      service.prepare({ ...transition(), backupBasenames: [] }, record())
    ).rejects.toThrow('invalid_pending_transition');
    const pending = await service.prepare(transition(), record());
    await expect(service.prepare(transition(), record())).rejects.toThrow(
      'recovery_required'
    );
    await expect(
      service.advance(pending, 'prepared', 'verified')
    ).rejects.toThrow('invalid_stage_change');
    await expect(
      service.advance(
        {
          ...pending,
          backupBasenames: ['policy-00000000-0000-0000-0000-000000000002.json'],
        },
        'prepared',
        'guarded'
      )
    ).rejects.toThrow('transition_changed');
    await service.advance(pending, 'prepared', 'guarded');
    await expect(
      service.advance(pending, 'prepared', 'guarded')
    ).rejects.toThrow('stage_changed');
    const finalize = vi.fn(async () => {});
    await expect(service.finishApplied(pending, finalize)).rejects.toThrow(
      'stage_changed'
    );
    expect(finalize).not.toHaveBeenCalled();
    expect((await service.get()).applied).toEqual(record());
  });

  test('every persisted transition stage survives a database close/reopen with historical identities', async () => {
    const fixtureValue = await fixture();
    let { store, service } = fixtureValue;
    const pending = await service.prepare(transition(), record());
    for (const stage of [
      'prepared',
      'guarded',
      'peers',
      'classified',
      'verified',
      'restoring',
    ] as const) {
      if (stage === 'restoring')
        await service.markRestoring(pending, 'injected_failure');
      else if (stage !== 'prepared') {
        const current = (await service.get()).pending!;
        await service.advance(pending, current.stage, stage);
      }
      await store.close();
      store = createNodeSqliteDatabase(fixtureValue.databasePath, schema);
      stores.push(store);
      service = new RoutingPolicyRuntimeService(store.db);
      expect(await service.get()).toMatchObject({
        applied: record(),
        pending: {
          ...pending,
          stage,
          errorCode: stage === 'restoring' ? 'injected_failure' : null,
        },
        runtime: { appliedRevision: 1 },
      });
    }
  });

  test('failed final verification rolls back runtime evidence and retains pending without leaking its cause', async () => {
    const { db, service } = await fixture();
    const pending = await service.prepare(transition(), record());
    await verified(service, pending);
    await expect(
      service.finishApplied(pending, async (tx) => {
        await tx
          .update(schema.interfaceRuntimeState)
          .set({ appliedRevision: 999 })
          .where(eq(schema.interfaceRuntimeState.interfaceId, 'wg0'))
          .execute();
        throw new Error('sensitive backend input');
      })
    ).rejects.toThrow('final_verification_failed');
    expect(
      (await db.query.interfaceRuntimeState.findFirst())?.appliedRevision
    ).not.toBe(999);
    expect(await service.get()).toMatchObject({
      applied: record(),
      pending: { stage: 'verified' },
      runtime: { appliedRevision: 1 },
    });
    await service.finishApplied(pending, async (tx) => {
      await tx
        .update(schema.interfaceRuntimeState)
        .set({ appliedRevision: 2 })
        .where(eq(schema.interfaceRuntimeState.interfaceId, 'wg0'))
        .execute();
    });
    expect(await service.get()).toMatchObject({
      applied: record(2),
      pending: null,
      runtime: { appliedRevision: 2, status: 'idle', lastError: null },
    });
    expect(
      (await db.query.interfaceRuntimeState.findFirst())?.appliedRevision
    ).toBe(2);
  });

  test('stale desired state cannot remove the guard or claim Applied; verified rollback preserves the old revision', async () => {
    const { db, service } = await fixture();
    const pending = await service.prepare(transition(), record());
    await verified(service, pending);
    await db
      .update(schema.runtimeReconciliationState)
      .set({ desiredRevision: 3 })
      .execute();
    const removeGuard = vi.fn(async () => {});
    await expect(service.finishApplied(pending, removeGuard)).rejects.toThrow(
      'desired_changed'
    );
    expect(removeGuard).not.toHaveBeenCalled();
    await service.markRestoring(pending, 'desired_changed');
    await expect(
      service.finishRestored(pending, async () => {
        throw new Error('restore failed');
      })
    ).rejects.toThrow('final_verification_failed');
    expect((await service.get()).pending?.stage).toBe('restoring');
    await service.finishRestored(pending, async () => {});
    expect(await service.get()).toMatchObject({
      applied: record(),
      pending: null,
      runtime: {
        desiredRevision: 3,
        appliedRevision: 1,
        status: 'pending',
        lastError: 'routing_policy_restored',
      },
    });
  });

  test('holds the writer lock through final verification so a concurrent save remains pending', async () => {
    const { db, service } = await fixture();
    const pending = await service.prepare(transition(), record());
    await verified(service, pending);
    const entered = deferred(),
      release = deferred();
    let saveFinished = false;
    const finish = service.finishApplied(pending, async () => {
      entered.resolve();
      await release.promise;
      expect(saveFinished).toBe(false);
    });
    await entered.promise;
    const save = db
      .update(schema.runtimeReconciliationState)
      .set({
        desiredRevision: sql`${schema.runtimeReconciliationState.desiredRevision} + 1`,
        status: 'pending',
      })
      .execute()
      .then(() => {
        saveFinished = true;
      });
    release.resolve();
    await Promise.all([finish, save]);
    expect(await service.get()).toMatchObject({
      applied: record(2),
      pending: null,
      runtime: { desiredRevision: 3, appliedRevision: 2, status: 'pending' },
    });
  });

  test('strictly rejects corrupt stored JSON and false records without exposing persisted values', async () => {
    const { store, service } = await fixture();
    for (const value of ['false', '{"privateKey":"secret-test-value"}', '{']) {
      await store.raw.execute({
        sql: 'UPDATE routing_policy_runtime_table SET pending = ?',
        args: [value],
      });
      let caught: unknown;
      try {
        await service.get();
      } catch (error) {
        caught = error;
      }
      expect(String(caught)).toMatch(
        /invalid_pending_transition|state_unreadable/
      );
      expect(String(caught)).not.toContain('secret-test-value');
    }
  });
});
