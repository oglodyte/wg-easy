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
import { deriveRoutingAvailabilityWithdrawal } from '#server/utils/routingPolicyAvailability';
import type {
  AppliedRoutingPolicyPlan,
  PendingPolicyTransition,
  RoutingPolicyJournal,
  PolicyBootstrapBaseline,
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
    clientFirewall: { enableIpv6: false, interfaces: [], entries: [] },
    interfaces: [
      {
        interfaceId: 'wg0',
        ipv4Cidr: '10.8.0.0/24',
        enabled: true,
        observedUp: true,
      },
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

function bootstrap(): PendingPolicyTransition {
  const target = record(2);
  const baseline: PolicyBootstrapBaseline = {
    interfaces: target.plan.interfaces,
    clients: [
      {
        id: 73,
        interfaceId: 'wg0',
        ipv4Address: '10.8.0.2',
        ipv6Address: null,
        enabled: true,
        serverAllowedIps: [],
      },
    ],
    groups: target.plan.groups.map((g) => ({
      id: g.id,
      routingSlot: g.routingSlot,
      enabled: g.enabled,
      natEnabled: g.natEnabled,
      allExitsDownPolicy: g.allExitsDownPolicy,
      routedIpv4Prefixes: [],
      memberClientIds: [],
      selectedExitClientId: null,
    })),
    peers: target.plan.peers,
  };
  return { ...transition(), ...target, bootstrap: baseline };
}

async function bootstrapFixture() {
  const f = await fixture({ version: 1, applied: false });
  await f.db
    .update(schema.runtimeReconciliationState)
    .set({ appliedRevision: 2, status: 'idle' })
    .execute();
  await f.db
    .update(schema.interfaceRuntimeState)
    .set({ desiredRevision: 2, appliedRevision: 2 })
    .execute();
  return f;
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
  await db
    .update(schema.interfaceRuntimeState)
    .set({
      desiredRevision: 1,
      appliedRevision: 1,
      observedUp: true,
      status: 'up',
    })
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
  test('cold-namespace rebase CAS replaces the single pending backup without advancing any revision', async () => {
    const { db, service } = await fixture();
    const previous = record();
    previous.plan.namespaceId =
      '11111111-1111-4111-8111-111111111111:4:4026531001';
    previous.plan.interfaces[0]!.hooksApplied = true;
    previous.fingerprint = routingPolicyRuntimeFingerprint(previous.plan);
    await db
      .update(schema.routingPolicyRuntime)
      .set({ applied: previous })
      .execute();
    const pending = await service.prepare(transition(), previous);
    const target = deriveRoutingAvailabilityWithdrawal(
      previous,
      new Set(['wg0']),
      {
        namespaceId: '11111111-1111-4111-8111-111111111111:4:4026531002',
        resetHooks: true,
      }
    );
    const next: PendingPolicyTransition = {
      ...pending,
      ...target,
      withdrawal: { unavailableInterfaceIds: ['wg0'], resetNamespace: true },
      supersededGuardScopes: pending.guardScopes,
      backupBasenames: ['policy-00000000-0000-0000-0000-000000000002.json'],
    };
    await expect(
      service.rebasePendingToWithdrawal(pending, {
        ...next,
        backupBasenames: pending.backupBasenames,
      })
    ).rejects.toThrow('invalid_namespace_rebase');
    await expect(
      service.rebasePendingToWithdrawal(pending, {
        ...next,
        supersededGuardScopes: undefined,
      })
    ).rejects.toThrow('invalid_namespace_rebase');
    await service.rebasePendingToWithdrawal(pending, next);
    expect(await service.get()).toMatchObject({
      applied: previous,
      pending: next,
      runtime: { desiredRevision: 2, appliedRevision: 1, status: 'degraded' },
    });
    await expect(
      service.rebasePendingToWithdrawal(pending, next)
    ).rejects.toThrow('transition_changed');
  });

  test('a safety withdrawal completes at the old revision despite newer desired state and cannot roll back up', async () => {
    const { db, service } = await fixture();
    const previous = record();
    previous.plan.namespaceId =
      '11111111-1111-4111-8111-111111111111:4:4026531001';
    previous.plan.interfaces[0]!.hooksApplied = true;
    previous.fingerprint = routingPolicyRuntimeFingerprint(previous.plan);
    await db
      .update(schema.routingPolicyRuntime)
      .set({ applied: previous })
      .execute();
    const target = deriveRoutingAvailabilityWithdrawal(
      previous,
      new Set(['wg0']),
      {
        namespaceId: previous.plan.namespaceId,
      }
    );
    const pending = await service.prepare(
      {
        ...transition(),
        ...target,
        withdrawal: { unavailableInterfaceIds: ['wg0'], resetNamespace: false },
      },
      previous
    );
    await service.markRestoring(pending, 'interrupted_transition');
    await expect(
      service.finishRestored(pending, async () => {})
    ).rejects.toThrow('withdrawal_requires_completion');
    await service.resumeWithdrawal(pending);
    for (const [from, to] of [
      ['guarded', 'peers'],
      ['peers', 'classified'],
      ['classified', 'verified'],
    ] as const)
      await service.advance(pending, from, to);
    await service.finishApplied(pending, async () => {});
    expect(await service.get()).toMatchObject({
      applied: target,
      pending: null,
      runtime: { desiredRevision: 2, appliedRevision: 1, status: 'degraded' },
    });
  });

  test('withdrawal evidence cannot change policy semantics, raise the revision or take ownership across the wrong namespace', async () => {
    const { db, service } = await fixture();
    const previous = record();
    previous.plan.namespaceId =
      '11111111-1111-4111-8111-111111111111:4:4026531001';
    previous.plan.interfaces[0]!.hooksApplied = true;
    previous.fingerprint = routingPolicyRuntimeFingerprint(previous.plan);
    await db
      .update(schema.routingPolicyRuntime)
      .set({ applied: previous })
      .execute();
    const target = deriveRoutingAvailabilityWithdrawal(
      previous,
      new Set(['wg0']),
      {
        namespaceId: previous.plan.namespaceId,
      }
    );
    const pending = {
      ...transition(),
      ...target,
      withdrawal: { unavailableInterfaceIds: ['wg0'], resetNamespace: false },
    };
    const changed = structuredClone(pending);
    changed.plan.groups[0]!.natEnabled = false;
    changed.fingerprint = routingPolicyRuntimeFingerprint(changed.plan);
    for (const invalid of [
      changed,
      { ...pending, revision: 2 },
      {
        ...pending,
        withdrawal: { ...pending.withdrawal, resetNamespace: true },
      },
    ]) {
      await expect(service.prepare(invalid, previous)).rejects.toThrow(
        /invalid_|namespace_reset_mismatch/
      );
      expect((await service.get()).pending).toBeNull();
    }
    // Persisted corruption is also refused on read, before any recovery callback.
    await db
      .update(schema.routingPolicyRuntime)
      .set({ pending: changed })
      .execute();
    await expect(service.get()).rejects.toThrow(
      'invalid_availability_withdrawal'
    );
  });

  test('first activation commits version 2 only after whole-state verification under the writer lock', async () => {
    const { service, db } = await bootstrapFixture();
    const pending = await service.prepare(bootstrap(), null);
    expect(await service.get()).toMatchObject({
      version: 1,
      applied: null,
      pending: { bootstrap: pending.bootstrap },
    });
    await verified(service, pending);
    await service.finishApplied(pending, async (tx) => {
      expect((await tx.query.general.findFirst())?.routingPolicyVersion).toBe(
        1
      );
      expect(
        (await tx.query.routingPolicyRuntime.findFirst())?.applied
      ).toBeNull();
    });
    expect(await service.get()).toMatchObject({
      version: 2,
      applied: record(2),
      pending: null,
      runtime: { appliedRevision: 2, status: 'idle' },
    });
    expect((await db.query.general.findFirst())?.routingPolicyVersion).toBe(2);
    await expect(service.prepare(bootstrap(), null)).rejects.toThrow(
      'version_unavailable'
    );
  });

  test.each(['global', 'interface'] as const)(
    'refuses first activation before the old %s configuration converges',
    async (scope) => {
      const { service, db } = await bootstrapFixture();
      if (scope === 'global')
        await db
          .update(schema.runtimeReconciliationState)
          .set({ appliedRevision: 1 })
          .execute();
      else
        await db
          .update(schema.interfaceRuntimeState)
          .set({ restartRequired: true })
          .execute();
      await expect(service.prepare(bootstrap(), null)).rejects.toThrow(
        'bootstrap_not_converged'
      );
      expect(await service.get()).toMatchObject({
        version: 1,
        applied: null,
        pending: null,
      });
    }
  );

  test('failed activation verification rolls back version/evidence and verified restoration preserves version 1', async () => {
    const { service } = await bootstrapFixture();
    const pending = await service.prepare(bootstrap(), null);
    await verified(service, pending);
    await expect(
      service.finishApplied(pending, async () => {
        throw new Error('private fixture bytes');
      })
    ).rejects.toThrow('final_verification_failed');
    expect(await service.get()).toMatchObject({
      version: 1,
      applied: null,
      pending: { stage: 'verified' },
    });
    await service.markRestoring(pending, 'interrupted_transition');
    await service.finishRestored(pending, async () => {});
    expect(await service.get()).toMatchObject({
      version: 1,
      applied: null,
      pending: null,
      runtime: { appliedRevision: 2 },
    });
  });

  test.each([
    'prepared',
    'guarded',
    'peers',
    'classified',
    'verified',
    'restoring',
  ] as const)(
    'bootstrap %s survives storage reopen without fabricated Applied evidence',
    async (stage) => {
      const { service, store, databasePath } = await bootstrapFixture();
      const pending = await service.prepare(bootstrap(), null);
      let from: PendingPolicyTransition['stage'] = 'prepared';
      for (const to of [
        'guarded',
        'peers',
        'classified',
        'verified',
      ] as const) {
        if (from === stage || stage === 'restoring') break;
        await service.advance(pending, from, to);
        from = to;
      }
      if (stage === 'restoring')
        await service.markRestoring(pending, 'interrupted_transition');
      await store.close();
      const reopened = createNodeSqliteDatabase(databasePath, schema);
      stores.push(reopened);
      const fresh = new RoutingPolicyRuntimeService(reopened.db);
      expect(await fresh.get()).toMatchObject({
        version: 1,
        applied: null,
        pending: { stage, bootstrap: pending.bootstrap },
      });
      await fresh.markRestoring(pending, 'interrupted_transition');
      await fresh.finishRestored(pending, async () => {});
      expect(await fresh.get()).toMatchObject({
        version: 1,
        applied: null,
        pending: null,
      });
    }
  );

  test('a concurrent save prevents promotion before guard removal and retains its desired revision after restore', async () => {
    const { service, db } = await bootstrapFixture();
    const pending = await service.prepare(bootstrap(), null);
    await verified(service, pending);
    await db
      .update(schema.runtimeReconciliationState)
      .set({ desiredRevision: 3 })
      .execute();
    const removeGuard = vi.fn();
    await expect(service.finishApplied(pending, removeGuard)).rejects.toThrow(
      'desired_changed'
    );
    expect(removeGuard).not.toHaveBeenCalled();
    await service.markRestoring(pending, 'desired_changed');
    await service.finishRestored(pending, async () => {});
    expect(await service.get()).toMatchObject({
      version: 1,
      applied: null,
      pending: null,
      runtime: { desiredRevision: 3, appliedRevision: 2 },
    });
  });

  test('invalid or secret-bearing legacy baselines are refused before persistence', async () => {
    const { service } = await bootstrapFixture();
    const badPrefix = bootstrap();
    badPrefix.bootstrap!.peers[0]!.prefixes.push('198.51.100.0/24');
    const badIdentity = bootstrap();
    badIdentity.bootstrap!.clients[0]!.id = 74;
    const badGroup = bootstrap();
    badGroup.bootstrap!.groups[0]!.natEnabled = false;
    const secret = {
      ...bootstrap(),
      bootstrap: {
        ...bootstrap().bootstrap,
        privateKey: 'private fixture bytes',
      },
    };
    for (const invalid of [badPrefix, badIdentity, badGroup, secret]) {
      await expect(
        service.prepare(invalid as PendingPolicyTransition, null)
      ).rejects.toThrow('invalid_pending_transition');
      expect(await service.get()).toMatchObject({
        version: 1,
        applied: null,
        pending: null,
      });
    }
  });

  test('a verified policy never advances global Applied over a failed interface', async () => {
    const { db, service } = await fixture();
    await db
      .update(schema.interfaceRuntimeState)
      .set({
        status: 'degraded',
        observedUp: false,
        restartRequired: true,
        lastError: 'interface_unavailable',
      })
      .execute();
    const pending = await service.prepare(transition(), record());
    await verified(service, pending);
    await service.finishApplied(pending, async () => {});
    expect(await service.get()).toMatchObject({
      applied: record(2),
      pending: null,
      runtime: {
        desiredRevision: 2,
        appliedRevision: 1,
        status: 'degraded',
        lastError: 'interface_configuration_unapplied',
      },
    });
    // A health retry uses the same desired revision, not a new sequence.
    const retry = await service.prepare(transition(), record(2));
    await verified(service, retry);
    await service.finishApplied(retry, async (tx) => {
      await tx
        .update(schema.interfaceRuntimeState)
        .set({
          status: 'up',
          observedUp: true,
          restartRequired: false,
          lastError: null,
        })
        .execute();
    });
    expect(await service.get()).toMatchObject({
      applied: record(2),
      pending: null,
      runtime: {
        desiredRevision: 2,
        appliedRevision: 2,
        status: 'idle',
        lastError: null,
      },
    });
  });
  test.each([
    'pending revision',
    'pending status',
    'restart required',
    'unobserved enabled device',
  ])(
    'configuration evidence refuses false global convergence: %s',
    async (kind) => {
      const { db, service } = await fixture();
      const patch =
        kind === 'pending revision'
          ? { desiredRevision: 2 }
          : kind === 'pending status'
            ? { status: 'pending' as const }
            : kind === 'restart required'
              ? { restartRequired: true }
              : { observedUp: false };
      await db.update(schema.interfaceRuntimeState).set(patch).execute();
      const pending = await service.prepare(transition(), record());
      await verified(service, pending);
      await service.finishApplied(pending, async () => {});
      expect((await service.get()).runtime).toMatchObject({
        appliedRevision: 1,
        status: 'degraded',
      });
    }
  );
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
        .set({ appliedRevision: 2, desiredRevision: 2 })
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
