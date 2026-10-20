import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, describe, expect, test, vi } from 'vitest';

import { createNodeSqliteDatabase } from '#db/nodeSqlite';
import { RoutingPolicyRuntimeService } from '#db/repositories/runtime/policyService';
import * as schema from '#db/schema';
import { RoutingExecutor } from '#server/utils/routingExecutor';
import { RoutingGuard } from '#server/utils/routingGuard';
import { RoutingPolicyBackups } from '#server/utils/routingPolicyBackups';
import {
  applyGuardedRoutingPolicy,
  restorePendingRoutingPolicy,
  type PolicyRecoveryDependencies,
} from '#server/utils/routingPolicyRecovery';
import { routingPolicyRuntimeFingerprint } from '#server/utils/routingPolicyRuntime';
import { deriveRoutingAvailabilityWithdrawal } from '#server/utils/routingPolicyAvailability';
import { buildRoutingPolicyTransition } from '#server/utils/routingPolicyTransition';
import type {
  AppliedRoutingPolicyPlan,
  RoutingPolicyJournal,
  PendingPolicyTransition,
  PolicyBootstrapBaseline,
} from '#shared/types/routingPolicy';

const roots: string[] = [],
  stores: ReturnType<typeof createNodeSqliteDatabase>[] = [];
afterEach(async () => {
  await Promise.all(stores.splice(0).map((s) => s.close()));
  await Promise.all(roots.splice(0).map((r) => fs.rm(r, { recursive: true })));
});
function record(revision: number, peerId: string): RoutingPolicyJournal {
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
    groups: [],
    peers: [
      { clientId: 73, interfaceId: 'wg0', peerId, prefixes: ['10.8.0.2/32'] },
    ],
  };
  return { revision, plan, fingerprint: routingPolicyRuntimeFingerprint(plan) };
}
async function fixture({ bootstrap = false } = {}) {
  const directory = await fs.mkdtemp(
    path.join(os.tmpdir(), 'wg-easy-policy-recovery-')
  );
  roots.push(directory);
  const databasePath = path.join(directory, 'test.db');
  const store = createNodeSqliteDatabase(databasePath, schema);
  stores.push(store);
  await store.migrate({
    migrationsFolder: fileURLToPath(
      new URL('../../server/database/migrations', import.meta.url)
    ),
  });
  const previous = bootstrap
      ? record(2, 'b'.repeat(64))
      : record(1, 'a'.repeat(64)),
    target = record(2, 'b'.repeat(64));
  await store.db
    .update(schema.general)
    .set({ routingPolicyVersion: bootstrap ? 1 : 2 })
    .execute();
  await store.db
    .update(schema.runtimeReconciliationState)
    .set({
      desiredRevision: 2,
      appliedRevision: bootstrap ? 2 : 1,
      status: 'pending',
    })
    .execute();
  await store.db
    .update(schema.routingPolicyRuntime)
    .set({ applied: bootstrap ? null : previous })
    .execute();
  if (bootstrap)
    await store.db
      .update(schema.interfaceRuntimeState)
      .set({
        desiredRevision: 2,
        appliedRevision: 2,
        observedUp: true,
        status: 'up',
      })
      .execute();
  const baseline: PolicyBootstrapBaseline | undefined = bootstrap
    ? {
        interfaces: previous.plan.interfaces,
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
        groups: [],
        peers: previous.plan.peers,
      }
    : undefined;
  const configPath = path.join(directory, 'wg0.conf');
  await fs.writeFile(configPath, '# prior fixture bytes\n', { mode: 0o600 });
  const state = {
    activeGuard: null as string | null,
    peer: previous.fingerprint,
    linux: bootstrap ? 'legacy' : previous.fingerprint,
    failAt: '',
    failed: false,
    restoreFails: false,
    bumpDesired: false,
    afterRemove: false,
  };
  const events: string[] = [];
  function fault(at: string) {
    events.push(at);
    if (state.failAt === at && !state.failed) {
      state.failed = true;
      throw new Error('sensitive backend fixture input');
    }
  }
  const executor = new RoutingExecutor(async () => ''),
    guard = new RoutingGuard(async () => '');
  vi.spyOn(executor, 'prepare').mockImplementation(async () => {
    fault('preflight');
  });
  vi.spyOn(executor, 'apply').mockImplementation(async (plan) => {
    expect(state.activeGuard).not.toBeNull();
    state.linux = plan.classifier?.fingerprint ?? 'legacy';
    fault('linux');
  });
  vi.spyOn(executor, 'verify').mockImplementation(
    async (plan, expectedGuard) => {
      expect(state.linux).toBe(plan.classifier?.fingerprint ?? 'legacy');
      expect(state.activeGuard).toBe(expectedGuard?.fingerprint ?? null);
      fault(expectedGuard ? 'guarded_verify' : 'unguarded_verify');
    }
  );
  vi.spyOn(guard, 'prepare').mockImplementation(async () => {
    expect(state.activeGuard).toBeNull();
    return null;
  });
  vi.spyOn(guard, 'install').mockImplementation(async (plan) => {
    state.activeGuard = plan.fingerprint;
    fault('guard');
  });
  vi.spyOn(guard, 'verify').mockImplementation(async (plan) => {
    expect(state.activeGuard).toBe(plan?.fingerprint ?? null);
  });
  vi.spyOn(guard, 'ensure').mockImplementation(async (plan) => {
    if (state.activeGuard !== null && state.activeGuard !== plan.fingerprint)
      throw new Error('unknown guard state');
    if (state.activeGuard === null) await guard.install(plan);
    await guard.verify(plan);
  });
  vi.spyOn(guard, 'remove').mockImplementation(async (plan) => {
    expect(state.activeGuard).toBe(plan.fingerprint);
    state.activeGuard = null;
    state.afterRemove = true;
    fault('remove');
  });
  const backups = new RoutingPolicyBackups(directory);
  const deps: PolicyRecoveryDependencies = {
    journal: new RoutingPolicyRuntimeService(store.db),
    backups,
    executor,
    guard,
    protectedPaths: [],
    previousConfigurations: new Map([['wg0', '# prior fixture bytes\n']]),
    candidateConfigurations: new Map([['wg0', '# candidate fixture bytes\n']]),
    preflightManagedState: async () => {
      fault('managed_preflight');
    },
    applyManagedState: async (plan) => {
      expect(state.activeGuard).not.toBeNull();
      expect((await deps.journal.get()).pending?.stage).toBe('guarded');
      await fs.writeFile(
        configPath,
        deps.candidateConfigurations?.get('wg0') ??
          '# candidate fixture bytes\n'
      );
      state.peer = routingPolicyRuntimeFingerprint(plan);
      fault('peers');
      if (state.bumpDesired)
        await store.db
          .update(schema.runtimeReconciliationState)
          .set({ desiredRevision: 3 })
          .execute();
    },
    restoreManagedState: async (plan) => {
      expect(state.activeGuard).not.toBeNull();
      expect(await fs.readFile(configPath, 'utf8')).toBe(
        '# prior fixture bytes\n'
      );
      fault('restore');
      if (state.restoreFails) throw new Error('restore failed');
      state.peer = routingPolicyRuntimeFingerprint(plan);
    },
    verifyManagedState: async (plan) => {
      expect(state.peer).toBe(routingPolicyRuntimeFingerprint(plan));
      fault(state.afterRemove ? 'peers_after_remove' : 'peer_verify');
    },
    validateConfig: async () => {
      fault('validate_restore');
    },
    publishGroups: async (tx, applied) => {
      expect(state.activeGuard).toBeNull();
      await tx
        .update(schema.interfaceRuntimeState)
        .set({
          appliedRevision: applied.revision,
          desiredRevision: applied.revision,
          observedUp: true,
          status: 'up',
        })
        .execute();
      fault('publish');
    },
  };
  return {
    directory,
    databasePath,
    store,
    configPath,
    previous,
    target,
    state,
    events,
    deps,
    baseline,
  };
}

describe('inactive guarded peer-aware orchestration', () => {
  test.each(['guard', 'peers', 'linux', 'remove', 'publish'])(
    'completes a durable withdrawal down after %s failure, without restoring the historical up-device',
    async (failure) => {
      const f = await fixture();
      f.deps.candidateConfigurations = f.deps.previousConfigurations;
      f.previous.plan.namespaceId =
        '11111111-1111-4111-8111-111111111111:4:4026531001';
      f.previous.plan.interfaces[0]!.hooksApplied = true;
      f.previous.fingerprint = routingPolicyRuntimeFingerprint(f.previous.plan);
      await f.store.db
        .update(schema.routingPolicyRuntime)
        .set({ applied: f.previous })
        .execute();
      f.state.peer = f.previous.fingerprint;
      f.state.linux = f.previous.fingerprint;
      const down = deriveRoutingAvailabilityWithdrawal(
        f.previous,
        new Set(['wg0']),
        {
          namespaceId: f.previous.plan.namespaceId,
        }
      );
      const restore = f.deps.restoreManagedState;
      f.deps.restoreManagedState = async (plan, backup, guard) => {
        expect(plan.interfaces[0]).toMatchObject({
          observedUp: false,
          hooksApplied: true,
        });
        await restore(plan, backup, guard);
      };
      f.deps.beforeRestoreManagedState = async (previous, target) => {
        expect(previous).toEqual(down.plan);
        expect(target).toEqual(down.plan);
      };
      f.state.failAt = failure;
      f.state.bumpDesired = true;
      expect(
        await applyGuardedRoutingPolicy(f.deps, down, {
          withdrawal: {
            unavailableInterfaceIds: ['wg0'],
            resetNamespace: false,
          },
        })
      ).toEqual({ status: 'applied', cleanupPending: false });
      expect(await f.deps.journal.get()).toMatchObject({
        applied: down,
        pending: null,
        runtime: { appliedRevision: 1, status: 'degraded' },
      });
      expect(f.state.peer).toBe(down.fingerprint);
      expect(f.state.activeGuard).toBeNull();
    }
  );

  test('an interrupted withdrawal retains private evidence and resumes forward after reopening storage', async () => {
    const f = await fixture();
    f.deps.candidateConfigurations = f.deps.previousConfigurations;
    f.previous.plan.namespaceId =
      '11111111-1111-4111-8111-111111111111:4:4026531001';
    f.previous.plan.interfaces[0]!.hooksApplied = true;
    f.previous.fingerprint = routingPolicyRuntimeFingerprint(f.previous.plan);
    await f.store.db
      .update(schema.routingPolicyRuntime)
      .set({ applied: f.previous })
      .execute();
    f.state.linux = f.previous.fingerprint;
    const down = deriveRoutingAvailabilityWithdrawal(
      f.previous,
      new Set(['wg0']),
      {
        namespaceId: f.previous.plan.namespaceId,
      }
    );
    f.state.failAt = 'linux';
    f.state.restoreFails = true;
    expect(
      await applyGuardedRoutingPolicy(f.deps, down, {
        withdrawal: { unavailableInterfaceIds: ['wg0'], resetNamespace: false },
      })
    ).toMatchObject({ status: 'failed', guarded: true });
    const pending = (await f.deps.journal.get()).pending!;
    expect(pending).toMatchObject({
      withdrawal: { unavailableInterfaceIds: ['wg0'] },
      stage: 'restoring',
    });
    await f.deps.backups.readPrivateConfigurations(pending.backupBasenames[0]!);
    await f.store.close();
    const reopened = createNodeSqliteDatabase(f.databasePath, schema);
    stores.push(reopened);
    f.deps.journal = new RoutingPolicyRuntimeService(reopened.db);
    f.state.restoreFails = false;
    const restore = f.deps.restoreManagedState;
    f.deps.restoreManagedState = async (plan, backup, guard) => {
      expect(plan).toEqual(down.plan);
      await restore(plan, backup, guard);
    };
    expect(await restorePendingRoutingPolicy(f.deps)).toEqual({
      status: 'applied',
      cleanupPending: false,
    });
    expect(await f.deps.journal.get()).toMatchObject({
      applied: down,
      pending: null,
    });
  });

  test('stops candidate runtime under the guard using durable candidate bytes before old files are restored', async () => {
    const f = await fixture();
    f.deps.candidateConfigurations = new Map([
      ['wg0', '# candidate fixture bytes\n'],
    ]);
    f.state.failAt = 'linux';
    let failStop = true;
    f.deps.beforeRestoreManagedState = async (
      _previous,
      _target,
      reference,
      guard
    ) => {
      await f.deps.guard.verify(guard);
      expect((await f.deps.journal.get()).pending?.stage).toBe('restoring');
      expect(await fs.readFile(f.configPath, 'utf8')).toBe(
        '# candidate fixture bytes\n'
      );
      expect(await f.deps.backups.readPrivateConfigurations(reference)).toEqual(
        [
          {
            interfaceId: 'wg0',
            config: '# prior fixture bytes\n',
            candidate: '# candidate fixture bytes\n',
          },
        ]
      );
      f.events.push('stop_candidate');
      if (failStop) throw new Error('private candidate hook failure');
    };
    expect(await applyGuardedRoutingPolicy(f.deps, f.target)).toMatchObject({
      status: 'failed',
      guarded: true,
    });
    expect((await f.deps.journal.get()).applied).toEqual(f.previous);
    expect(f.events).not.toContain('validate_restore');
    expect(await fs.readFile(f.configPath, 'utf8')).toBe(
      '# candidate fixture bytes\n'
    );
    failStop = false;
    expect(await restorePendingRoutingPolicy(f.deps)).toEqual({
      status: 'restored',
      cleanupPending: false,
    });
    expect(f.events.indexOf('stop_candidate')).toBeLessThan(
      f.events.indexOf('validate_restore')
    );
    expect(await fs.readFile(f.configPath, 'utf8')).toBe(
      '# prior fixture bytes\n'
    );
    expect(f.state.activeGuard).toBeNull();
    expect((await f.deps.journal.get()).pending).toBeNull();
  });

  test('bootstraps a verified v1 generation without storing false v2 evidence before publication', async () => {
    const f = await fixture({ bootstrap: true });
    expect(
      await applyGuardedRoutingPolicy(f.deps, f.target, {
        bootstrap: f.baseline,
      })
    ).toEqual({ status: 'applied', cleanupPending: false });
    expect(await f.deps.journal.get()).toMatchObject({
      version: 2,
      applied: f.target,
      pending: null,
    });
    expect(f.events.indexOf('guard')).toBeLessThan(f.events.indexOf('peers'));
    expect(f.events.indexOf('remove')).toBeLessThan(
      f.events.indexOf('publish')
    );
  });

  test.each([
    'guard',
    'peers',
    'peer_verify',
    'linux',
    'guarded_verify',
    'remove',
    'peers_after_remove',
    'publish',
  ])(
    'restores the old legacy Linux plan/private bytes and version 1 after bootstrap failure at %s',
    async (failure) => {
      const f = await fixture({ bootstrap: true });
      f.state.failAt = failure;
      expect(
        await applyGuardedRoutingPolicy(f.deps, f.target, {
          bootstrap: f.baseline,
        })
      ).toEqual({ status: 'restored', cleanupPending: false });
      expect(await f.deps.journal.get()).toMatchObject({
        version: 1,
        applied: null,
        pending: null,
        runtime: { appliedRevision: 2 },
      });
      expect(f.state.linux).toBe('legacy');
      expect(f.state.activeGuard).toBeNull();
      expect(await fs.readFile(f.configPath, 'utf8')).toBe(
        '# prior fixture bytes\n'
      );
    }
  );

  test('an interrupted bootstrap retains its old baseline and private bytes when restoration fails, then a fresh instance recovers it', async () => {
    const f = await fixture({ bootstrap: true });
    f.state.failAt = 'linux';
    f.state.restoreFails = true;
    expect(
      await applyGuardedRoutingPolicy(f.deps, f.target, {
        bootstrap: f.baseline,
      })
    ).toMatchObject({ status: 'failed', guarded: true });
    expect(await f.deps.journal.get()).toMatchObject({
      version: 1,
      applied: null,
      pending: { bootstrap: f.baseline, stage: 'restoring' },
    });
    await f.store.close();
    const reopened = createNodeSqliteDatabase(f.databasePath, schema);
    stores.push(reopened);
    f.deps.journal = new RoutingPolicyRuntimeService(reopened.db);
    f.state.restoreFails = false;
    expect(await restorePendingRoutingPolicy(f.deps)).toEqual({
      status: 'restored',
      cleanupPending: false,
    });
    expect(f.state.linux).toBe('legacy');
    expect(f.state.activeGuard).toBeNull();
    expect(await f.deps.journal.get()).toMatchObject({
      version: 1,
      applied: null,
      pending: null,
    });
  });

  test('a stale desired revision during first activation restores v1 without losing the newer save', async () => {
    const f = await fixture({ bootstrap: true });
    f.state.bumpDesired = true;
    expect(
      await applyGuardedRoutingPolicy(f.deps, f.target, {
        bootstrap: f.baseline,
      })
    ).toMatchObject({ status: 'restored' });
    expect(await f.deps.journal.get()).toMatchObject({
      version: 1,
      applied: null,
      pending: null,
      runtime: { desiredRevision: 3, appliedRevision: 2 },
    });
    expect(f.state.linux).toBe('legacy');
  });

  test('preflights before durable preparation, guards before peer writes and publishes only after complete absence verification', async () => {
    const f = await fixture();
    expect(await applyGuardedRoutingPolicy(f.deps, f.target)).toEqual({
      status: 'applied',
      cleanupPending: false,
    });
    expect(await f.deps.journal.get()).toMatchObject({
      applied: f.target,
      pending: null,
      runtime: { appliedRevision: 2 },
    });
    expect(f.events.indexOf('preflight')).toBeLessThan(
      f.events.indexOf('guard')
    );
    expect(f.events.indexOf('guard')).toBeLessThan(f.events.indexOf('peers'));
    expect(f.events.indexOf('remove')).toBeLessThan(
      f.events.indexOf('publish')
    );
    expect(f.events).not.toContain('restore');
    expect(
      (await fs.readdir(f.deps.backups.directory)).filter((n) =>
        n.endsWith('.json')
      )
    ).toEqual([]);
  });
  test('rejects preflight without Linux or peer mutations and redacts its cause', async () => {
    const f = await fixture();
    f.state.failAt = 'managed_preflight';
    await expect(applyGuardedRoutingPolicy(f.deps, f.target)).rejects.toThrow(
      'Routing policy recovery: preflight_failed'
    );
    expect(f.events).toEqual(['managed_preflight']);
    expect((await f.deps.journal.get()).pending).toBeNull();
    expect(f.state.peer).toBe(f.previous.fingerprint);
  });
  test.each([
    'guard',
    'peers',
    'peer_verify',
    'linux',
    'guarded_verify',
    'remove',
    'peers_after_remove',
    'publish',
  ])(
    'restores prior bytes/peers and never publishes the target after failure at %s',
    async (failure) => {
      const f = await fixture();
      f.state.failAt = failure;
      expect(await applyGuardedRoutingPolicy(f.deps, f.target)).toEqual({
        status: 'restored',
        cleanupPending: false,
      });
      expect(await fs.readFile(f.configPath, 'utf8')).toBe(
        '# prior fixture bytes\n'
      );
      expect(f.state.peer).toBe(f.previous.fingerprint);
      expect(f.state.linux).toBe(f.previous.fingerprint);
      expect(f.state.activeGuard).toBeNull();
      expect(await f.deps.journal.get()).toMatchObject({
        applied: f.previous,
        pending: null,
        runtime: { appliedRevision: 1, status: 'pending' },
      });
      expect(
        (await f.store.db.query.interfaceRuntimeState.findFirst())
          ?.appliedRevision
      ).toBe(1);
    }
  );
  test('retains scoped guard, pending evidence and backup if prior peer restoration cannot be verified', async () => {
    const f = await fixture();
    f.state.failAt = 'linux';
    f.state.restoreFails = true;
    expect(await applyGuardedRoutingPolicy(f.deps, f.target)).toEqual({
      status: 'failed',
      guarded: true,
      errorCode: 'transition_failed',
    });
    const evidence = await f.deps.journal.get();
    expect(evidence).toMatchObject({
      applied: f.previous,
      pending: { stage: 'restoring' },
      runtime: { appliedRevision: 1, status: 'degraded' },
    });
    expect(f.state.activeGuard).not.toBeNull();
    expect(
      await fs.stat(
        path.join(
          f.deps.backups.directory,
          evidence.pending!.backupBasenames[0]!
        )
      )
    ).toBeDefined();
    f.state.restoreFails = false;
    expect(await restorePendingRoutingPolicy(f.deps)).toEqual({
      status: 'restored',
      cleanupPending: false,
    });
    expect(f.state.activeGuard).toBeNull();
  });
  test('coalesces a newer desired generation by restoring without advancing Applied', async () => {
    const f = await fixture();
    f.state.bumpDesired = true;
    expect(await applyGuardedRoutingPolicy(f.deps, f.target)).toMatchObject({
      status: 'restored',
    });
    expect(await f.deps.journal.get()).toMatchObject({
      applied: f.previous,
      pending: null,
      runtime: { desiredRevision: 3, appliedRevision: 1 },
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
    'a new service recovers persisted %s uncertainty, including an absent guard after removal',
    async (stage) => {
      const f = await fixture();
      const guard = buildRoutingPolicyTransition(
        f.previous.plan,
        f.target.plan,
        { protectedPaths: [] }
      );
      const basename = await f.deps.backups.create(['wg0']);
      const pending = await f.deps.journal.prepare(
        {
          ...f.target,
          stage: 'prepared',
          guardScopes: guard.scopes,
          backupBasenames: [basename],
          errorCode: null,
        },
        f.previous
      );
      let at: PendingPolicyTransition['stage'] = 'prepared';
      for (const next of [
        'guarded',
        'peers',
        'classified',
        'verified',
      ] as const) {
        if (at === stage || stage === 'restoring') break;
        await f.deps.journal.advance(pending, at, next);
        at = next;
      }
      if (stage === 'restoring')
        await f.deps.journal.markRestoring(pending, 'interrupted_transition');
      await fs.writeFile(f.configPath, '# uncertain candidate bytes\n');
      f.state.peer = f.target.fingerprint;
      f.state.linux = f.target.fingerprint;
      f.state.activeGuard =
        stage === 'verified' || stage === 'prepared' ? null : guard.fingerprint;
      await f.store.close();
      const reopened = createNodeSqliteDatabase(f.databasePath, schema);
      stores.push(reopened);
      f.deps.journal = new RoutingPolicyRuntimeService(reopened.db);
      expect(await restorePendingRoutingPolicy(f.deps)).toEqual({
        status: 'restored',
        cleanupPending: false,
      });
      expect(await f.deps.journal.get()).toMatchObject({
        applied: f.previous,
        pending: null,
        runtime: { appliedRevision: 1 },
      });
      expect(await fs.readFile(f.configPath, 'utf8')).toBe(
        '# prior fixture bytes\n'
      );
      expect(f.state.activeGuard).toBeNull();
    }
  );
  test('private cleanup failure cannot roll back an already verified and published generation', async () => {
    const f = await fixture();
    vi.spyOn(f.deps.backups, 'remove').mockRejectedValue(
      new Error('cleanup failed')
    );
    expect(await applyGuardedRoutingPolicy(f.deps, f.target)).toEqual({
      status: 'applied',
      cleanupPending: true,
    });
    expect(await f.deps.journal.get()).toMatchObject({
      applied: f.target,
      pending: null,
      runtime: { appliedRevision: 2 },
    });
    expect(f.events).not.toContain('restore');
  });
  test('unknown guard state is preserved and is never reported as verified protection', async () => {
    const f = await fixture();
    const closure = buildRoutingPolicyTransition(
      f.previous.plan,
      f.target.plan,
      { protectedPaths: [] }
    );
    const basename = await f.deps.backups.create(['wg0']);
    await f.deps.journal.prepare(
      {
        ...f.target,
        stage: 'prepared',
        guardScopes: closure.scopes,
        backupBasenames: [basename],
        errorCode: null,
      },
      f.previous
    );
    f.state.activeGuard = 'foreign-manifest';
    expect(await restorePendingRoutingPolicy(f.deps)).toEqual({
      status: 'failed',
      guarded: false,
      errorCode: 'transition_failed',
    });
    expect(f.state.activeGuard).toBe('foreign-manifest');
    expect(f.deps.guard.install).not.toHaveBeenCalled();
    expect(f.deps.executor.apply).not.toHaveBeenCalled();
    expect(f.events).not.toContain('restore');
    expect((await f.deps.journal.get()).pending?.backupBasenames).toEqual([
      basename,
    ]);
  });
});
