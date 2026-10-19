import type {
  PolicyPublicationTransaction,
  RoutingPolicyRuntimeService,
} from '#db/repositories/runtime/policyService';
import type { RoutingExecutor } from '#server/utils/routingExecutor';
import {
  buildRoutingGuard,
  type RoutingGuard,
  type RoutingGuardPlan,
  type RoutingGuardScope,
} from '#server/utils/routingGuard';
import type { RoutingPolicyBackups } from '#server/utils/routingPolicyBackups';
import {
  parseRoutingPolicyJournal,
  RoutingPolicyJournalError,
} from '#server/utils/routingPolicyJournal';
import { renderRoutingPolicyLinux } from '#server/utils/routingPolicyLinux';
import { buildRoutingPolicyTransition } from '#server/utils/routingPolicyTransition';
import type {
  AppliedRoutingPolicyPlan,
  PendingPolicyTransition,
  RoutingPolicyJournal,
} from '#shared/types/routingPolicy';

/** Called inside the existing serialized coordinator, never a second loop. */
export type PolicyRecoveryDependencies = {
  journal: RoutingPolicyRuntimeService;
  backups: RoutingPolicyBackups;
  executor: RoutingExecutor;
  guard: RoutingGuard;
  protectedPaths: readonly RoutingGuardScope[];
  preflightManagedState: (
    previous: AppliedRoutingPolicyPlan,
    target: AppliedRoutingPolicyPlan
  ) => Promise<void>;
  applyManagedState: (
    target: AppliedRoutingPolicyPlan,
    guard: RoutingGuardPlan
  ) => Promise<void>;
  restoreManagedState: (
    previous: AppliedRoutingPolicyPlan,
    backup: string,
    guard: RoutingGuardPlan
  ) => Promise<void>;
  verifyManagedState: (
    plan: AppliedRoutingPolicyPlan,
    guard: RoutingGuardPlan | null
  ) => Promise<void>;
  validateConfig: (interfaceId: string, temporaryPath: string) => Promise<void>;
  publishGroups: (
    tx: PolicyPublicationTransaction,
    record: RoutingPolicyJournal,
    restored: boolean
  ) => Promise<void>;
};
export type PolicyTransitionResult =
  | {
      status: 'applied' | 'restored';
      cleanupPending: boolean;
    }
  | { status: 'failed'; guarded: boolean; errorCode: string };

async function ensureGuard(
  deps: PolicyRecoveryDependencies,
  guard: RoutingGuardPlan
) {
  try {
    await deps.guard.verify(guard);
    return;
  } catch {
    /* Inspect absence before installing; unknown state stays untouched. */
  }
  await deps.guard.ensure(guard);
}
async function cleanup(
  deps: PolicyRecoveryDependencies,
  pending: PendingPolicyTransition
) {
  try {
    await deps.backups.remove(pending.backupBasenames[0]!);
    return false;
  } catch {
    return true;
  } // Only a private unreferenced orphan remains; no rollback after publication.
}
function safeFailure(error: unknown) {
  return error instanceof RoutingPolicyJournalError
    ? error.code
    : 'transition_failed';
}

/** Recover persisted uncertainty before starting another desired generation. */
export async function restorePendingRoutingPolicy(
  deps: PolicyRecoveryDependencies
): Promise<PolicyTransitionResult> {
  const state = await deps.journal.get();
  if (!state.pending) throw new RoutingPolicyJournalError('transition_missing');
  if (!state.applied)
    throw new RoutingPolicyJournalError('bootstrap_recovery_unavailable');
  const pending = state.pending,
    previous = state.applied;
  const previousLinux = renderRoutingPolicyLinux(previous.plan),
    targetLinux = renderRoutingPolicyLinux(pending.plan);
  // Use the persisted closure, not a reduced closure recomputed after a crash.
  const guard = buildRoutingGuard(pending.guardScopes, {
    protectedPaths: deps.protectedPaths,
  });
  try {
    await ensureGuard(deps, guard);
    await deps.journal.markRestoring(
      pending,
      pending.errorCode ?? 'interrupted_transition'
    );
    // This restoration uses private prior bytes even if desired rows/keys are gone.
    await deps.backups.restore(
      pending.backupBasenames[0]!,
      deps.validateConfig
    );
    await deps.guard.verify(guard);
    await deps.restoreManagedState(
      previous.plan,
      pending.backupBasenames[0]!,
      guard
    );
    await deps.guard.verify(guard);
    await deps.executor.apply(previousLinux, {
      previousPlan: targetLinux,
      guardedTransition: { guard, knownPlans: [targetLinux] },
    });
    await deps.verifyManagedState(previous.plan, guard);
    await deps.executor.verify(previousLinux, guard);
    await deps.journal.finishRestored(pending, async (tx) => {
      await deps.guard.remove(guard);
      await deps.executor.verify(previousLinux, null);
      await deps.verifyManagedState(previous.plan, null);
      await deps.publishGroups(tx, previous, true);
    });
  } catch (error) {
    let guarded: boolean;
    try {
      await ensureGuard(deps, guard);
      guarded = true;
    } catch {
      guarded = false;
    }
    const errorCode = safeFailure(error);
    await deps.journal.markRestoring(pending, errorCode).catch(() => {});
    return { status: 'failed', guarded, errorCode };
  }
  return { status: 'restored', cleanupPending: await cleanup(deps, pending) };
}

/** Inactive orchestration primitive; bootstrap/promotion must be supplied first. */
export async function applyGuardedRoutingPolicy(
  deps: PolicyRecoveryDependencies,
  value: RoutingPolicyJournal,
  {
    forcePeerIds = new Set<string>(),
  }: { forcePeerIds?: ReadonlySet<string> } = {}
): Promise<PolicyTransitionResult> {
  const target = parseRoutingPolicyJournal(value);
  const state = await deps.journal.get();
  if (state.pending) throw new RoutingPolicyJournalError('recovery_required');
  if (!state.applied)
    throw new RoutingPolicyJournalError('bootstrap_recovery_unavailable');
  const previous = state.applied;
  const guard = buildRoutingPolicyTransition(previous.plan, target.plan, {
    protectedPaths: deps.protectedPaths,
    forcePeerIds,
  });
  const previousLinux = renderRoutingPolicyLinux(previous.plan),
    targetLinux = renderRoutingPolicyLinux(target.plan);
  try {
    await deps.preflightManagedState(previous.plan, target.plan);
    await deps.executor.prepare(targetLinux, {
      previousPlan: previousLinux,
      knownPlans: [previousLinux],
    });
    await deps.guard.prepare(guard, null);
  } catch {
    throw new RoutingPolicyJournalError('preflight_failed');
  }
  const interfaces = [
    ...new Set(
      [...previous.plan.interfaces, ...target.plan.interfaces].map(
        (i) => i.interfaceId
      )
    ),
  ];
  const basename = await deps.backups.create(interfaces);
  let pending: PendingPolicyTransition;
  try {
    pending = await deps.journal.prepare(
      {
        ...target,
        stage: 'prepared',
        guardScopes: guard.scopes,
        backupBasenames: [basename],
        errorCode: null,
      },
      previous
    );
  } catch (error) {
    // Confirm no committed journal references the file before exact owned cleanup.
    const latest = await deps.journal.get();
    if (!latest.pending?.backupBasenames.includes(basename))
      await deps.backups.remove(basename).catch(() => {});
    throw error;
  }
  try {
    await deps.guard.install(guard);
    await deps.journal.advance(pending, 'prepared', 'guarded');
    await deps.guard.verify(guard);
    await deps.applyManagedState(target.plan, guard);
    await deps.guard.verify(guard);
    await deps.verifyManagedState(target.plan, guard);
    await deps.journal.advance(pending, 'guarded', 'peers');
    await deps.executor.apply(targetLinux, {
      previousPlan: previousLinux,
      guardedTransition: { guard, knownPlans: [previousLinux] },
    });
    await deps.journal.advance(pending, 'peers', 'classified');
    await deps.verifyManagedState(target.plan, guard);
    await deps.executor.verify(targetLinux, guard);
    await deps.journal.advance(pending, 'classified', 'verified');
    await deps.journal.finishApplied(pending, async (tx) => {
      await deps.guard.remove(guard);
      await deps.executor.verify(targetLinux, null);
      await deps.verifyManagedState(target.plan, null);
      await deps.publishGroups(tx, target, false);
    });
  } catch (error) {
    await deps.journal
      .markRestoring(pending, safeFailure(error))
      .catch(() => {});
    return restorePendingRoutingPolicy(deps);
  }
  return { status: 'applied', cleanupPending: await cleanup(deps, pending) };
}
