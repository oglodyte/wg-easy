import { eq } from 'drizzle-orm';

import { general } from '../general/schema';

import { routingPolicyRuntime, runtimeReconciliationState } from './schema';

import type { DBType } from '#db/sqlite';
import { assertRoutingAvailabilityWithdrawal } from '#server/utils/routingPolicyAvailability';
import { RoutingKernelNamespaceSchema } from '#server/utils/routingPolicyKernelContext';
import {
  parsePendingPolicyTransition,
  parseRoutingPolicyJournal,
  RoutingPolicyJournalError,
} from '#server/utils/routingPolicyJournal';
import type {
  PendingPolicyTransition,
  RoutingPolicyJournal,
} from '#shared/types/routingPolicy';

export type PolicyPublicationTransaction = Parameters<
  Parameters<DBType['transaction']>[0]
>[0];
type Database = Pick<DBType, 'query' | 'update'>;
type TransitionIdentity = Pick<
  PendingPolicyTransition,
  'revision' | 'fingerprint' | 'backupBasenames'
>;
type Stage = PendingPolicyTransition['stage'];

const followingStage: Partial<Record<Stage, Stage>> = {
  prepared: 'guarded',
  guarded: 'peers',
  peers: 'classified',
  classified: 'verified',
};
function fail(code: string): never {
  throw new RoutingPolicyJournalError(code);
}
function sameJournal(
  a: Pick<RoutingPolicyJournal, 'revision' | 'fingerprint'> | null,
  b: Pick<RoutingPolicyJournal, 'revision' | 'fingerprint'> | null
) {
  return a?.revision === b?.revision && a?.fingerprint === b?.fingerprint;
}
function requireIdentity(
  pending: PendingPolicyTransition | null,
  expected: TransitionIdentity
) {
  // The private backup UUID distinguishes retries of the same revision/plan.
  if (
    !pending ||
    !sameJournal(pending, expected) ||
    JSON.stringify(pending.backupBasenames) !==
      JSON.stringify(expected.backupBasenames)
  )
    fail('transition_changed');
  return pending;
}

async function readState(db: Database) {
  try {
    const settings = await db.query.general
      .findFirst({ columns: { routingPolicyVersion: true } })
      .execute();
    if (!settings || ![1, 2].includes(settings.routingPolicyVersion))
      fail('version_unavailable');
    const row = await db.query.routingPolicyRuntime
      .findFirst({ where: eq(routingPolicyRuntime.id, 1) })
      .execute();
    const runtime = await db.query.runtimeReconciliationState
      .findFirst({ where: eq(runtimeReconciliationState.id, 1) })
      .execute();
    if (!row || !runtime) fail('state_missing');
    const applied =
      row.applied !== null ? parseRoutingPolicyJournal(row.applied) : null;
    const pending =
      row.pending !== null ? parsePendingPolicyTransition(row.pending) : null;
    if (pending?.withdrawal)
      assertRoutingAvailabilityWithdrawal(applied, pending);
    if (
      (settings.routingPolicyVersion === 1 &&
        (applied || (pending && !pending.bootstrap))) ||
      (settings.routingPolicyVersion === 2 && pending?.bootstrap)
    )
      fail('version_evidence_mismatch');
    if (
      !Number.isSafeInteger(runtime.desiredRevision) ||
      !Number.isSafeInteger(runtime.appliedRevision) ||
      runtime.appliedRevision < 0 ||
      runtime.desiredRevision < runtime.appliedRevision ||
      (applied &&
        (applied.revision < runtime.appliedRevision ||
          applied.revision > runtime.desiredRevision)) ||
      (pending &&
        (pending.revision > runtime.desiredRevision ||
          pending.revision < (applied?.revision ?? runtime.appliedRevision)))
    )
      fail('revision_evidence_mismatch');
    return {
      version: settings.routingPolicyVersion,
      applied,
      pending,
      runtime,
    };
  } catch (error) {
    if (error instanceof RoutingPolicyJournalError) throw error;
    // JSON decoding and database driver messages must not echo persisted input.
    fail('state_unreadable');
  }
}

/** Read inside the caller's existing transaction; never start a nested reader. */
export const readRoutingPolicyStateInTransaction = readState;

/** Policy health cannot make an unverified interface configuration Applied. */
async function configurationsConverged(
  tx: PolicyPublicationTransaction,
  plan: RoutingPolicyJournal['plan']
) {
  const interfaces = await tx.query.wgInterface
    .findMany({ columns: { name: true, enabled: true, pendingDelete: true } })
    .execute();
  const runtime = await tx.query.interfaceRuntimeState.findMany().execute();
  const states = new Map(runtime.map((i) => [i.interfaceId, i]));
  const planned = new Map(plan.interfaces.map((i) => [i.interfaceId, i]));
  return (
    interfaces.length === planned.size &&
    interfaces.every((iface) => {
      const state = states.get(iface.name),
        intended = planned.get(iface.name),
        enabled = iface.enabled && !iface.pendingDelete;
      return (
        state &&
        intended &&
        intended.enabled === enabled &&
        intended.observedUp === enabled &&
        state.observedUp === enabled &&
        state.status === (enabled ? 'up' : 'disabled') &&
        state.appliedRevision === state.desiredRevision &&
        !state.restartRequired &&
        state.lastError === null
      );
    })
  );
}

/** Inactive until promotion; the existing coordinator is its sole writer. */
export class RoutingPolicyRuntimeService {
  constructor(private readonly db: DBType) {}

  get() {
    return this.db.transaction((tx) => readState(tx));
  }

  async prepare(
    value: PendingPolicyTransition,
    expectedApplied: RoutingPolicyJournal | null
  ) {
    const pending = parsePendingPolicyTransition(value);
    const expected = expectedApplied
      ? parseRoutingPolicyJournal(expectedApplied)
      : null;
    if (
      pending.stage !== 'prepared' ||
      pending.errorCode !== null ||
      pending.backupBasenames.length !== 1
    )
      fail('invalid_preparation');
    await this.db.transaction(
      async (tx) => {
        const state = await readState(tx);
        if (pending.bootstrap) {
          if (state.version !== 1 || expected !== null)
            fail('version_unavailable');
          if (
            state.runtime.appliedRevision !== pending.revision ||
            !(await configurationsConverged(tx, pending.plan))
          )
            fail('bootstrap_not_converged');
        } else if (state.version !== 2) fail('version_unavailable');
        if (state.pending) fail('recovery_required');
        if (!sameJournal(state.applied, expected)) fail('applied_changed');
        if (pending.withdrawal)
          assertRoutingAvailabilityWithdrawal(state.applied, pending);
        else if (state.runtime.desiredRevision !== pending.revision)
          fail('desired_changed');
        await tx
          .update(routingPolicyRuntime)
          .set({ pending })
          .where(eq(routingPolicyRuntime.id, 1))
          .execute();
      },
      { behavior: 'immediate' }
    );
    return pending;
  }

  async advance(expected: TransitionIdentity, from: Stage, to: Stage) {
    if (followingStage[from] !== to) fail('invalid_stage_change');
    return this.db.transaction(
      async (tx) => {
        const state = await readState(tx);
        const pending = requireIdentity(state.pending, expected);
        if (pending.stage !== from) fail('stage_changed');
        const next = { ...pending, stage: to };
        await tx
          .update(routingPolicyRuntime)
          .set({ pending: next })
          .where(eq(routingPolicyRuntime.id, 1))
          .execute();
        return next;
      },
      { behavior: 'immediate' }
    );
  }

  async markRestoring(expected: TransitionIdentity, errorCode: string) {
    if (!/^[a-z][a-z0-9_]{0,95}$/.test(errorCode)) fail('invalid_error_code');
    return this.db.transaction(
      async (tx) => {
        const state = await readState(tx);
        const pending = requireIdentity(state.pending, expected);
        const next = { ...pending, stage: 'restoring' as const, errorCode };
        await tx
          .update(routingPolicyRuntime)
          .set({ pending: next })
          .where(eq(routingPolicyRuntime.id, 1))
          .execute();
        await tx
          .update(runtimeReconciliationState)
          .set({ status: 'degraded', lastError: errorCode })
          .where(eq(runtimeReconciliationState.id, 1))
          .execute();
        return next;
      },
      { behavior: 'immediate' }
    );
  }

  /** Restart completion of a safety withdrawal; never restore the lost device. */
  async resumeWithdrawal(expected: TransitionIdentity) {
    return this.db.transaction(
      async (tx) => {
        const state = await readState(tx);
        const pending = requireIdentity(state.pending, expected);
        assertRoutingAvailabilityWithdrawal(state.applied, pending);
        const next = { ...pending, stage: 'guarded' as const, errorCode: null };
        await tx
          .update(routingPolicyRuntime)
          .set({ pending: next })
          .where(eq(routingPolicyRuntime.id, 1))
          .execute();
        return next;
      },
      { behavior: 'immediate' }
    );
  }

  /** CAS rebase after old private files and a fresh down-baseline backup are durable. */
  async rebasePendingToWithdrawal(
    expected: TransitionIdentity,
    value: PendingPolicyTransition
  ) {
    const next = parsePendingPolicyTransition(value);
    if (
      !next.withdrawal?.resetNamespace ||
      next.stage !== 'prepared' ||
      next.errorCode !== null
    )
      fail('invalid_preparation');
    return this.db.transaction(
      async (tx) => {
        const state = await readState(tx);
        const pending = requireIdentity(state.pending, expected);
        if (
          state.version !== 2 ||
          !state.applied ||
          next.backupBasenames[0] === pending.backupBasenames[0] ||
          JSON.stringify(next.supersededGuardScopes) !==
            JSON.stringify(pending.guardScopes)
        )
          fail('invalid_namespace_rebase');
        assertRoutingAvailabilityWithdrawal(state.applied, next);
        await tx
          .update(routingPolicyRuntime)
          .set({ pending: next })
          .where(eq(routingPolicyRuntime.id, 1))
          .execute();
        await tx
          .update(runtimeReconciliationState)
          .set({ status: 'degraded', lastError: 'namespace_recovery_pending' })
          .where(eq(runtimeReconciliationState.id, 1))
          .execute();
        return next;
      },
      { behavior: 'immediate' }
    );
  }

  /** A lost first-promotion namespace has no v2 Applied generation to restore. */
  async cancelLostBootstrap(
    expected: TransitionIdentity,
    namespaceId: string,
    verifyUnavailable: (tx: PolicyPublicationTransaction) => Promise<void>
  ) {
    if (!RoutingKernelNamespaceSchema.safeParse(namespaceId).success)
      fail('namespace_evidence_required');
    await this.db.transaction(
      async (tx) => {
        const state = await readState(tx),
          pending = requireIdentity(state.pending, expected);
        if (
          state.version !== 1 ||
          state.applied ||
          !pending.bootstrap ||
          !pending.plan.namespaceId ||
          namespaceId === pending.plan.namespaceId
        )
          fail('bootstrap_cancellation_unavailable');
        try {
          await verifyUnavailable(tx);
        } catch {
          fail('final_verification_failed');
        }
        await tx
          .update(routingPolicyRuntime)
          .set({ applied: null, pending: null })
          .where(eq(routingPolicyRuntime.id, 1))
          .execute();
        await tx
          .update(runtimeReconciliationState)
          .set({ status: 'pending', lastError: 'bootstrap_namespace_reset' })
          .where(eq(runtimeReconciliationState.id, 1))
          .execute();
      },
      { behavior: 'immediate' }
    );
  }

  /**
   * Hold the desired-state writer lock across final guard removal, complete
   * verification and group evidence writes. If any fail, the durable pending
   * record survives; the caller must re-guard before restoring/retrying Linux.
   * A process crash after guard removal is recovered from that same record.
   */
  async finishApplied(
    expected: TransitionIdentity,
    verifyAndPublishGroups: (tx: PolicyPublicationTransaction) => Promise<void>
  ) {
    return this.finish(expected, false, verifyAndPublishGroups);
  }

  /** No target revision is published merely because rollback succeeded. */
  async finishRestored(
    expected: TransitionIdentity,
    verifyAndPublishGroups: (tx: PolicyPublicationTransaction) => Promise<void>
  ) {
    return this.finish(expected, true, verifyAndPublishGroups);
  }

  private async finish(
    expected: TransitionIdentity,
    restoring: boolean,
    verifyAndPublishGroups: (tx: PolicyPublicationTransaction) => Promise<void>
  ) {
    return this.db.transaction(
      async (tx) => {
        const state = await readState(tx);
        const pending = requireIdentity(state.pending, expected);
        if (pending.stage !== (restoring ? 'restoring' : 'verified'))
          fail('stage_changed');
        if (pending.withdrawal && restoring)
          fail('withdrawal_requires_completion');
        if (
          !restoring &&
          !pending.withdrawal &&
          state.runtime.desiredRevision !== pending.revision
        )
          fail('desired_changed');
        try {
          await verifyAndPublishGroups(tx);
        } catch {
          fail('final_verification_failed');
        }
        const applied = restoring
          ? state.applied
          : parseRoutingPolicyJournal({
              revision: pending.revision,
              fingerprint: pending.fingerprint,
              plan: pending.plan,
            });
        const complete =
          !restoring &&
          !pending.withdrawal &&
          (await configurationsConverged(tx, pending.plan));
        if (pending.bootstrap && !restoring) {
          if (!complete) fail('bootstrap_not_converged');
          await tx.update(general).set({ routingPolicyVersion: 2 }).execute();
        }
        await tx
          .update(routingPolicyRuntime)
          .set({ applied, pending: null })
          .where(eq(routingPolicyRuntime.id, 1))
          .execute();
        await tx
          .update(runtimeReconciliationState)
          .set(
            restoring
              ? {
                  status: 'pending',
                  lastError: 'routing_policy_restored',
                }
              : complete
                ? {
                    appliedRevision: pending.revision,
                    status: 'idle',
                    lastSucceededAt: new Date().toISOString(),
                    lastError: null,
                  }
                : {
                    status: 'degraded',
                    lastError: 'interface_configuration_unapplied',
                  }
          )
          .where(eq(runtimeReconciliationState.id, 1))
          .execute();
        return applied;
      },
      { behavior: 'immediate' }
    );
  }
}
