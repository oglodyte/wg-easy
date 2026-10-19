import { eq } from 'drizzle-orm';

import { general } from '../general/schema';

import { routingPolicyRuntime, runtimeReconciliationState } from './schema';

import type { DBType } from '#db/sqlite';
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
    const settings = await db.query.general.findFirst().execute();
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

/** Policy health cannot make an unverified interface configuration Applied. */
async function configurationsConverged(
  tx: PolicyPublicationTransaction,
  plan: RoutingPolicyJournal['plan']
) {
  const interfaces = await tx.query.wgInterface.findMany().execute();
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
        if (state.runtime.desiredRevision !== pending.revision)
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
        if (!restoring && state.runtime.desiredRevision !== pending.revision)
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
          !restoring && (await configurationsConverged(tx, pending.plan));
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
