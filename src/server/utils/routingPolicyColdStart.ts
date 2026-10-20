import fs from 'node:fs/promises';

import type {
  RoutingPolicyRuntimeService,
  PolicyPublicationTransaction,
} from '#db/repositories/runtime/policyService';
import {
  ManagedInterfaceTransition,
  type ManagedInterfaceDevices,
} from '#server/utils/managedInterfaceTransition';
import type { ManagedServerHookEffects } from '#server/utils/managedServerHooks';
import {
  isOwnedRoutingRoute,
  isOwnedRoutingRule,
  preflightRoutingOwnership,
} from '#server/utils/routing';
import { deriveRoutingAvailabilityWithdrawal } from '#server/utils/routingPolicyAvailability';
import type { RoutingPolicyBackups } from '#server/utils/routingPolicyBackups';
import type { RoutingExecutor } from '#server/utils/routingExecutor';
import {
  buildRoutingGuard,
  type RoutingGuard,
  type RoutingGuardScope,
} from '#server/utils/routingGuard';
import type { RoutingPolicyFirewall } from '#server/utils/routingPolicyFirewall';
import { RoutingPolicyJournalError } from '#server/utils/routingPolicyJournal';
import { renderRoutingPolicyLinux } from '#server/utils/routingPolicyLinux';
import { buildRoutingPolicyTransition } from '#server/utils/routingPolicyTransition';
import { RoutingKernelNamespaceSchema } from '#server/utils/routingPolicyKernelContext';
import type { PendingPolicyTransition } from '#shared/types/routingPolicy';

type Dependencies = {
  journal: RoutingPolicyRuntimeService;
  backups: RoutingPolicyBackups;
  executor: RoutingExecutor;
  guard: RoutingGuard;
  firewall: RoutingPolicyFirewall;
  devices: ManagedInterfaceDevices;
  hooks: ManagedServerHookEffects;
  configDirectory: string;
  protectedPaths: readonly RoutingGuardScope[];
};

/** Cold-start proof is stricter than same-namespace owned-generation recovery. */
export async function verifyColdRoutingNamespace(
  deps: Pick<Dependencies, 'executor' | 'firewall' | 'devices'>,
  interfaceIds: readonly string[]
) {
  for (const id of new Set(interfaceIds))
    if (await deps.devices.observe(id))
      throw new RoutingPolicyJournalError('cold_namespace_device_present');
  const observed = await deps.executor.observe();
  if (
    !preflightRoutingOwnership(observed).ok ||
    observed.chains.length ||
    observed.routes.some(isOwnedRoutingRoute) ||
    observed.policyRules.some(isOwnedRoutingRule) ||
    observed.markUses.some((mark) => mark.owner === 'wg-easy') ||
    observed.ownedParentJumps?.length ||
    observed.ownedChainRules?.length
  )
    throw new RoutingPolicyJournalError('cold_namespace_routing_present');
  await deps.firewall.verifyAbsent();
}

/**
 * Called by the existing coordinator before replaying Pending in a new network
 * namespace. No old hooks or devices are restored. Exactly one Pending survives.
 */
export async function rebasePendingRoutingNamespace(
  deps: Dependencies,
  namespaceId: string
): Promise<PendingPolicyTransition> {
  if (!RoutingKernelNamespaceSchema.safeParse(namespaceId).success)
    throw new RoutingPolicyJournalError('namespace_evidence_required');
  const state = await deps.journal.get(),
    pending = state.pending,
    previous = state.applied;
  if (state.version !== 2 || !previous?.plan.namespaceId || !pending)
    throw new RoutingPolicyJournalError('namespace_rebase_unavailable');
  if (
    pending.withdrawal?.resetNamespace &&
    pending.plan.namespaceId === namespaceId
  )
    return pending;
  if (previous.plan.namespaceId === namespaceId)
    throw new RoutingPolicyJournalError('namespace_reset_mismatch');
  const interfaces = [
    ...new Set(
      [...previous.plan.interfaces, ...pending.plan.interfaces].map(
        (i) => i.interfaceId
      )
    ),
  ].sort();
  await verifyColdRoutingNamespace(deps, interfaces);
  const oldGuard = buildRoutingGuard(pending.guardScopes, {
    protectedPaths: deps.protectedPaths,
  });
  // Before the CAS only this old record authorizes repair, including a partial
  // family install. No routes, filter chains or admitted hook effects are made.
  await deps.guard.ensure(oldGuard);
  await deps.backups.verifyKnownCurrentConfigurations(
    pending.backupBasenames[0]!
  );
  await deps.backups.restore(pending.backupBasenames[0]!, async (id, file) => {
    await deps.guard.verify(oldGuard);
    await deps.devices.validate(id, await fs.readFile(file, 'utf8'));
  });
  await deps.guard.verify(oldGuard);
  const unavailableInterfaceIds = previous.plan.interfaces
      .map((i) => i.interfaceId)
      .sort(),
    target = deriveRoutingAvailabilityWithdrawal(
      previous,
      new Set(unavailableInterfaceIds),
      { namespaceId, resetHooks: true }
    ),
    saved = await deps.backups.readPrivateConfigurations(
      pending.backupBasenames[0]!
    );
  // A candidate may introduce an interface absent from Applied; its old bytes
  // are restored above, but it cannot become part of the historical generation.
  if (
    unavailableInterfaceIds.some(
      (id) => !saved.some((entry) => entry.interfaceId === id)
    )
  )
    throw new RoutingPolicyJournalError('namespace_rebase_backup_incomplete');
  const candidates = new Map(
    unavailableInterfaceIds.map((id) => [
      id,
      saved.find((e) => e.interfaceId === id)!.config,
    ])
  );
  const transition = await ManagedInterfaceTransition.prepare(
    deps,
    target.plan,
    target.plan,
    candidates
  );
  const guard = buildRoutingPolicyTransition(previous.plan, target.plan, {
    protectedPaths: deps.protectedPaths,
  });
  await deps.executor.prepare(renderRoutingPolicyLinux(target.plan), {
    knownPlans: [],
  });
  await deps.guard.prepare(guard, oldGuard);
  const reference = await deps.backups.create(unavailableInterfaceIds, {
    candidateConfigurations: transition.candidateConfigurations,
    expectedPreviousConfigurations: transition.previousConfigurations,
    lifecycleIntent: transition.intent,
  });
  const next: PendingPolicyTransition = {
    ...target,
    withdrawal: { unavailableInterfaceIds, resetNamespace: true },
    supersededGuardScopes: pending.guardScopes,
    stage: 'prepared',
    guardScopes: guard.scopes,
    backupBasenames: [reference],
    errorCode: null,
  };
  try {
    await deps.journal.rebasePendingToWithdrawal(pending, next);
  } catch (error) {
    const latest = await deps.journal.get();
    if (!latest.pending?.backupBasenames.includes(reference))
      await deps.backups.remove(reference).catch(() => {});
    throw error;
  }
  // The old private file is now only an orphan; a later verified publication
  // may remove it. A crash here is replayed using next's exact guard manifests.
  return next;
}

/** Only an empty, different namespace permits abandoning an interrupted v1 bridge. */
export async function cancelPendingBootstrapInNewNamespace(
  deps: Dependencies,
  namespaceId: string,
  publishUnavailable: (
    tx: PolicyPublicationTransaction,
    interfaceIds: readonly string[]
  ) => Promise<void>
) {
  const state = await deps.journal.get(),
    pending = state.pending;
  if (
    state.version !== 1 ||
    state.applied ||
    !pending?.bootstrap ||
    !pending.plan.namespaceId ||
    namespaceId === pending.plan.namespaceId ||
    !RoutingKernelNamespaceSchema.safeParse(namespaceId).success
  )
    throw new RoutingPolicyJournalError('bootstrap_cancellation_unavailable');
  const ids = pending.plan.interfaces.map((i) => i.interfaceId),
    guard = buildRoutingGuard(pending.guardScopes, {
      protectedPaths: deps.protectedPaths,
    });
  await verifyColdRoutingNamespace(deps, ids);
  await deps.guard.ensure(guard);
  try {
    await deps.backups.verifyKnownCurrentConfigurations(
      pending.backupBasenames[0]!
    );
    await deps.backups.restore(
      pending.backupBasenames[0]!,
      async (id, file) => {
        await deps.guard.verify(guard);
        await deps.devices.validate(id, await fs.readFile(file, 'utf8'));
      }
    );
    await deps.journal.cancelLostBootstrap(pending, namespaceId, async (tx) => {
      await deps.guard.remove(guard);
      await deps.guard.verify(null, { families: [4, 6] });
      await verifyColdRoutingNamespace(deps, ids);
      await publishUnavailable(tx, ids);
    });
  } catch (error) {
    await deps.guard.ensure(guard).catch(() => {});
    throw error;
  }
  // Only an unreferenced private orphan can remain after a successful commit.
  await deps.backups.remove(pending.backupBasenames[0]!).catch(() => {});
}
