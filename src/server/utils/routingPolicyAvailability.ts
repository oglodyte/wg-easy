import {
  parseRoutingPolicyJournal,
  RoutingPolicyJournalError,
} from '#server/utils/routingPolicyJournal';
import { RoutingKernelNamespaceSchema } from '#server/utils/routingPolicyKernelContext';
import { routingPolicyRuntimeFingerprint } from '#server/utils/routingPolicyRuntime';
import type {
  PendingPolicyTransition,
  RoutingPolicyJournal,
} from '#shared/types/routingPolicy';

/** The descriptor authorizes only the exact safety withdrawal of Applied. */
export function assertRoutingAvailabilityWithdrawal(
  previous: RoutingPolicyJournal | null,
  pending: PendingPolicyTransition
) {
  if (!previous || !pending.withdrawal || !pending.plan.namespaceId)
    throw new RoutingPolicyJournalError('invalid_availability_withdrawal');
  const derived = deriveRoutingAvailabilityWithdrawal(
    previous,
    new Set(pending.withdrawal.unavailableInterfaceIds),
    {
      namespaceId: pending.plan.namespaceId,
      resetHooks: pending.withdrawal.resetNamespace,
    }
  );
  if (
    derived.revision !== pending.revision ||
    derived.fingerprint !== pending.fingerprint
  )
    throw new RoutingPolicyJournalError('invalid_availability_withdrawal');
}

/**
 * Withdraw availability from the last verified policy without using newer
 * desired rows or selecting a new gateway. Completion still requires Linux
 * verification under a durable guard; this pure result is not Applied.
 */
export function deriveRoutingAvailabilityWithdrawal(
  value: RoutingPolicyJournal,
  unavailableInterfaceIds: ReadonlySet<string>,
  {
    namespaceId,
    resetHooks = false,
  }: { namespaceId: string; resetHooks?: boolean }
): RoutingPolicyJournal {
  const previous = parseRoutingPolicyJournal(value);
  if (
    !previous.plan.namespaceId ||
    !RoutingKernelNamespaceSchema.safeParse(namespaceId).success
  )
    throw new RoutingPolicyJournalError('namespace_evidence_required');
  if (
    resetHooks
      ? namespaceId === previous.plan.namespaceId
      : namespaceId !== previous.plan.namespaceId
  )
    throw new RoutingPolicyJournalError('namespace_reset_mismatch');
  const known = new Map(
    previous.plan.interfaces.map((i) => [i.interfaceId, i])
  );
  if (
    unavailableInterfaceIds.size === 0 ||
    [...unavailableInterfaceIds].some((id) => !known.has(id)) ||
    (resetHooks && unavailableInterfaceIds.size !== known.size)
  )
    throw new RoutingPolicyJournalError('invalid_availability_withdrawal');
  if (
    !resetHooks &&
    [...unavailableInterfaceIds].some((id) => !known.get(id)!.observedUp)
  )
    throw new RoutingPolicyJournalError('invalid_availability_withdrawal');
  const plan = structuredClone(previous.plan);
  plan.namespaceId = namespaceId;
  for (const iface of plan.interfaces) {
    iface.hooksApplied = resetHooks
      ? false
      : (iface.hooksApplied ?? iface.observedUp);
    if (unavailableInterfaceIds.has(iface.interfaceId))
      iface.observedUp = false;
  }
  const up = new Set(
    plan.interfaces.filter((i) => i.observedUp).map((i) => i.interfaceId)
  );
  plan.peers = plan.peers.filter((p) => up.has(p.interfaceId));
  plan.siteRoutes = plan.siteRoutes.filter((p) => up.has(p.interfaceId));
  plan.clientFirewall.interfaces = plan.clientFirewall.interfaces.filter((i) =>
    up.has(i.interfaceId)
  );
  plan.clientFirewall.entries = plan.clientFirewall.entries.filter((e) =>
    up.has(e.interfaceId)
  );
  for (const group of plan.groups)
    if (group.exitInterfaceId && !up.has(group.exitInterfaceId)) {
      group.selectedExitClientId = null;
      group.exitInterfaceId = null;
      group.serverIpv4Address = null;
    }
  const groups = new Map(plan.groups.map((g) => [g.id, g]));
  for (const program of plan.programs)
    for (const branch of program.branches) {
      const group = groups.get(branch.groupId)!;
      branch.action =
        group.selectedExitClientId === null ? group.allExitsDownPolicy : 'exit';
    }
  return parseRoutingPolicyJournal({
    revision: previous.revision,
    plan,
    fingerprint: routingPolicyRuntimeFingerprint(plan),
  });
}
