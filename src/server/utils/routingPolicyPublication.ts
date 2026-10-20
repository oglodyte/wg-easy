import { eq, inArray, lte } from 'drizzle-orm';

import { interfaceRuntimeState } from '#db/repositories/runtime/schema';
import {
  routingGroupRuntimeState,
  routingSlotTombstone,
} from '#db/repositories/routingGroup/schema';
import type { PrivateDesiredRoutingGeneration } from '#db/repositories/runtime/generationSnapshot';
import type { PolicyPublicationTransaction } from '#db/repositories/runtime/policyService';
import type { RoutingPolicyJournal } from '#shared/types/routingPolicy';

/** An empty replacement namespace proves unavailability, never an active group. */
export async function publishRoutingNamespaceUnavailable(
  tx: PolicyPublicationTransaction,
  interfaceIds: readonly string[]
) {
  if (interfaceIds.length)
    await tx
      .update(interfaceRuntimeState)
      .set({
        observedUp: false,
        status: 'pending',
        lastError: 'bootstrap_namespace_reset',
      })
      .where(inArray(interfaceRuntimeState.interfaceId, [...interfaceIds]))
      .execute();
  for (const group of await tx.query.routingGroup
    .findMany({ columns: { id: true, enabled: true } })
    .execute())
    await tx
      .update(routingGroupRuntimeState)
      .set({
        selectedExitClientId: null,
        appliedExitClientId: null,
        selectedSince: null,
        appliedSince: null,
        status: group.enabled ? 'degraded' : 'disabled',
        reason: group.enabled ? 'bootstrap_namespace_reset' : null,
      })
      .where(eq(routingGroupRuntimeState.groupId, group.id))
      .execute();
}

/** Caller holds the journal's writer lock across final whole-kernel verification. */
export async function publishRoutingPolicyEvidence(
  tx: PolicyPublicationTransaction,
  record: RoutingPolicyJournal,
  {
    generation,
    failures = new Map(),
    configurationApplied = false,
  }: {
    generation?: PrivateDesiredRoutingGeneration;
    failures?: ReadonlyMap<string, string>;
    configurationApplied?: boolean;
  } = {}
) {
  const now = new Date().toISOString(),
    interfaces = await tx.query.wgInterface.findMany().execute(),
    states = await tx.query.interfaceRuntimeState.findMany().execute(),
    captured = new Map(
      generation?.interfaceRuntime.map((i) => [i.interfaceId, i]) ?? []
    ),
    planned = new Map(record.plan.interfaces.map((i) => [i.interfaceId, i]));
  for (const iface of interfaces) {
    const old = states.find((i) => i.interfaceId === iface.name);
    if (!old) throw new Error('Interface runtime evidence missing');
    const up = planned.get(iface.name)?.observedUp ?? false,
      desiredUp = iface.enabled && !iface.pendingDelete,
      verified =
        configurationApplied &&
        generation &&
        !failures.has(iface.name) &&
        up === desiredUp &&
        captured.get(iface.name)?.desiredRevision === old.desiredRevision;
    await tx
      .update(interfaceRuntimeState)
      .set({
        observedUp: up,
        ...(up !== old.observedUp
          ? up
            ? { lastStartedAt: now }
            : { lastStoppedAt: now }
          : {}),
        ...(verified
          ? {
              appliedRevision: old.desiredRevision,
              restartRequired: false,
              status: up ? ('up' as const) : ('disabled' as const),
              lastError: null,
              lastAppliedAt: now,
            }
          : up === old.observedUp &&
              old.status === (up ? 'up' : 'disabled') &&
              !failures.has(iface.name)
            ? {}
            : {
                status: 'degraded' as const,
                lastError:
                  failures.get(iface.name) ??
                  'interface_configuration_unapplied',
              }),
      })
      .where(eq(interfaceRuntimeState.interfaceId, iface.name))
      .execute();
  }
  const [groups, runtimes, clients] = await Promise.all([
      tx.query.routingGroup.findMany({ columns: { id: true } }).execute(),
      tx.query.routingGroupRuntimeState.findMany().execute(),
      tx.query.client.findMany({ columns: { id: true } }).execute(),
    ]),
    liveGroups = new Set(groups.map((g) => g.id)),
    liveClients = new Set(clients.map((c) => c.id));
  for (const group of record.plan.groups) {
    if (!liveGroups.has(group.id)) continue;
    const old = runtimes.find((r) => r.groupId === group.id),
      historicalMissing =
        group.selectedExitClientId !== null &&
        !liveClients.has(group.selectedExitClientId),
      selected = historicalMissing ? null : group.selectedExitClientId,
      changed = selected !== (old?.selectedExitClientId ?? null),
      active = group.enabled && selected !== null,
      state = {
        selectedExitClientId: selected,
        appliedExitClientId: selected,
        evaluatedRevision: record.revision,
        appliedRevision: record.revision,
        selectedSince: active
          ? changed
            ? now
            : (old?.selectedSince ?? now)
          : null,
        appliedSince: active
          ? old?.appliedExitClientId === selected
            ? (old.appliedSince ?? now)
            : now
          : null,
        lastEvaluatedAt: now,
        lastFailoverAt: changed ? now : (old?.lastFailoverAt ?? null),
        status: historicalMissing
          ? ('degraded' as const)
          : !group.enabled
            ? ('disabled' as const)
            : active
              ? ('active' as const)
              : group.allExitsDownPolicy === 'block'
                ? ('blocked' as const)
                : ('host_fallback' as const),
        reason: historicalMissing
          ? 'historical_exit_profile_unavailable'
          : null,
      };
    await tx
      .insert(routingGroupRuntimeState)
      .values({ groupId: group.id, ...state })
      .onConflictDoUpdate({
        target: routingGroupRuntimeState.groupId,
        set: state,
      })
      .execute();
  }
  if (configurationApplied)
    await tx
      .delete(routingSlotTombstone)
      .where(lte(routingSlotTombstone.releasedAfterRevision, record.revision))
      .execute();
}
