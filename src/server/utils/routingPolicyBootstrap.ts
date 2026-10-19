import { normalizeCidr } from 'cidr-tools';

import { buildRoutingPlan } from '#server/utils/routing';
import {
  parsePolicyBootstrapBaseline,
  RoutingPolicyJournalError,
} from '#server/utils/routingPolicyJournal';
import type {
  PolicyBootstrapBaseline,
  PolicySnapshot,
  RoutingPolicyJournal,
} from '#shared/types/routingPolicy';

/** Build only from the same freshly verified v1 generation as the target. */
export function buildPolicyBootstrapBaseline(
  snapshot: PolicySnapshot,
  target: RoutingPolicyJournal
): PolicyBootstrapBaseline {
  if (snapshot.groups.some((g) => g.excludedIpv4Prefixes?.length))
    throw new RoutingPolicyJournalError('invalid_bootstrap_baseline');
  const selections = new Map(
    target.plan.groups.map((g) => [g.id, g.selectedExitClientId])
  );
  const baseline: PolicyBootstrapBaseline = {
    interfaces: structuredClone(target.plan.interfaces),
    clients: [...snapshot.clients]
      .sort((a, b) => a.id - b.id)
      .map((c) => ({
        id: c.id,
        interfaceId: c.interfaceId,
        ipv4Address: c.ipv4Address,
        ipv6Address: c.ipv6Address ?? null,
        enabled: c.enabled,
        serverAllowedIps: c.serverAllowedIps.map((p) => normalizeCidr(p)),
      })),
    groups: [...snapshot.groups]
      .sort((a, b) => a.id - b.id)
      .map((g) => ({
        id: g.id,
        routingSlot: g.routingSlot,
        enabled: g.enabled,
        natEnabled: g.natEnabled,
        allExitsDownPolicy: g.allExitsDownPolicy,
        routedIpv4Prefixes: g.routedIpv4Prefixes.map((p) => normalizeCidr(p)),
        memberClientIds: [...g.memberClientIds].sort((a, b) => a - b),
        selectedExitClientId: selections.get(g.id) ?? null,
      })),
    peers: [],
  };
  const legacy = buildRoutingPlan(baseline);
  const additions = new Map(
    legacy.peerAllowedIps.map((p) => [p.clientId, p.prefixes])
  );
  const clients = new Map(baseline.clients.map((c) => [c.id, c]));
  baseline.peers = target.plan.peers.map((peer) => {
    const client = clients.get(peer.clientId);
    if (!client)
      throw new RoutingPolicyJournalError('invalid_bootstrap_baseline');
    return {
      ...peer,
      prefixes: [
        ...new Set(
          [
            `${client.ipv4Address}/32`,
            ...(target.plan.clientFirewall.enableIpv6 && client.ipv6Address
              ? [`${client.ipv6Address}/128`]
              : []),
            ...client.serverAllowedIps,
            ...(additions.get(client.id) ?? []),
          ].map((p) => normalizeCidr(p))
        ),
      ].sort(),
    };
  });
  return parsePolicyBootstrapBaseline(baseline, target);
}
