import { createHash } from 'node:crypto';

import { normalizeCidr, parseCidr } from 'cidr-tools';
import { stringifyIp } from 'ip-bigint';

import {
  compileRoutingPolicy,
  policyPeerId,
  PolicyValidationError,
} from '#server/utils/routingPolicy';
import { RoutingKernelNamespaceSchema } from '#server/utils/routingPolicyKernelContext';
import type {
  AppliedRoutingPolicyPlan,
  PolicyClientFirewall,
  PolicySnapshot,
} from '#shared/types/routingPolicy';

/** Object member order is not part of the persisted runtime fingerprint. */
export function routingPolicyRuntimeFingerprint(
  plan: AppliedRoutingPolicyPlan
) {
  const canonical = (value: unknown): unknown => {
    if (Array.isArray(value)) return value.map(canonical);
    if (value && typeof value === 'object')
      return Object.fromEntries(
        Object.keys(value)
          .sort()
          .map((key) => [
            key,
            canonical((value as Record<string, unknown>)[key]),
          ])
      );
    return value;
  };
  return createHash('sha256')
    .update(JSON.stringify(canonical(plan)))
    .digest('hex');
}

/** Normalize a complete desired snapshot; health selects actions, never rank. */
export function specializeRoutingPolicy(
  snapshot: PolicySnapshot,
  {
    selectedExitClientIds,
    enabledInterfaceIds,
    upInterfaceIds,
    enableIpv6,
    clientFirewall,
    namespaceId,
    hooksAppliedInterfaceIds,
  }: {
    selectedExitClientIds: ReadonlyMap<number, number | null>;
    enabledInterfaceIds: ReadonlySet<string>;
    upInterfaceIds: ReadonlySet<string>;
    enableIpv6: boolean;
    clientFirewall: PolicyClientFirewall;
    namespaceId?: string;
    hooksAppliedInterfaceIds?: ReadonlySet<string>;
  }
) {
  const compiled = compileRoutingPolicy(snapshot);
  if (clientFirewall.enableIpv6 !== enableIpv6)
    throw new PolicyValidationError('firewall_ipv6_mismatch');
  const clients = new Map(snapshot.clients.map((c) => [c.id, c]));
  const interfaces = new Map(
    snapshot.interfaces.map((i) => [i.interfaceId, i])
  );
  const compiledGroups = new Map(compiled.groups.map((g) => [g.id, g]));
  const knownGroups = new Set(snapshot.groups.map((g) => g.id));
  for (const [groupId, selected] of selectedExitClientIds) {
    if (
      !knownGroups.has(groupId) ||
      (selected !== null && !compiledGroups.has(groupId))
    )
      throw new PolicyValidationError('selection_group_unavailable', {
        groupIds: [groupId],
      });
  }
  for (const id of enabledInterfaceIds)
    if (!interfaces.has(id))
      throw new PolicyValidationError('interface_not_found');
  for (const id of upInterfaceIds)
    if (!enabledInterfaceIds.has(id))
      throw new PolicyValidationError('interface_availability_invalid', {
        interfaceId: interfaces.has(id) ? id : undefined,
      });
  if (
    namespaceId !== undefined &&
    !RoutingKernelNamespaceSchema.safeParse(namespaceId).success
  )
    throw new PolicyValidationError('namespace_invalid');
  if (
    hooksAppliedInterfaceIds &&
    [...hooksAppliedInterfaceIds].some((id) => !enabledInterfaceIds.has(id))
  )
    throw new PolicyValidationError('hook_availability_invalid');
  if (
    hooksAppliedInterfaceIds &&
    [...upInterfaceIds].some((id) => !hooksAppliedInterfaceIds.has(id))
  )
    throw new PolicyValidationError('hook_availability_invalid');
  const peers = compiled.basePeers
    .filter((p) => upInterfaceIds.has(p.interfaceId))
    .map((p) => ({
      ...p,
      prefixes: [
        ...new Set([
          normalizeCidr(`${clients.get(p.clientId)!.ipv4Address}/32`),
          ...(enableIpv6 && clients.get(p.clientId)!.ipv6Address
            ? [normalizeCidr(`${clients.get(p.clientId)!.ipv6Address}/128`)]
            : []),
          ...clients
            .get(p.clientId)!
            .serverAllowedIps.map((value) => normalizeCidr(value)),
        ]),
      ].sort(),
    }));
  const peerById = new Map(peers.map((p) => [p.clientId, p]));
  const groups: AppliedRoutingPolicyPlan['groups'] = [...snapshot.groups]
    .sort((a, b) => a.id - b.id)
    .map((g) => {
      const active = compiledGroups.get(g.id);
      const selectedId = active
        ? (selectedExitClientIds.get(g.id) ?? null)
        : null;
      const exit = selectedId === null ? undefined : clients.get(selectedId);
      if (
        selectedId !== null &&
        (!exit?.enabled ||
          !g.exits.some((e) => e.clientId === selectedId && e.enabled) ||
          !enabledInterfaceIds.has(exit.interfaceId) ||
          !upInterfaceIds.has(exit.interfaceId))
      )
        throw new PolicyValidationError('selected_exit_unavailable', {
          groupIds: [g.id],
          clientIds: [selectedId],
        });
      const prefixes = active?.effectivePrefixes ?? [];
      if (exit) {
        const peer = peerById.get(exit.id);
        if (!peer)
          throw new PolicyValidationError('selected_peer_missing', {
            clientIds: [exit.id],
          });
        peer.prefixes = [...new Set([...peer.prefixes, ...prefixes])].sort();
      }
      return {
        id: g.id,
        routingSlot: g.routingSlot,
        natEnabled: g.natEnabled,
        enabled: g.enabled,
        allExitsDownPolicy: g.allExitsDownPolicy,
        selectedExitClientId: exit?.id ?? null,
        exitInterfaceId: exit?.interfaceId ?? null,
        serverIpv4Address: exit
          ? stringifyIp({
              number:
                parseCidr(interfaces.get(exit.interfaceId)!.ipv4Cidr).start +
                1n,
              version: 4,
            })
          : null,
        effectivePrefixes: [...prefixes],
      };
    });
  const groupById = new Map(groups.map((g) => [g.id, g]));
  const plan: AppliedRoutingPolicyPlan = {
    version: 2,
    ...(namespaceId !== undefined ? { namespaceId } : {}),
    clientFirewall: structuredClone(clientFirewall),
    interfaces: [...snapshot.interfaces]
      .sort((a, b) => a.interfaceId.localeCompare(b.interfaceId))
      .map((i) => ({
        interfaceId: i.interfaceId,
        ipv4Cidr: normalizeCidr(i.ipv4Cidr),
        enabled: enabledInterfaceIds.has(i.interfaceId),
        observedUp: upInterfaceIds.has(i.interfaceId),
        ...(namespaceId !== undefined || hooksAppliedInterfaceIds
          ? {
              hooksApplied:
                hooksAppliedInterfaceIds?.has(i.interfaceId) ??
                upInterfaceIds.has(i.interfaceId),
            }
          : {}),
      })),
    siteRoutes: [...snapshot.clients]
      .filter(
        (c) =>
          c.enabled &&
          enabledInterfaceIds.has(c.interfaceId) &&
          upInterfaceIds.has(c.interfaceId) &&
          c.serverAllowedIps.length > 0
      )
      .sort((a, b) => a.id - b.id)
      .map((c) => ({
        interfaceId: c.interfaceId,
        prefixes: [
          ...new Set(c.serverAllowedIps.map((p) => normalizeCidr(p))),
        ].sort(),
      })),
    bypassPrefixes: [...compiled.bypassPrefixes],
    programs: compiled.programs.map((p) => ({
      sources: p.sources.map((source) => ({ ...source })),
      branches: p.branches.map((branch) => ({
        ...branch,
        action:
          groupById.get(branch.groupId)!.selectedExitClientId !== null
            ? ('exit' as const)
            : compiledGroups.get(branch.groupId)!.allExitsDownPolicy,
      })),
    })),
    groups,
    peers,
  };
  return {
    compiled,
    plan,
    fingerprint: routingPolicyRuntimeFingerprint(plan),
  };
}

/** Exact complete maps catch stale peers and stale more-specific ownership. */
export function verifyRoutingPolicyPeerMap(
  plan: AppliedRoutingPolicyPlan,
  observed: readonly {
    interfaceId: string;
    publicKey: string;
    allowedIps: readonly string[];
  }[]
) {
  const managed = new Set(plan.interfaces.map((i) => i.interfaceId));
  const actual = new Map<string, string[]>();
  for (const peer of observed) {
    if (!managed.has(peer.interfaceId)) continue;
    const id = policyPeerId(peer);
    if (actual.has(id))
      throw new PolicyValidationError('duplicate_observed_peer', {
        interfaceId: peer.interfaceId,
      });
    try {
      actual.set(
        id,
        [...new Set(peer.allowedIps.map((p) => normalizeCidr(p)))].sort()
      );
    } catch {
      throw new PolicyValidationError('invalid_observed_peer_map', {
        interfaceId: peer.interfaceId,
      });
    }
  }
  const expected = new Map(plan.peers.map((p) => [p.peerId, p]));
  for (const [peerId, prefixes] of actual) {
    const peer = expected.get(peerId);
    if (!peer || JSON.stringify(peer.prefixes) !== JSON.stringify(prefixes))
      throw new PolicyValidationError(
        'peer_map_mismatch',
        peer
          ? { interfaceId: peer.interfaceId, clientIds: [peer.clientId] }
          : {}
      );
  }
  for (const peer of plan.peers)
    if (!actual.has(peer.peerId))
      throw new PolicyValidationError('peer_missing', {
        interfaceId: peer.interfaceId,
        clientIds: [peer.clientId],
      });
}
