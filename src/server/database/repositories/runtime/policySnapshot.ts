import type { DBType } from '#db/sqlite';
import type { PolicySnapshot } from '#shared/types/routingPolicy';

/** Call inside the caller's transaction so validation sees the final generation. */
export async function readProposedRoutingState(db: Pick<DBType, 'query'>) {
  const [general, interfaces, clients, groups, members, exits] =
    await Promise.all([
      db.query.general
        .findFirst({ columns: { routingPolicyVersion: true } })
        .execute(),
      db.query.wgInterface
        .findMany({ columns: { name: true, ipv4Cidr: true, publicKey: true } })
        .execute(),
      db.query.client
        .findMany({
          columns: {
            id: true,
            name: true,
            interfaceId: true,
            publicKey: true,
            ipv4Address: true,
            ipv6Address: true,
            enabled: true,
            serverAllowedIps: true,
          },
        })
        .execute(),
      db.query.routingGroup.findMany().execute(),
      db.query.routingGroupMember.findMany().execute(),
      db.query.routingGroupExit.findMany().execute(),
    ]);
  if (!general) throw new Error('General Config not found');
  const memberships = new Map<number, number[]>(),
    candidates = new Map<
      number,
      PolicySnapshot['groups'][number]['exits'][number][]
    >();
  for (const member of members) {
    const list = memberships.get(member.groupId) ?? [];
    list.push(member.clientId);
    memberships.set(member.groupId, list);
  }
  for (const exit of exits) {
    const list = candidates.get(exit.groupId) ?? [];
    list.push({
      clientId: exit.clientId,
      enabled: exit.enabled,
      priority: exit.priority,
    });
    candidates.set(exit.groupId, list);
  }
  const snapshot: PolicySnapshot = {
    interfaces: interfaces.map((i) => ({
      interfaceId: i.name,
      ipv4Cidr: i.ipv4Cidr,
      publicKey: i.publicKey,
    })),
    clients,
    groups: groups.map((g) => ({
      id: g.id,
      name: g.name,
      enabled: g.enabled,
      routingSlot: g.routingSlot,
      natEnabled: g.natEnabled,
      allExitsDownPolicy: g.allExitsDownPolicy,
      routedIpv4Prefixes: g.routedIpv4Prefixes,
      excludedIpv4Prefixes: g.excludedIpv4Prefixes,
      memberClientIds: (memberships.get(g.id) ?? []).sort((a, b) => a - b),
      exits: (candidates.get(g.id) ?? []).sort(
        (a, b) => a.priority - b.priority || a.clientId - b.clientId
      ),
    })),
  };
  return { version: general.routingPolicyVersion, snapshot };
}
