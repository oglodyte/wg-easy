import { createHash } from 'node:crypto';

import { normalizeCidr, parseCidr } from 'cidr-tools';

import type {
  CompiledPolicy,
  PolicyCell,
  PolicyClient,
  PolicyCounts,
  PolicyGroup,
  PolicySnapshot,
} from '#shared/types/routingPolicy';
import { InterfaceNameSchema, RoutingSlotSchema } from '#shared/utils/schemas';

export const POLICY_LIMITS = {
  prefixes: 64,
  exits: 16,
  members: 1024,
  groups: 999,
  memberships: 16,
  intervals: 4096,
  groupDispatch: 4096,
  dispatch: 20000,
  classifierRules: 44096,
  peerPrefixes: 4096,
  interfacePrefixes: 8192,
  globalPrefixes: 16384,
  claims: 65536,
  winnerWork: 1000000,
  comparisons: 1000000,
  guardRules: 44096,
} as const;

type Range = { start: number; end: number };
type Prefix = Range & { cidr: string; rank: number };
export class PolicyValidationError extends Error {
  constructor(
    readonly code: string,
    readonly detail: {
      groupIds?: number[];
      clientIds?: number[];
      interfaceId?: string;
      destination?: string;
      budget?: string;
      limit?: number;
      actual?: number;
    } = {}
  ) {
    // Deliberately exclude input strings/keys from errors and logs.
    super(`Routing policy: ${code}`);
    this.name = 'PolicyValidationError';
  }
}
function limit(
  budget: string,
  actual: number,
  maximum: number,
  groupIds?: number[]
) {
  if (actual > maximum)
    throw new PolicyValidationError('budget_exceeded', {
      budget,
      actual,
      limit: maximum,
      groupIds,
    });
}
function prefix(value: string): Prefix {
  try {
    const p = parseCidr(value);
    if (p.version !== 4 || !p.prefixPresent) throw new Error();
    return {
      start: Number(p.start),
      end: Number(p.end) + 1,
      cidr: normalizeCidr(value),
      rank: Number(p.prefix),
    };
  } catch {
    throw new PolicyValidationError('invalid_ipv4_prefix');
  }
}
function address(value: number) {
  return [24, 16, 8, 0]
    .map((shift) => Math.floor(value / 2 ** shift) % 256)
    .join('.');
}
function contains(r: Range, value: number) {
  return r.start <= value && value < r.end;
}
function overlaps(a: Range, b: Range) {
  return a.start < b.end && b.start < a.end;
}
function union(ranges: readonly Range[]): Range[] {
  const result: Range[] = [];
  for (const r of [...ranges].sort(
    (a, b) => a.start - b.start || a.end - b.end
  )) {
    const last = result.at(-1);
    if (last && r.start <= last.end) last.end = Math.max(last.end, r.end);
    else result.push({ start: r.start, end: r.end });
  }
  return result;
}
/** Summarize unsigned half-open intervals without enumerating addresses. */
export function policyRangeCidrs(ranges: readonly Range[]) {
  const result: string[] = [];
  for (const r of union(ranges)) {
    let start = r.start;
    while (start < r.end) {
      let bits = 0;
      while (
        bits < 32 &&
        start % 2 ** (bits + 1) === 0 &&
        start + 2 ** (bits + 1) <= r.end
      )
        bits++;
      result.push(`${address(start)}/${32 - bits}`);
      start += 2 ** bits;
    }
  }
  return result;
}
export function policyPeerId(
  client: Pick<PolicyClient, 'interfaceId' | 'publicKey'>
) {
  return createHash('sha256')
    .update(JSON.stringify([client.interfaceId, client.publicKey]))
    .digest('hex');
}
/** A pair is exclusive only when enabling both would violate accepted identity constraints. */
export function policyCandidatesCanCoexist(a: PolicyClient, b: PolicyClient) {
  return (
    a.id === b.id ||
    !(
      a.ipv4Address === b.ipv4Address ||
      (a.ipv6Address != null && a.ipv6Address === b.ipv6Address) ||
      (a.interfaceId === b.interfaceId && a.publicKey === b.publicKey)
    )
  );
}
function validateIdentities(snapshot: PolicySnapshot) {
  const keyInterfaces = new Map<string, string>();
  const live = {
    ipv4: new Set<string>(),
    ipv6: new Set<string>(),
    peer: new Set<string>(),
  };
  const serverKeys = new Set(
    snapshot.interfaces.map((i) => i.publicKey).filter(Boolean)
  );
  for (const c of snapshot.clients) {
    if (
      serverKeys.has(c.publicKey) ||
      (keyInterfaces.has(c.publicKey) &&
        keyInterfaces.get(c.publicKey) !== c.interfaceId)
    )
      throw new PolicyValidationError('credential_conflict', {
        clientIds: [c.id],
        interfaceId: c.interfaceId,
      });
    keyInterfaces.set(c.publicKey, c.interfaceId);
    if (!c.enabled) continue;
    const peer = policyPeerId(c);
    if (
      live.ipv4.has(c.ipv4Address) ||
      (c.ipv6Address && live.ipv6.has(c.ipv6Address)) ||
      live.peer.has(peer)
    )
      throw new PolicyValidationError('enabled_identity_conflict', {
        clientIds: [c.id],
        interfaceId: c.interfaceId,
      });
    live.ipv4.add(c.ipv4Address);
    if (c.ipv6Address) live.ipv6.add(c.ipv6Address);
    live.peer.add(peer);
  }
}

/** Inactive Phase 1 compiler. No DB, health, subprocess, or Linux access. */
export function compileRoutingPolicy(snapshot: PolicySnapshot): CompiledPolicy {
  limit('groups', snapshot.groups.length, POLICY_LIMITS.groups);
  validateIdentities(snapshot);
  const clients = new Map(snapshot.clients.map((c) => [c.id, c]));
  const interfaces = new Set(
    snapshot.interfaces.map((i) => InterfaceNameSchema.parse(i.interfaceId))
  );
  const bypass = union(snapshot.interfaces.map((i) => prefix(i.ipv4Cidr)));
  const slots = new Set<number>();
  const ids = new Set<number>();
  const memberships = new Map<number, number[]>();
  const groups = [...snapshot.groups]
    .sort((a, b) => a.id - b.id)
    .map((g) => {
      RoutingSlotSchema.parse(g.routingSlot);
      if (ids.has(g.id) || slots.has(g.routingSlot))
        throw new PolicyValidationError('duplicate_group_identity');
      ids.add(g.id);
      slots.add(g.routingSlot);
      limit(
        'included_prefixes',
        g.routedIpv4Prefixes.length,
        POLICY_LIMITS.prefixes,
        [g.id]
      );
      limit(
        'excluded_prefixes',
        g.excludedIpv4Prefixes?.length ?? 0,
        POLICY_LIMITS.prefixes,
        [g.id]
      );
      limit('exits', g.exits.length, POLICY_LIMITS.exits, [g.id]);
      limit('members', g.memberClientIds.length, POLICY_LIMITS.members, [g.id]);
      const exitIds = new Set<number>();
      const priorities = new Set<number>();
      for (const e of g.exits) {
        if (!clients.has(e.clientId))
          throw new PolicyValidationError('client_not_found', {
            clientIds: [e.clientId],
            groupIds: [g.id],
          });
        if (
          exitIds.has(e.clientId) ||
          priorities.has(e.priority) ||
          !Number.isSafeInteger(e.priority) ||
          e.priority < 0
        )
          throw new PolicyValidationError('invalid_exit_order', {
            groupIds: [g.id],
          });
        exitIds.add(e.clientId);
        priorities.add(e.priority);
      }
      for (const id of new Set(g.memberClientIds)) {
        if (!clients.has(id))
          throw new PolicyValidationError('client_not_found', {
            clientIds: [id],
            groupIds: [g.id],
          });
        if (exitIds.has(id))
          throw new PolicyValidationError('self_exit', {
            clientIds: [id],
            groupIds: [g.id],
          });
        const memberGroups = memberships.get(id) ?? [];
        memberGroups.push(g.id);
        limit(
          'memberships',
          memberGroups.length,
          POLICY_LIMITS.memberships,
          memberGroups
        );
        memberships.set(id, memberGroups);
      }
      if (
        g.enabled &&
        (!g.memberClientIds.length ||
          !g.exits.some((e) => e.enabled) ||
          !g.routedIpv4Prefixes.length)
      )
        throw new PolicyValidationError('enabled_group_incomplete', {
          groupIds: [g.id],
        });
      const included = [
        ...new Set(g.routedIpv4Prefixes.map((s) => prefix(s).cidr)),
      ]
        .map(prefix)
        .sort((a, b) => a.start - b.start || b.rank - a.rank);
      const excluded = union((g.excludedIpv4Prefixes ?? []).map(prefix));
      return { ...g, included, excluded };
    });
  for (const c of clients.values()) {
    if (!interfaces.has(c.interfaceId))
      throw new PolicyValidationError('interface_not_found', {
        clientIds: [c.id],
      });
    const host = prefix(`${c.ipv4Address}/32`);
    const iface = snapshot.interfaces.find(
      (i) => i.interfaceId === c.interfaceId
    )!;
    const network = prefix(iface.ipv4Cidr);
    if (
      !contains(network, host.start) ||
      host.start <= network.start + 1 ||
      host.end === network.end
    )
      throw new PolicyValidationError('reserved_client_address', {
        clientIds: [c.id],
        interfaceId: c.interfaceId,
      });
  }
  const active = groups.filter((g) => g.enabled);
  const counts: PolicyCounts = {
    intervals: 0,
    programs: 0,
    sourceDispatches: 0,
    dispatchEntries: 0,
    classifierRules: 0,
    candidateClaims: 0,
    winnerWork: 0,
    candidateComparisons: 0,
    generatedPeerPrefixes: 0,
  };
  const work = (groupIds?: number[]) => {
    limit(
      'winner_work',
      ++counts.winnerWork,
      POLICY_LIMITS.winnerWork,
      groupIds
    );
  };
  // Group sources first: no source-by-interval matrix is ever allocated.
  const programMap = new Map<string, CompiledPolicy['programs'][number]>();
  const perGroupDispatch = new Map<number, number>();
  const addDispatch = (id: number, n: number) => {
    const total = (perGroupDispatch.get(id) ?? 0) + n;
    limit('group_dispatch', total, POLICY_LIMITS.groupDispatch, [id]);
    perGroupDispatch.set(id, total);
  };
  for (const c of [...clients.values()].sort((a, b) => a.id - b.id)) {
    if (!c.enabled) continue;
    const groupIds = (memberships.get(c.id) ?? [])
      .filter((id) => active.some((g) => g.id === id))
      .sort((a, b) => a - b);
    if (!groupIds.length) continue;
    limit(
      'dispatch',
      ++counts.sourceDispatches,
      POLICY_LIMITS.dispatch,
      groupIds
    );
    for (const id of groupIds) addDispatch(id, 1);
    const key = groupIds.join(',');
    if (!programMap.has(key))
      programMap.set(key, { groupIds, sources: [], cells: [], branches: [] });
    programMap.get(key)!.sources.push({
      clientId: c.id,
      interfaceId: c.interfaceId,
      ipv4Address: c.ipv4Address,
    });
  }
  const programs = [...programMap.values()].sort((a, b) =>
    a.groupIds.join(',').localeCompare(b.groupIds.join(','))
  );
  counts.programs = programs.length;
  const boundaries = new Set<number>();
  const boundary = (r: Range) => {
    boundaries.add(r.start);
    boundaries.add(r.end);
    limit('intervals', boundaries.size - 1, POLICY_LIMITS.intervals);
  };
  for (const g of active)
    for (const r of [...g.included, ...g.excluded]) boundary(r);
  for (const r of bypass) boundary(r);
  // Legacy uniqueness remains global and includes disabled declarations.
  const legacy: { client: PolicyClient; range: Prefix }[] = [];
  for (const c of clients.values())
    for (const s of c.serverAllowedIps) {
      const parsed = parseCidr(s);
      if (!parsed.prefixPresent || Number(parsed.prefix) === 0)
        throw new PolicyValidationError('legacy_default_route', {
          clientIds: [c.id],
        });
      for (const other of clients.values()) {
        if (other.id >= c.id) continue;
        for (const existing of other.serverAllowedIps) {
          limit(
            'candidate_comparisons',
            ++counts.candidateComparisons,
            POLICY_LIMITS.comparisons
          );
          const p = parseCidr(existing);
          if (
            parsed.version === p.version &&
            parsed.start <= p.end &&
            p.start <= parsed.end
          )
            throw new PolicyValidationError('legacy_conflict', {
              clientIds: [other.id, c.id],
            });
        }
      }
      if (parsed.version !== 4) continue;
      const range = prefix(s);
      legacy.push({ client: c, range });
      boundary(range);
    }
  const points = [...boundaries].sort((a, b) => a - b);
  const intervals = points
    .slice(0, -1)
    .map((start, i) => ({ start, end: points[i + 1]! }));
  counts.intervals = intervals.length;
  const rankCache = new Map<string, Prefix | null>();
  const rank = (g: (typeof groups)[number], index: number) => {
    const key = `${g.id}:${index}`;
    if (rankCache.has(key)) return rankCache.get(key)!;
    const start = intervals[index]!.start;
    let result: Prefix | null = null;
    for (const r of g.included) {
      work([g.id]);
      if (contains(r, start) && (!result || r.rank > result.rank)) result = r;
    }
    for (const r of g.excluded) {
      work([g.id]);
      if (contains(r, start)) result = null;
    }
    rankCache.set(key, result);
    return result;
  };
  const scopes = new Map<number, Set<number>>(
    active.map((g) => [g.id, new Set<number>()])
  );
  // Reject empty policies independently of their current enabled source set.
  for (const g of active) {
    let nonempty = false;
    for (let i = 0; i < intervals.length; i++) {
      work([g.id]);
      if (!bypass.some((r) => contains(r, intervals[i]!.start)) && rank(g, i))
        nonempty = true;
    }
    if (!nonempty)
      throw new PolicyValidationError('empty_policy', { groupIds: [g.id] });
  }
  for (const program of programs) {
    const participating = active.filter((g) => program.groupIds.includes(g.id));
    for (let i = 0; i < intervals.length; i++) {
      const region = intervals[i]!;
      if (bypass.some((r) => contains(r, region.start))) continue;
      let winner: { group: PolicyGroup; match: Prefix } | undefined;
      const tied: number[] = [];
      for (const g of participating) {
        work(program.groupIds);
        const match = rank(g, i);
        if (!match) continue;
        if (!winner || match.rank > winner.match.rank) {
          winner = { group: g, match };
          tied.splice(0, tied.length, g.id);
        } else if (match.rank === winner.match.rank) tied.push(g.id);
      }
      if (tied.length > 1)
        throw new PolicyValidationError('equal_specificity', {
          groupIds: tied,
          clientIds: [program.sources[0]!.clientId],
          destination: address(region.start),
        });
      if (!winner) continue;
      const cell: PolicyCell = {
        ...region,
        groupId: winner.group.id,
        originalPrefix: winner.match.cidr,
        specificity: winner.match.rank,
      };
      program.cells.push(cell);
      scopes.get(cell.groupId)!.add(i);
    }
    for (const g of participating) {
      const prefixes = policyRangeCidrs(
        program.cells.filter((c) => c.groupId === g.id)
      );
      addDispatch(g.id, prefixes.length);
      for (const p of prefixes) {
        limit(
          'dispatch',
          counts.sourceDispatches +
            programs.reduce((n, p) => n + p.branches.length, 0) +
            1,
          POLICY_LIMITS.dispatch,
          [g.id]
        );
        program.branches.push({ prefix: p, groupId: g.id });
      }
    }
  }
  counts.dispatchEntries =
    counts.sourceDispatches +
    programs.reduce((n, p) => n + p.branches.length, 0);
  // Two terminal rules per branch; source dispatches, definitions, bypass and owner/clear rules.
  counts.classifierRules =
    counts.sourceDispatches +
    2 * (counts.dispatchEntries - counts.sourceDispatches) +
    programs.length +
    bypass.length +
    interfaces.size +
    3;
  limit(
    'classifier_rules',
    counts.classifierRules,
    POLICY_LIMITS.classifierRules
  );
  limit(
    'classifier_scaffolding',
    programs.length + bypass.length + interfaces.size + 3,
    4096
  );
  const compiledGroups = active.map((g) => {
    const effectivePrefixes = policyRangeCidrs(
      [...scopes.get(g.id)!].map((i) => intervals[i]!)
    );
    return {
      id: g.id,
      name: g.name,
      includedPrefixes: g.included.map((p) => p.cidr),
      excludedPrefixes: policyRangeCidrs(g.excluded),
      effectivePrefixes,
      shadowed: effectivePrefixes.length === 0,
      natEnabled: g.natEnabled,
      allExitsDownPolicy: g.allExitsDownPolicy,
    };
  });
  const claims: CompiledPolicy['candidateClaims'] = [];
  for (const g of active)
    for (const i of scopes.get(g.id)!)
      for (const exit of [...g.exits].sort((a, b) => a.clientId - b.clientId)) {
        if (!exit.enabled) continue;
        const c = clients.get(exit.clientId)!;
        limit('candidate_claims', claims.length + 1, POLICY_LIMITS.claims, [
          g.id,
        ]);
        claims.push({
          interval: i,
          groupId: g.id,
          clientId: c.id,
          interfaceId: c.interfaceId,
          peerId: policyPeerId(c),
        });
      }
  counts.candidateClaims = claims.length;
  const claimsByRegion = new Map<string, typeof claims>();
  for (const claim of claims) {
    const key = `${claim.interfaceId}:${claim.interval}`;
    const siblings = claimsByRegion.get(key) ?? [];
    const c = clients.get(claim.clientId)!;
    const conflict = (other: PolicyClient, groupId?: number) => {
      limit(
        'candidate_comparisons',
        ++counts.candidateComparisons,
        POLICY_LIMITS.comparisons,
        [claim.groupId]
      );
      if (
        policyPeerId(other) !== claim.peerId &&
        policyCandidatesCanCoexist(c, other)
      )
        throw new PolicyValidationError('peer_conflict', {
          groupIds:
            groupId === undefined ? [claim.groupId] : [groupId, claim.groupId],
          clientIds: [other.id, c.id],
          interfaceId: c.interfaceId,
          destination: address(intervals[claim.interval]!.start),
        });
    };
    for (const other of siblings)
      if (other.groupId !== claim.groupId)
        conflict(clients.get(other.clientId)!, other.groupId);
    for (const l of legacy)
      if (
        l.client.interfaceId === claim.interfaceId &&
        overlaps(l.range, intervals[claim.interval]!)
      )
        conflict(l.client);
    siblings.push(claim);
    claimsByRegion.set(key, siblings);
  }
  // Conservative worst-choice budgets: each group contributes once globally/per interface;
  // per-peer unions include every group that can ever select that peer.
  const peerRanges = new Map<string, Range[]>();
  const interfaceCounts = new Map<string, number>();
  for (const g of compiledGroups) {
    const source = active.find((p) => p.id === g.id)!;
    const candidates = source.exits
      .filter((e) => e.enabled)
      .map((e) => clients.get(e.clientId)!);
    counts.generatedPeerPrefixes += g.effectivePrefixes.length;
    limit(
      'global_peer_prefixes',
      counts.generatedPeerPrefixes,
      POLICY_LIMITS.globalPrefixes,
      [g.id]
    );
    for (const iface of new Set(candidates.map((c) => c.interfaceId))) {
      const n = (interfaceCounts.get(iface) ?? 0) + g.effectivePrefixes.length;
      limit('interface_peer_prefixes', n, POLICY_LIMITS.interfacePrefixes, [
        g.id,
      ]);
      interfaceCounts.set(iface, n);
    }
    for (const peer of new Set(candidates.map(policyPeerId))) {
      const ranges = [
        ...(peerRanges.get(peer) ?? []),
        ...g.effectivePrefixes.map(prefix),
      ];
      const merged = union(ranges);
      limit(
        'peer_prefixes',
        policyRangeCidrs(merged).length,
        POLICY_LIMITS.peerPrefixes,
        [g.id]
      );
      peerRanges.set(peer, merged);
    }
  }
  const basePeers = [...clients.values()]
    .filter((c) => c.enabled)
    .sort((a, b) => a.id - b.id)
    .map((c) => ({
      clientId: c.id,
      interfaceId: c.interfaceId,
      peerId: policyPeerId(c),
      prefixes: [
        `${c.ipv4Address}/32`,
        ...(c.ipv6Address ? [`${c.ipv6Address}/128`] : []),
        ...c.serverAllowedIps.map((value) => normalizeCidr(value)),
      ].sort(),
    }));
  const semantic = {
    version: 2 as const,
    bypassPrefixes: policyRangeCidrs(bypass),
    intervals,
    programs,
    groups: compiledGroups,
    candidateClaims: claims,
    basePeers,
  };
  const fingerprint = createHash('sha256')
    .update(JSON.stringify(semantic))
    .digest('hex');
  return { ...semantic, fingerprint, counts };
}
