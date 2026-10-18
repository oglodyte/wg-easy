import { parseCidr } from 'cidr-tools';

import {
  buildRoutingGuard,
  RoutingGuardError,
  type RoutingGuardScope,
} from '#server/utils/routingGuard';
import { POLICY_LIMITS, policyRangeCidrs } from '#server/utils/routingPolicy';
import type { AppliedRoutingPolicyPlan } from '#shared/types/routingPolicy';

type Range = { start: number; end: number };
type Branch = Range & { signature: string; groupId: number };
type Source = AppliedRoutingPolicyPlan['programs'][number]['sources'][number];
function range(value: string): Range {
  try {
    const parsed = parseCidr(value);
    if (parsed.version !== 4 || !parsed.prefixPresent) throw new Error();
    return { start: Number(parsed.start), end: Number(parsed.end) + 1 };
  } catch {
    throw new RoutingGuardError('invalid_transition_plan');
  }
}
function sourcePrograms(plan: AppliedRoutingPolicyPlan | null) {
  const programs = new Map<
    string,
    { source: Source; branches: Branch[]; programId: number }
  >();
  if (!plan) return programs;
  const groups = new Map(plan.groups.map((g) => [g.id, g]));
  for (const [programId, p] of plan.programs.entries()) {
    const branches = p.branches
      .map((b) => {
        const g = groups.get(b.groupId);
        if (!g) throw new RoutingGuardError('invalid_transition_plan');
        return {
          ...range(b.prefix),
          groupId: b.groupId,
          signature: JSON.stringify([
            b.action,
            g.routingSlot,
            g.natEnabled,
            g.selectedExitClientId,
            g.exitInterfaceId,
            g.serverIpv4Address,
          ]),
        };
      })
      .sort((a, b) => a.start - b.start || a.end - b.end);
    for (let i = 1; i < branches.length; i++)
      if (branches[i]!.start < branches[i - 1]!.end)
        throw new RoutingGuardError('invalid_transition_plan');
    for (const source of p.sources) {
      const key = JSON.stringify([source.interfaceId, source.ipv4Address]);
      if (programs.has(key))
        throw new RoutingGuardError('duplicate_transition_source');
      programs.set(key, { source, branches, programId });
    }
  }
  return programs;
}
type Trie = { owner?: string; zero?: Trie; one?: Trie };
function peerTrie(peers: AppliedRoutingPolicyPlan['peers']) {
  const root: Trie = {},
    points = new Set<number>();
  for (const peer of peers)
    for (const prefix of peer.prefixes) {
      const p = parseCidr(prefix);
      if (p.version !== 4) continue;
      const start = Number(p.start);
      points.add(start);
      points.add(Number(p.end) + 1);
      let node = root;
      for (let bit = 0; bit < Number(p.prefix); bit++) {
        const side =
          Math.floor(start / 2 ** (31 - bit)) % 2 === 0 ? 'zero' : 'one';
        node[side] ??= {};
        node = node[side]!;
      }
      if (node.owner && node.owner !== peer.peerId)
        throw new RoutingGuardError('ambiguous_transition_peer');
      node.owner = peer.peerId;
    }
  return { root, points };
}
function lookup(root: Trie, address: number) {
  let node: Trie | undefined = root,
    owner = root.owner;
  for (let bit = 0; bit < 32 && node; bit++) {
    node =
      node[Math.floor(address / 2 ** (31 - bit)) % 2 === 0 ? 'zero' : 'one'];
    if (node?.owner) owner = node.owner;
  }
  return owner;
}

/** Pure IPv4 closure; previous identities survive deletion and key replacement. */
export function buildRoutingPolicyTransition(
  previous: AppliedRoutingPolicyPlan | null,
  target: AppliedRoutingPolicyPlan,
  {
    protectedPaths,
    forcePeerIds = new Set<string>(),
  }: {
    protectedPaths: readonly RoutingGuardScope[];
    forcePeerIds?: ReadonlySet<string>;
  }
) {
  const scopes = new Map<string, RoutingGuardScope>();
  const add = (scope: RoutingGuardScope) => {
    scopes.set(JSON.stringify(scope), scope);
    if (scopes.size > POLICY_LIMITS.guardRules)
      throw new RoutingGuardError('rule_budget_exceeded', {
        actual: scopes.size,
        limit: POLICY_LIMITS.guardRules,
      });
  };
  const previousPrograms = sourcePrograms(previous),
    nextPrograms = sourcePrograms(target);
  const oldGroups = new Map(previous?.groups.map((g) => [g.id, g]) ?? []),
    newGroups = new Map(target.groups.map((g) => [g.id, g]));
  const changedByProgram = new Map<string, string[]>();
  for (const key of new Set([
    ...previousPrograms.keys(),
    ...nextPrograms.keys(),
  ])) {
    const before = previousPrograms.get(key),
      after = nextPrograms.get(key),
      source = (after ?? before)!.source;
    const programKey = `${before?.programId ?? -1}:${after?.programId ?? -1}`;
    let changedPrefixes = changedByProgram.get(programKey);
    if (!changedPrefixes) {
      const points = [
        ...new Set(
          [...(before?.branches ?? []), ...(after?.branches ?? [])].flatMap(
            (b) => [b.start, b.end]
          )
        ),
      ].sort((a, b) => a - b);
      let oldIndex = 0,
        newIndex = 0;
      const changed: Range[] = [];
      for (let i = 0; i < points.length - 1; i++) {
        const start = points[i]!,
          end = points[i + 1]!;
        while (
          before?.branches[oldIndex] &&
          before.branches[oldIndex]!.end <= start
        )
          oldIndex++;
        while (
          after?.branches[newIndex] &&
          after.branches[newIndex]!.end <= start
        )
          newIndex++;
        const a = before?.branches[oldIndex],
          b = after?.branches[newIndex];
        const oldBranch =
          a && a.start <= start && start < a.end ? a : undefined;
        const newBranch =
          b && b.start <= start && start < b.end ? b : undefined;
        if (oldBranch?.signature === newBranch?.signature) continue;
        changed.push({ start, end });
        // Unmatched/stale SNAT replies can arrive at INPUT rather than FORWARD.
        for (const [branch, groups] of [
          [oldBranch, oldGroups],
          [newBranch, newGroups],
        ] as const) {
          const group = branch ? groups.get(branch.groupId) : undefined;
          if (
            !group?.natEnabled ||
            !group.exitInterfaceId ||
            !group.serverIpv4Address
          )
            continue;
          for (const prefix of policyRangeCidrs([{ start, end }]))
            add({
              direction: 'input',
              inputInterface: group.exitInterfaceId,
              source: prefix,
              destination: `${group.serverIpv4Address}/32`,
            });
        }
      }
      changedPrefixes = policyRangeCidrs(changed);
      changedByProgram.set(programKey, changedPrefixes);
    }
    for (const prefix of changedPrefixes) {
      add({
        direction: 'forward',
        inputInterface: source.interfaceId,
        source: `${source.ipv4Address}/32`,
        destination: prefix,
      });
      // Tracked SNAT replies are reverse-translated before the filter hook.
      add({
        direction: 'forward',
        outputInterface: source.interfaceId,
        source: prefix,
        destination: `${source.ipv4Address}/32`,
      });
    }
  }
  // The peer map may stay the same while an unmarked site route is removed.
  // Guard its prefix independently of the old device so host fallback cannot
  // become visible before the whole transition has been verified.
  const siteClaims = (plan: AppliedRoutingPolicyPlan | null) =>
    new Map(
      (plan?.siteRoutes ?? []).flatMap((route) =>
        route.prefixes
          .filter((prefix) => parseCidr(prefix).version === 4)
          .map((prefix) => [prefix, route.interfaceId] as const)
      )
    );
  const oldSites = siteClaims(previous),
    newSites = siteClaims(target);
  const siteRanges = [...new Set([...oldSites.keys(), ...newSites.keys()])]
    .filter((prefix) => oldSites.get(prefix) !== newSites.get(prefix))
    .map(range);
  for (const prefix of policyRangeCidrs(siteRanges)) {
    add({ direction: 'forward', source: '0.0.0.0/0', destination: prefix });
    add({ direction: 'output', source: '0.0.0.0/0', destination: prefix });
    add({ direction: 'forward', source: prefix, destination: '0.0.0.0/0' });
    add({ direction: 'input', source: prefix, destination: '0.0.0.0/0' });
  }
  const oldPeers = new Map(previous?.peers.map((p) => [p.peerId, p]) ?? []),
    newPeers = new Map(target.peers.map((p) => [p.peerId, p]));
  const changedPeers = new Set(forcePeerIds);
  for (const id of new Set([...oldPeers.keys(), ...newPeers.keys()]))
    if (
      JSON.stringify(oldPeers.get(id)?.prefixes) !==
      JSON.stringify(newPeers.get(id)?.prefixes)
    )
      changedPeers.add(id);
  const interfaces = new Set(
    [...(previous?.peers ?? []), ...target.peers].map((p) => p.interfaceId)
  );
  for (const interfaceId of interfaces) {
    const before = peerTrie(
        (previous?.peers ?? []).filter((p) => p.interfaceId === interfaceId)
      ),
      after = peerTrie(
        target.peers.filter((p) => p.interfaceId === interfaceId)
      );
    const points = [...new Set([...before.points, ...after.points])].sort(
        (a, b) => a - b
      ),
      changed: Range[] = [];
    for (let i = 0; i < points.length - 1; i++) {
      const start = points[i]!,
        end = points[i + 1]!,
        oldOwner = lookup(before.root, start),
        newOwner = lookup(after.root, start);
      if (
        (oldOwner && changedPeers.has(oldOwner)) ||
        (newOwner && changedPeers.has(newOwner))
      )
        changed.push({ start, end });
    }
    for (const prefix of policyRangeCidrs(changed)) {
      add({
        direction: 'forward',
        outputInterface: interfaceId,
        source: '0.0.0.0/0',
        destination: prefix,
      });
      add({
        direction: 'output',
        outputInterface: interfaceId,
        source: '0.0.0.0/0',
        destination: prefix,
      });
      add({
        direction: 'forward',
        inputInterface: interfaceId,
        source: prefix,
        destination: '0.0.0.0/0',
      });
      add({
        direction: 'input',
        inputInterface: interfaceId,
        source: prefix,
        destination: '0.0.0.0/0',
      });
    }
  }
  return buildRoutingGuard([...scopes.values()], { protectedPaths });
}
