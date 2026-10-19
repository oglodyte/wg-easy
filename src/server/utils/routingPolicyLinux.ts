import { createHash } from 'node:crypto';

import { parseCidr } from 'cidr-tools';

import {
  buildRoutingPlan,
  FWMARK_MASK,
  formatMark,
  routeCommand,
  ruleCommand,
  routingMarkForSlot,
  ROUTING_MARK_CHAIN,
  ROUTING_NAT_CHAIN,
  ROUTING_OWNER_COMMENT,
  ROUTING_PRIORITY_BASE,
  ROUTING_PROGRAM_CHAIN_PREFIX,
  ROUTING_TABLE_BASE,
  SITE_TO_SITE_PRIORITY,
  SITE_TO_SITE_TABLE_ID,
  WG_EASY_ROUTE_PROTOCOL,
  type PlannedPolicyRule,
  type PlannedRoute,
  type RoutingPlan,
} from '#server/utils/routing';
import {
  POLICY_LIMITS,
  PolicyValidationError,
} from '#server/utils/routingPolicy';
import { parseRoutingPolicyJournal } from '#server/utils/routingPolicyJournal';
import { routingPolicyRuntimeFingerprint } from '#server/utils/routingPolicyRuntime';
import type { AppliedRoutingPolicyPlan } from '#shared/types/routingPolicy';

/** Render Linux state from the same normalized snapshot as complete peer ownership. */
export function renderRoutingPolicyLinux(
  value: AppliedRoutingPolicyPlan
): RoutingPlan {
  const { plan, fingerprint } = parseRoutingPolicyJournal({
    revision: 0,
    fingerprint: routingPolicyRuntimeFingerprint(value),
    plan: value,
  });
  const result = buildRoutingPlan({ interfaces: [], clients: [], groups: [] });
  const byGroup = new Map(plan.groups.map((g) => [g.id, g]));
  const mask = formatMark(FWMARK_MASK);
  result.classifier = { fingerprint, children: [] };
  result.markChainRules = [
    [
      '-A',
      ROUTING_MARK_CHAIN,
      '-m',
      'comment',
      '--comment',
      `${ROUTING_OWNER_COMMENT} policy ${fingerprint} reset`,
      '-j',
      'MARK',
      '--set-xmark',
      `0x00000000/${mask}`,
    ],
  ];
  for (const prefix of plan.bypassPrefixes)
    result.markChainRules.push([
      '-A',
      ROUTING_MARK_CHAIN,
      '-d',
      prefix,
      '-m',
      'comment',
      '--comment',
      `${ROUTING_OWNER_COMMENT} managed-cidr bypass`,
      '-j',
      'RETURN',
    ]);

  const names = new Map<string, string>();
  for (const program of plan.programs) {
    if (!program.branches.length) continue;
    const signature = program.branches.map((b) => [
      b.prefix,
      b.groupId,
      b.action,
      routingMarkForSlot(byGroup.get(b.groupId)!.routingSlot),
    ]);
    const programFingerprint = createHash('sha256')
      .update(JSON.stringify(signature))
      .digest('hex');
    const name = `${ROUTING_PROGRAM_CHAIN_PREFIX}${programFingerprint.slice(0, 16)}`;
    if (names.has(name) && names.get(name) !== programFingerprint)
      throw new PolicyValidationError('classifier_name_collision');
    if (!names.has(name)) {
      names.set(name, programFingerprint);
      const rules: string[][] = [];
      for (const b of program.branches) {
        const match = [
          '-A',
          name,
          '-d',
          b.prefix,
          '-m',
          'comment',
          '--comment',
          `${ROUTING_OWNER_COMMENT} program ${programFingerprint}`,
        ];
        if (b.action !== 'host')
          rules.push([
            ...match,
            '-j',
            'MARK',
            '--set-xmark',
            `${formatMark(routingMarkForSlot(byGroup.get(b.groupId)!.routingSlot))}/${mask}`,
          ]);
        rules.push([...match, '-j', 'RETURN']);
      }
      result.classifier.children.push({
        name,
        fingerprint: programFingerprint,
        rules,
      });
    }
    for (const source of program.sources)
      result.markChainRules.push([
        '-A',
        ROUTING_MARK_CHAIN,
        '-s',
        `${source.ipv4Address}/32`,
        '-i',
        source.interfaceId,
        '-m',
        'comment',
        '--comment',
        `${ROUTING_OWNER_COMMENT} source ${source.clientId}`,
        '--goto',
        name,
      ]);
  }
  result.parentMarkJumps = plan.interfaces
    .filter((i) => i.enabled)
    .map((i) => ({
      interfaceId: i.interfaceId,
      args: [
        '-A',
        'PREROUTING',
        '-i',
        i.interfaceId,
        '-m',
        'comment',
        '--comment',
        ROUTING_OWNER_COMMENT,
        '-j',
        ROUTING_MARK_CHAIN,
      ],
    }));

  function addRoute(route: Omit<PlannedRoute, 'command'>) {
    result.routes.push({ ...route, command: routeCommand(route) });
  }
  function addRule(rule: Omit<PlannedPolicyRule, 'command'>) {
    result.policyRules.push({ ...rule, command: ruleCommand(rule) });
  }
  for (const group of plan.groups) {
    const selected = group.selectedExitClientId !== null;
    const outcome = !group.enabled
      ? 'disabled'
      : selected
        ? 'selected_exit'
        : group.allExitsDownPolicy;
    const table = ROUTING_TABLE_BASE + group.routingSlot,
      priority = ROUTING_PRIORITY_BASE + group.routingSlot,
      fwmark = routingMarkForSlot(group.routingSlot);
    result.groups.push({
      groupId: group.id,
      routingSlot: group.routingSlot,
      outcome,
      selectedExitClientId: group.selectedExitClientId,
      table,
      priority,
      fwmark,
    });
    if (!group.enabled || !group.effectivePrefixes.length || outcome === 'host')
      continue;
    for (const prefix of group.effectivePrefixes)
      addRoute({
        family: 4,
        table,
        protocol: WG_EASY_ROUTE_PROTOCOL,
        prefix,
        type: selected ? 'unicast' : 'unreachable',
        ...(selected ? { device: group.exitInterfaceId! } : {}),
      });
    addRule({
      family: 4,
      table,
      priority,
      protocol: WG_EASY_ROUTE_PROTOCOL,
      fwmark,
      mask: FWMARK_MASK,
    });
    if (selected && group.natEnabled)
      result.natChainRules.push([
        '-A',
        ROUTING_NAT_CHAIN,
        '-o',
        group.exitInterfaceId!,
        '-m',
        'mark',
        '--mark',
        `${formatMark(fwmark)}/${mask}`,
        '-m',
        'comment',
        '--comment',
        `${ROUTING_OWNER_COMMENT} group ${group.id}`,
        '-j',
        'SNAT',
        '--to-source',
        group.serverIpv4Address!,
      ]);
  }
  const families = new Set<4 | 6>();
  for (const route of plan.siteRoutes)
    for (const prefix of route.prefixes) {
      const family = parseCidr(prefix).version;
      families.add(family);
      addRoute({
        family,
        table: SITE_TO_SITE_TABLE_ID,
        protocol: WG_EASY_ROUTE_PROTOCOL,
        prefix,
        type: 'unicast',
        device: route.interfaceId,
      });
    }
  for (const family of [...families].sort())
    addRule({
      family,
      table: SITE_TO_SITE_TABLE_ID,
      priority: SITE_TO_SITE_PRIORITY,
      protocol: WG_EASY_ROUTE_PROTOCOL,
    });
  result.parentNatJump = result.natChainRules.length
    ? [
        '-A',
        'POSTROUTING',
        '-m',
        'comment',
        '--comment',
        ROUTING_OWNER_COMMENT,
        '-j',
        ROUTING_NAT_CHAIN,
      ]
    : null;
  result.peerAllowedIps = plan.peers.map((p) => ({
    clientId: p.clientId,
    prefixes: [...p.prefixes],
  }));
  const classifierRules =
    3 +
    result.parentMarkJumps.length +
    (result.markChainRules.length - 1) +
    result.classifier.children.length +
    result.classifier.children.reduce((n, c) => n + c.rules.length, 0);
  if (classifierRules > POLICY_LIMITS.classifierRules)
    throw new PolicyValidationError('classifier_rule_budget');
  return result;
}
