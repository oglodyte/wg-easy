import { normalizeCidr, parseCidr } from 'cidr-tools';
import { stringifyIp } from 'ip-bigint';

import type { AllExitsDownPolicy } from '#shared/types/runtime';
import { schemaLimits } from '#shared/utils/schemas';

export const ROUTING_TABLE_BASE = 52000;
export const ROUTING_PRIORITY_BASE = 22000;
export const ROUTING_SLOT_MIN = 1;
export const ROUTING_SLOT_MAX = 999;
export const ROUTING_GROUP_PRIORITY_MAX = 22999;
export const SITE_TO_SITE_TABLE_ID = 51999;
export const SITE_TO_SITE_PRIORITY = 23000;
export const WG_EASY_ROUTE_PROTOCOL = 186;
export const FWMARK_NAMESPACE = 0x54000000;
export const FWMARK_MASK = 0xffff0000;
export const ROUTING_MARK_CHAIN = 'WG_ROUTE_MARK';
export const ROUTING_NAT_CHAIN = 'WG_ROUTE_NAT';

export type RoutingValidationIssue = {
  code:
    | 'client_not_found'
    | 'member_already_assigned'
    | 'exit_keepalive_invalid'
    | 'enabled_group_incomplete'
    | 'server_allowed_ip_conflict'
    | 'routing_group_overlap'
    | 'routing_server_allowed_ip_overlap'
    | 'global_rule_limit';
  message: string;
  clientIds?: number[];
  groupIds?: number[];
  prefixes?: string[];
};

export class RoutingValidationError extends Error {
  readonly issues: RoutingValidationIssue[];

  constructor(issues: RoutingValidationIssue[]) {
    super(issues.map(({ message }) => message).join('; '));
    this.name = 'RoutingValidationError';
    this.issues = issues;
  }
}

type CidrRange = ReturnType<typeof parseCidr>;

function parseRequiredCidr(value: string): CidrRange {
  const parsed = parseCidr(value);
  if (!parsed.prefixPresent) {
    throw new Error(`Expected a CIDR prefix: ${value}`);
  }
  return parsed;
}

export function canonicalizeServerAllowedIps(prefixes: readonly string[]) {
  const normalized = prefixes.map((prefix) => {
    const parsed = parseRequiredCidr(prefix);
    if (Number(parsed.prefix) === 0) {
      throw new Error(
        `Default route ${prefix} is not allowed in serverAllowedIps; use a routing group`
      );
    }
    return normalizeCidr(prefix);
  });
  return [...new Set(normalized)];
}

export function cidrsOverlap(first: string, second: string) {
  const left = parseRequiredCidr(first);
  const right = parseRequiredCidr(second);
  return (
    left.version === right.version &&
    left.start <= right.end &&
    right.start <= left.end
  );
}

export type ServerAllowedIpClient = {
  id: number;
  interfaceId: string;
  serverAllowedIps: readonly string[];
};

export function findServerAllowedIpConflicts(
  clients: readonly ServerAllowedIpClient[]
): RoutingValidationIssue[] {
  const assignments = clients.flatMap((client) =>
    canonicalizeServerAllowedIps(client.serverAllowedIps).map((prefix) => ({
      clientId: client.id,
      interfaceId: client.interfaceId,
      prefix,
    }))
  );
  const issues: RoutingValidationIssue[] = [];

  for (let leftIndex = 0; leftIndex < assignments.length; leftIndex += 1) {
    const left = assignments[leftIndex]!;
    for (
      let rightIndex = leftIndex + 1;
      rightIndex < assignments.length;
      rightIndex += 1
    ) {
      const right = assignments[rightIndex]!;
      if (
        left.clientId !== right.clientId &&
        cidrsOverlap(left.prefix, right.prefix)
      ) {
        issues.push({
          code: 'server_allowed_ip_conflict',
          message: `serverAllowedIps ${left.prefix} for client ${left.clientId} overlaps ${right.prefix} for client ${right.clientId}`,
          clientIds: [left.clientId, right.clientId],
          prefixes: [left.prefix, right.prefix],
        });
      }
    }
  }

  return issues;
}

export type RoutingConflictGroup = {
  id: number;
  enabled: boolean;
  routedIpv4Prefixes: readonly string[];
  exits: readonly {
    clientId: number;
    enabled: boolean;
  }[];
};

export function findRoutingPrefixConflicts({
  clients,
  groups,
}: {
  clients: readonly ServerAllowedIpClient[];
  groups: readonly RoutingConflictGroup[];
}): RoutingValidationIssue[] {
  const clientById = new Map(clients.map((client) => [client.id, client]));
  const enabledGroups = groups.filter(({ enabled }) => enabled);
  const issues: RoutingValidationIssue[] = [];
  const seen = new Set<string>();
  const addIssue = (key: string, issue: RoutingValidationIssue) => {
    if (seen.has(key)) return;
    seen.add(key);
    issues.push(issue);
  };

  for (let leftIndex = 0; leftIndex < enabledGroups.length; leftIndex += 1) {
    const leftGroup = enabledGroups[leftIndex]!;
    for (
      let rightIndex = leftIndex + 1;
      rightIndex < enabledGroups.length;
      rightIndex += 1
    ) {
      const rightGroup = enabledGroups[rightIndex]!;
      for (const leftExit of leftGroup.exits.filter(({ enabled }) => enabled)) {
        const leftClient = clientById.get(leftExit.clientId);
        if (!leftClient) continue;
        for (const rightExit of rightGroup.exits.filter(
          ({ enabled }) => enabled
        )) {
          const rightClient = clientById.get(rightExit.clientId);
          if (
            !rightClient ||
            leftClient.id === rightClient.id ||
            leftClient.interfaceId !== rightClient.interfaceId
          ) {
            continue;
          }
          for (const leftPrefix of leftGroup.routedIpv4Prefixes) {
            for (const rightPrefix of rightGroup.routedIpv4Prefixes) {
              if (!cidrsOverlap(leftPrefix, rightPrefix)) continue;
              const key = [
                'group',
                Math.min(leftGroup.id, rightGroup.id),
                Math.max(leftGroup.id, rightGroup.id),
                Math.min(leftClient.id, rightClient.id),
                Math.max(leftClient.id, rightClient.id),
                normalizeCidr(leftPrefix),
                normalizeCidr(rightPrefix),
              ].join(':');
              addIssue(key, {
                code: 'routing_group_overlap',
                message: `Routing groups ${leftGroup.id} and ${rightGroup.id} have overlapping prefixes on interface ${leftClient.interfaceId} through different exit clients`,
                clientIds: [leftClient.id, rightClient.id],
                groupIds: [leftGroup.id, rightGroup.id],
                prefixes: [
                  normalizeCidr(leftPrefix),
                  normalizeCidr(rightPrefix),
                ],
              });
            }
          }
        }
      }
    }
  }

  for (const group of enabledGroups) {
    for (const exit of group.exits.filter(({ enabled }) => enabled)) {
      const exitClient = clientById.get(exit.clientId);
      if (!exitClient) continue;
      for (const routedPrefix of group.routedIpv4Prefixes) {
        for (const siteClient of clients) {
          if (
            siteClient.id === exitClient.id ||
            siteClient.interfaceId !== exitClient.interfaceId
          ) {
            continue;
          }
          for (const sitePrefix of canonicalizeServerAllowedIps(
            siteClient.serverAllowedIps
          )) {
            if (!cidrsOverlap(routedPrefix, sitePrefix)) continue;
            const key = [
              'site',
              group.id,
              exitClient.id,
              siteClient.id,
              normalizeCidr(routedPrefix),
              sitePrefix,
            ].join(':');
            addIssue(key, {
              code: 'routing_server_allowed_ip_overlap',
              message: `Routing group ${group.id} prefix ${normalizeCidr(routedPrefix)} conflicts with client ${siteClient.id} serverAllowedIps ${sitePrefix} on interface ${exitClient.interfaceId}`,
              clientIds: [exitClient.id, siteClient.id],
              groupIds: [group.id],
              prefixes: [normalizeCidr(routedPrefix), sitePrefix],
            });
          }
        }
      }
    }
  }

  return issues;
}

export type ExitHealthSettings = {
  healthTimeoutSeconds: number;
  minHoldSeconds: number;
  failbackDelaySeconds: number;
};

export type ExitCandidateObservation = {
  clientId: number;
  priority: number;
  candidateEnabled: boolean;
  clientEnabled: boolean;
  interfaceEnabled: boolean;
  interfaceObservedUp: boolean;
  persistentKeepalive: number;
  latestHandshakeAt: Date | null;
  endpoint: string | null;
  healthySince?: Date | null;
};

export type ExitReadiness = ExitCandidateObservation & {
  keepaliveValid: boolean;
  handshakeSeen: boolean;
  handshakeFresh: boolean;
  configurationReady: boolean;
  observedHealthy: boolean;
  explicitlyUnavailable: boolean;
  reason: string;
};

export function evaluateExitReadiness(
  candidate: ExitCandidateObservation,
  settings: Pick<ExitHealthSettings, 'healthTimeoutSeconds'>,
  now = new Date()
): ExitReadiness {
  const maximumKeepalive = Math.floor(settings.healthTimeoutSeconds / 3);
  const keepaliveValid =
    candidate.persistentKeepalive > 0 &&
    candidate.persistentKeepalive <= maximumKeepalive;
  const handshakeSeen = candidate.latestHandshakeAt !== null;
  const handshakeAge = handshakeSeen
    ? now.getTime() - candidate.latestHandshakeAt!.getTime()
    : Number.POSITIVE_INFINITY;
  const handshakeFresh =
    handshakeSeen &&
    handshakeAge >= 0 &&
    handshakeAge <= settings.healthTimeoutSeconds * 1000;
  const explicitlyUnavailable =
    !candidate.candidateEnabled ||
    !candidate.clientEnabled ||
    !candidate.interfaceEnabled ||
    !candidate.interfaceObservedUp;
  const configurationReady =
    candidate.candidateEnabled &&
    candidate.clientEnabled &&
    candidate.interfaceEnabled &&
    keepaliveValid;
  const observedHealthy =
    configurationReady &&
    candidate.interfaceObservedUp &&
    candidate.endpoint !== null &&
    handshakeFresh;

  let reason = 'healthy';
  if (!candidate.candidateEnabled) reason = 'candidate disabled';
  else if (!candidate.clientEnabled) reason = 'client disabled';
  else if (!candidate.interfaceEnabled) reason = 'interface disabled';
  else if (!candidate.interfaceObservedUp) reason = 'interface is not up';
  else if (!keepaliveValid)
    reason = `persistent keepalive must be between 1 and ${maximumKeepalive} seconds`;
  else if (candidate.endpoint === null) reason = 'peer endpoint not observed';
  else if (!handshakeSeen) reason = 'no handshake observed';
  else if (!handshakeFresh) reason = 'handshake is stale';

  return {
    ...candidate,
    keepaliveValid,
    handshakeSeen,
    handshakeFresh,
    configurationReady,
    observedHealthy,
    explicitlyUnavailable,
    reason,
  };
}

export type ExitSelectionState = {
  selectedExitClientId: number | null;
  selectedSince: Date | null;
};

export type ExitSelectionResult = {
  selectedExitClientId: number | null;
  changed: boolean;
  reason: string;
  readiness: ExitReadiness[];
};

export function selectActiveExit({
  candidates,
  current,
  settings,
  now = new Date(),
}: {
  candidates: readonly ExitCandidateObservation[];
  current: ExitSelectionState;
  settings: ExitHealthSettings;
  now?: Date;
}): ExitSelectionResult {
  const readiness = candidates
    .map((candidate) => evaluateExitReadiness(candidate, settings, now))
    .sort(
      (left, right) =>
        left.priority - right.priority || left.clientId - right.clientId
    );
  const healthy = readiness.filter(({ observedHealthy }) => observedHealthy);
  const currentCandidate = readiness.find(
    ({ clientId }) => clientId === current.selectedExitClientId
  );
  const heldForMs = current.selectedSince
    ? now.getTime() - current.selectedSince.getTime()
    : Number.POSITIVE_INFINITY;
  const minimumHoldMet = heldForMs >= settings.minHoldSeconds * 1000;

  if (!currentCandidate) {
    const selectedExitClientId = healthy[0]?.clientId ?? null;
    return {
      selectedExitClientId,
      changed: selectedExitClientId !== current.selectedExitClientId,
      reason: selectedExitClientId
        ? 'selected highest-priority healthy exit'
        : 'no healthy exit candidate',
      readiness,
    };
  }

  if (currentCandidate.explicitlyUnavailable) {
    const selectedExitClientId = healthy[0]?.clientId ?? null;
    return {
      selectedExitClientId,
      changed: selectedExitClientId !== current.selectedExitClientId,
      reason: selectedExitClientId
        ? 'current exit became explicitly unavailable'
        : 'all exits are explicitly unavailable or unhealthy',
      readiness,
    };
  }

  if (!minimumHoldMet) {
    return {
      selectedExitClientId: currentCandidate.clientId,
      changed: false,
      reason: 'minimum active-exit hold is still in effect',
      readiness,
    };
  }

  if (!currentCandidate.observedHealthy) {
    const selectedExitClientId = healthy[0]?.clientId ?? null;
    return {
      selectedExitClientId,
      changed: selectedExitClientId !== current.selectedExitClientId,
      reason: selectedExitClientId
        ? 'current exit is unhealthy; failed over'
        : 'no healthy exit candidate',
      readiness,
    };
  }

  const recoveredHigherPriority = healthy.find((candidate) => {
    if (candidate.priority >= currentCandidate.priority) return false;
    if (!candidate.healthySince) return false;
    return (
      now.getTime() - candidate.healthySince.getTime() >=
      settings.failbackDelaySeconds * 1000
    );
  });
  if (recoveredHigherPriority) {
    return {
      selectedExitClientId: recoveredHigherPriority.clientId,
      changed: true,
      reason: 'higher-priority exit satisfied the failback delay',
      readiness,
    };
  }

  return {
    selectedExitClientId: currentCandidate.clientId,
    changed: false,
    reason: 'current exit remains selected',
    readiness,
  };
}

export type ObservedPolicyRule = {
  family: 4 | 6;
  priority: number;
  table: number;
  protocol?: number;
  fwmark?: number;
  mask?: number;
};

export type ObservedRoute = {
  family: 4 | 6;
  table: number;
  protocol?: number;
  prefix: string;
};

export type ObservedRoutingChain = {
  table: 'mangle' | 'nat';
  name: string;
  owner: 'wg-easy' | 'other';
};

export type ObservedMarkUse = {
  value: number;
  mask: number;
  owner: 'wg-easy' | 'other';
};

export type ObservedRoutingState = {
  policyRules: readonly ObservedPolicyRule[];
  routes: readonly ObservedRoute[];
  chains: readonly ObservedRoutingChain[];
  markUses: readonly ObservedMarkUse[];
};

export type OwnershipConflict = {
  kind: 'rule' | 'route' | 'chain' | 'mark';
  description: string;
};

function isRoutingTable(table: number) {
  return (
    table === SITE_TO_SITE_TABLE_ID ||
    (table >= ROUTING_TABLE_BASE + ROUTING_SLOT_MIN &&
      table <= ROUTING_TABLE_BASE + ROUTING_SLOT_MAX)
  );
}

function isRoutingPriority(priority: number) {
  return (
    priority === SITE_TO_SITE_PRIORITY ||
    (priority >= ROUTING_PRIORITY_BASE + ROUTING_SLOT_MIN &&
      priority <= ROUTING_GROUP_PRIORITY_MAX)
  );
}

export function routingMarkForSlot(slot: number) {
  if (slot < ROUTING_SLOT_MIN || slot > ROUTING_SLOT_MAX) {
    throw new Error(`Routing slot ${slot} is outside the owned range`);
  }
  return (FWMARK_NAMESPACE | (slot << 16)) >>> 0;
}

export function formatMark(mark: number) {
  return `0x${(mark >>> 0).toString(16).padStart(8, '0')}`;
}

function isExactOwnedRule(rule: ObservedPolicyRule) {
  if (rule.protocol !== WG_EASY_ROUTE_PROTOCOL) return false;
  if (
    rule.priority === SITE_TO_SITE_PRIORITY &&
    rule.table === SITE_TO_SITE_TABLE_ID &&
    rule.fwmark === undefined &&
    rule.mask === undefined
  ) {
    return true;
  }

  const slot = rule.priority - ROUTING_PRIORITY_BASE;
  return (
    slot >= ROUTING_SLOT_MIN &&
    slot <= ROUTING_SLOT_MAX &&
    rule.table === ROUTING_TABLE_BASE + slot &&
    rule.fwmark === routingMarkForSlot(slot) &&
    rule.mask === FWMARK_MASK
  );
}

export function preflightRoutingOwnership(observed: ObservedRoutingState): {
  ok: boolean;
  conflicts: OwnershipConflict[];
} {
  const conflicts: OwnershipConflict[] = [];

  for (const rule of observed.policyRules) {
    const touchesOwnedRange =
      isRoutingPriority(rule.priority) ||
      isRoutingTable(rule.table) ||
      (rule.mask !== undefined &&
        ((rule.mask >>> 0) & FWMARK_MASK) >>> 0 !== 0);
    if (touchesOwnedRange && !isExactOwnedRule(rule)) {
      conflicts.push({
        kind: 'rule',
        description: `non-owned policy rule uses priority ${rule.priority}, table ${rule.table}, or the wg-easy mark mask`,
      });
    }
  }

  for (const route of observed.routes) {
    if (
      isRoutingTable(route.table) &&
      route.protocol !== WG_EASY_ROUTE_PROTOCOL
    ) {
      conflicts.push({
        kind: 'route',
        description: `non-owned route ${route.prefix} occupies reserved table ${route.table}`,
      });
    }
  }

  for (const chain of observed.chains) {
    const reserved =
      (chain.table === 'mangle' && chain.name === ROUTING_MARK_CHAIN) ||
      (chain.table === 'nat' && chain.name === ROUTING_NAT_CHAIN);
    if (reserved && chain.owner !== 'wg-easy') {
      conflicts.push({
        kind: 'chain',
        description: `non-owned ${chain.table} chain ${chain.name} occupies a reserved name`,
      });
    }
  }

  for (const mark of observed.markUses) {
    if (
      mark.owner !== 'wg-easy' &&
      ((mark.mask >>> 0) & FWMARK_MASK) >>> 0 !== 0
    ) {
      conflicts.push({
        kind: 'mark',
        description: `non-owned packet mark ${formatMark(mark.value)}/${formatMark(mark.mask)} overlaps the wg-easy mask`,
      });
    }
  }

  return { ok: conflicts.length === 0, conflicts };
}

export type RoutingPlanInterface = {
  interfaceId: string;
  ipv4Cidr: string;
  enabled: boolean;
  observedUp: boolean;
};

export type RoutingPlanClient = ServerAllowedIpClient & {
  ipv4Address: string;
  enabled: boolean;
};

export type RoutingPlanGroup = {
  id: number;
  routingSlot: number;
  enabled: boolean;
  natEnabled: boolean;
  allExitsDownPolicy: AllExitsDownPolicy;
  routedIpv4Prefixes: readonly string[];
  memberClientIds: readonly number[];
  selectedExitClientId: number | null;
};

type CommandIntent = {
  executable: 'ip';
  args: string[];
};

type PlannedRoute = {
  family: 4 | 6;
  table: number;
  protocol: number;
  prefix: string;
  type: 'unicast' | 'unreachable';
  device?: string;
  command: CommandIntent;
};

type PlannedPolicyRule = {
  family: 4 | 6;
  priority: number;
  table: number;
  protocol: number;
  fwmark?: number;
  mask?: number;
  command: CommandIntent;
};

export type RoutingPlan = {
  executionAvailable: false;
  ownership: {
    routeProtocol: number;
    tableRange: [number, number];
    priorityRange: [number, number];
    siteToSiteTable: number;
    siteToSitePriority: number;
    fwmarkNamespace: number;
    fwmarkMask: number;
    markChain: string;
    natChain: string;
  };
  preflight:
    | { status: 'not_evaluated'; ok: null; conflicts: [] }
    | {
        status: 'passed' | 'conflict';
        ok: boolean;
        conflicts: OwnershipConflict[];
      };
  groups: {
    groupId: number;
    routingSlot: number;
    outcome: 'selected_exit' | 'block' | 'host' | 'disabled';
    selectedExitClientId: number | null;
    table: number;
    priority: number;
    fwmark: number;
  }[];
  parentMarkJumps: { interfaceId: string; args: string[] }[];
  markChainRules: string[][];
  natChainRules: string[][];
  routes: PlannedRoute[];
  policyRules: PlannedPolicyRule[];
  peerAllowedIps: { clientId: number; prefixes: string[] }[];
  warnings: string[];
};

function serverIpv4Address(cidr: string) {
  const parsed = parseRequiredCidr(cidr);
  if (parsed.version !== 4) throw new Error(`Expected an IPv4 CIDR: ${cidr}`);
  return stringifyIp({ number: parsed.start + 1n, version: 4 });
}

function routeCommand(route: Omit<PlannedRoute, 'command'>): CommandIntent {
  const args = [
    `-${route.family}`,
    'route',
    'replace',
    ...(route.type === 'unreachable' ? ['unreachable'] : []),
    route.prefix,
    ...(route.device ? ['dev', route.device] : []),
    'table',
    String(route.table),
    'proto',
    String(route.protocol),
  ];
  return { executable: 'ip', args };
}

function ruleCommand(rule: Omit<PlannedPolicyRule, 'command'>): CommandIntent {
  const args = [
    `-${rule.family}`,
    'rule',
    'add',
    ...(rule.fwmark !== undefined && rule.mask !== undefined
      ? ['fwmark', `${formatMark(rule.fwmark)}/${formatMark(rule.mask)}`]
      : []),
    'priority',
    String(rule.priority),
    'table',
    String(rule.table),
    'protocol',
    String(rule.protocol),
  ];
  return { executable: 'ip', args };
}

export function buildRoutingPlan({
  interfaces,
  clients,
  groups,
  observedState,
}: {
  interfaces: readonly RoutingPlanInterface[];
  clients: readonly RoutingPlanClient[];
  groups: readonly RoutingPlanGroup[];
  observedState?: ObservedRoutingState;
}): RoutingPlan {
  const serverAllowedIssues = findServerAllowedIpConflicts(clients);
  if (serverAllowedIssues.length > 0) {
    throw new RoutingValidationError(serverAllowedIssues);
  }
  const generatedRuleCount = groups
    .filter(({ enabled }) => enabled)
    .reduce(
      (total, group) =>
        total + group.memberClientIds.length * group.routedIpv4Prefixes.length,
      0
    );
  if (generatedRuleCount > schemaLimits.routingGlobalRuleLimit) {
    throw new RoutingValidationError([
      {
        code: 'global_rule_limit',
        message: `Routing plan would generate ${generatedRuleCount} member-prefix rules; the global limit is ${schemaLimits.routingGlobalRuleLimit}`,
      },
    ]);
  }

  const interfaceById = new Map(
    interfaces.map((wgInterface) => [wgInterface.interfaceId, wgInterface])
  );
  const clientById = new Map(clients.map((client) => [client.id, client]));
  const sortedGroups = [...groups].sort(
    (left, right) => left.routingSlot - right.routingSlot || left.id - right.id
  );
  const routingSlots = new Set<number>();
  for (const group of sortedGroups) {
    if (routingSlots.has(group.routingSlot)) {
      throw new Error(
        `Routing slot ${group.routingSlot} is assigned more than once`
      );
    }
    routingSlots.add(group.routingSlot);
    if (
      group.enabled &&
      (group.memberClientIds.length === 0 ||
        group.routedIpv4Prefixes.length === 0)
    ) {
      throw new RoutingValidationError([
        {
          code: 'enabled_group_incomplete',
          message: `Routing group ${group.id} is enabled but has no members or prefixes`,
          groupIds: [group.id],
        },
      ]);
    }
  }
  const routes: PlannedRoute[] = [];
  const policyRules: PlannedPolicyRule[] = [];
  const markChainRules: string[][] = [];
  const natChainRules: string[][] = [];
  const peerPrefixes = new Map<number, Set<string>>();
  const warnings: string[] = [];
  let groupMarkRuleCount = 0;

  const enabledInterfaces = [...interfaces]
    .filter(({ enabled, observedUp }) => enabled && observedUp)
    .sort((left, right) => left.interfaceId.localeCompare(right.interfaceId));
  for (const wgInterface of [...interfaces].sort((left, right) =>
    left.interfaceId.localeCompare(right.interfaceId)
  )) {
    markChainRules.push([
      '-A',
      ROUTING_MARK_CHAIN,
      '-d',
      normalizeCidr(wgInterface.ipv4Cidr),
      '-j',
      'RETURN',
    ]);
  }

  const groupPlans: RoutingPlan['groups'] = [];
  for (const group of sortedGroups) {
    const table = ROUTING_TABLE_BASE + group.routingSlot;
    const priority = ROUTING_PRIORITY_BASE + group.routingSlot;
    const fwmark = routingMarkForSlot(group.routingSlot);
    if (!group.enabled) {
      groupPlans.push({
        groupId: group.id,
        routingSlot: group.routingSlot,
        outcome: 'disabled',
        selectedExitClientId: null,
        table,
        priority,
        fwmark,
      });
      continue;
    }

    const prefixes = [
      ...new Set(
        group.routedIpv4Prefixes.map((prefix) => normalizeCidr(prefix))
      ),
    ].sort((left, right) => left.localeCompare(right));
    for (const prefix of prefixes) {
      if (parseRequiredCidr(prefix).version !== 4) {
        throw new Error(
          `Routing group ${group.id} contains non-IPv4 prefix ${prefix}`
        );
      }
    }
    const memberIds = [...new Set(group.memberClientIds)];
    for (const memberId of memberIds) {
      if (!clientById.has(memberId)) {
        throw new Error(
          `Routing group ${group.id} references unknown member ${memberId}`
        );
      }
    }
    const members = memberIds
      .map((clientId) => clientById.get(clientId)!)
      .filter((client): client is RoutingPlanClient => Boolean(client?.enabled))
      .sort((left, right) => left.id - right.id);
    const selectedExit = group.selectedExitClientId
      ? clientById.get(group.selectedExitClientId)
      : undefined;
    let outcome: 'selected_exit' | 'block' | 'host';

    if (selectedExit) {
      const exitInterface = interfaceById.get(selectedExit.interfaceId);
      if (!exitInterface) {
        throw new Error(
          `Selected exit ${selectedExit.id} references an unknown interface`
        );
      }
      if (
        !selectedExit.enabled ||
        !exitInterface.enabled ||
        !exitInterface.observedUp
      ) {
        throw new Error(
          `Selected exit ${selectedExit.id} is not enabled on an observed-up interface`
        );
      }
      outcome = 'selected_exit';
      for (const prefix of prefixes) {
        const routeBase = {
          family: 4 as const,
          table,
          protocol: WG_EASY_ROUTE_PROTOCOL,
          prefix,
          type: 'unicast' as const,
          device: exitInterface.interfaceId,
        };
        routes.push({ ...routeBase, command: routeCommand(routeBase) });
      }
      const assigned = peerPrefixes.get(selectedExit.id) ?? new Set<string>();
      prefixes.forEach((prefix) => assigned.add(prefix));
      peerPrefixes.set(selectedExit.id, assigned);

      if (group.natEnabled) {
        const source = serverIpv4Address(exitInterface.ipv4Cidr);
        natChainRules.push([
          '-A',
          ROUTING_NAT_CHAIN,
          '-m',
          'mark',
          '--mark',
          `${formatMark(fwmark)}/${formatMark(FWMARK_MASK)}`,
          '-o',
          exitInterface.interfaceId,
          '-j',
          'SNAT',
          '--to-source',
          source,
        ]);
      }
    } else if (group.allExitsDownPolicy === 'block') {
      outcome = 'block';
      for (const prefix of prefixes) {
        const routeBase = {
          family: 4 as const,
          table,
          protocol: WG_EASY_ROUTE_PROTOCOL,
          prefix,
          type: 'unreachable' as const,
        };
        routes.push({ ...routeBase, command: routeCommand(routeBase) });
      }
    } else {
      outcome = 'host';
      warnings.push(
        `Routing group ${group.id} has no selected exit and will use host routing`
      );
    }

    if (outcome !== 'host') {
      const ruleBase = {
        family: 4 as const,
        priority,
        table,
        protocol: WG_EASY_ROUTE_PROTOCOL,
        fwmark,
        mask: FWMARK_MASK,
      };
      policyRules.push({ ...ruleBase, command: ruleCommand(ruleBase) });
      for (const member of members) {
        for (const prefix of prefixes) {
          markChainRules.push([
            '-A',
            ROUTING_MARK_CHAIN,
            '-s',
            `${member.ipv4Address}/32`,
            '-d',
            prefix,
            '-m',
            'comment',
            '--comment',
            `wg-easy route group ${group.id}`,
            '-j',
            'MARK',
            '--set-xmark',
            `${formatMark(fwmark)}/${formatMark(FWMARK_MASK)}`,
          ]);
          groupMarkRuleCount += 1;
        }
      }
    }

    groupPlans.push({
      groupId: group.id,
      routingSlot: group.routingSlot,
      outcome,
      selectedExitClientId: selectedExit?.id ?? null,
      table,
      priority,
      fwmark,
    });
  }

  const siteRoutesByFamily = new Map<4 | 6, number>();
  for (const client of [...clients].sort((left, right) => left.id - right.id)) {
    const wgInterface = interfaceById.get(client.interfaceId);
    if (!client.enabled || !wgInterface?.enabled) continue;
    for (const prefix of canonicalizeServerAllowedIps(
      client.serverAllowedIps
    ).sort((left, right) => left.localeCompare(right))) {
      const family = parseRequiredCidr(prefix).version;
      const routeBase = {
        family,
        table: SITE_TO_SITE_TABLE_ID,
        protocol: WG_EASY_ROUTE_PROTOCOL,
        prefix,
        type: 'unicast' as const,
        device: client.interfaceId,
      };
      routes.push({ ...routeBase, command: routeCommand(routeBase) });
      siteRoutesByFamily.set(family, (siteRoutesByFamily.get(family) ?? 0) + 1);
    }
  }
  for (const family of [...siteRoutesByFamily.keys()].sort()) {
    const ruleBase = {
      family,
      priority: SITE_TO_SITE_PRIORITY,
      table: SITE_TO_SITE_TABLE_ID,
      protocol: WG_EASY_ROUTE_PROTOCOL,
    };
    policyRules.push({ ...ruleBase, command: ruleCommand(ruleBase) });
  }

  const parentMarkJumps =
    groupMarkRuleCount === 0
      ? []
      : enabledInterfaces.map(({ interfaceId }) => ({
          interfaceId,
          args: [
            '-A',
            'PREROUTING',
            '-i',
            interfaceId,
            '-j',
            ROUTING_MARK_CHAIN,
          ],
        }));
  const preflightResult = observedState
    ? preflightRoutingOwnership(observedState)
    : undefined;

  return {
    executionAvailable: false,
    ownership: {
      routeProtocol: WG_EASY_ROUTE_PROTOCOL,
      tableRange: [
        ROUTING_TABLE_BASE + ROUTING_SLOT_MIN,
        ROUTING_TABLE_BASE + ROUTING_SLOT_MAX,
      ],
      priorityRange: [
        ROUTING_PRIORITY_BASE + ROUTING_SLOT_MIN,
        ROUTING_GROUP_PRIORITY_MAX,
      ],
      siteToSiteTable: SITE_TO_SITE_TABLE_ID,
      siteToSitePriority: SITE_TO_SITE_PRIORITY,
      fwmarkNamespace: FWMARK_NAMESPACE,
      fwmarkMask: FWMARK_MASK,
      markChain: ROUTING_MARK_CHAIN,
      natChain: ROUTING_NAT_CHAIN,
    },
    preflight: preflightResult
      ? {
          status: preflightResult.ok ? 'passed' : 'conflict',
          ...preflightResult,
        }
      : { status: 'not_evaluated', ok: null, conflicts: [] },
    groups: groupPlans,
    parentMarkJumps,
    markChainRules,
    natChainRules,
    routes,
    policyRules,
    peerAllowedIps: [...peerPrefixes]
      .sort(([left], [right]) => left - right)
      .map(([clientId, prefixes]) => ({
        clientId,
        prefixes: [...prefixes].sort((left, right) =>
          left.localeCompare(right)
        ),
      })),
    warnings,
  };
}
