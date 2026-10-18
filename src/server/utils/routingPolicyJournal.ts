import { normalizeCidr, parseCidr } from 'cidr-tools';
import { isIPv4 } from 'is-ip';
import z from 'zod';

import { buildRoutingGuard } from '#server/utils/routingGuard';
import { isRoutingPolicyBackupReference } from '#server/utils/routingPolicyBackups';
import { POLICY_LIMITS, policyRangeCidrs } from '#server/utils/routingPolicy';
import { routingPolicyRuntimeFingerprint } from '#server/utils/routingPolicyRuntime';
import {
  InterfaceNameSchema,
  Ipv4CidrSchema,
  RoutingSlotSchema,
} from '#shared/utils/schemas';
import type {
  AppliedRoutingPolicyPlan,
  PendingPolicyTransition,
  RoutingPolicyJournal,
} from '#shared/types/routingPolicy';

export class RoutingPolicyJournalError extends Error {
  constructor(readonly code: string) {
    super(`Routing policy recovery: ${code}`);
    this.name = 'RoutingPolicyJournalError';
  }
}
const id = z.number().int().positive().max(Number.MAX_SAFE_INTEGER);
const address = z.string().refine(isIPv4);
const prefix = (family?: 4 | 6) =>
  z.string().refine((value) => {
    try {
      const parsed = parseCidr(value);
      return (
        parsed.prefixPresent &&
        (!family || parsed.version === family) &&
        normalizeCidr(value) === value
      );
    } catch {
      return false;
    }
  });
const fingerprint = z.string().regex(/^[0-9a-f]{64}$/);
const source = z.strictObject({
  clientId: id,
  interfaceId: InterfaceNameSchema,
  ipv4Address: address,
});
const branch = z.strictObject({
  prefix: prefix(4),
  groupId: id,
  action: z.enum(['exit', 'block', 'host']),
});
const planSchema = z.strictObject({
  version: z.literal(2),
  interfaces: z.array(
    z.strictObject({
      interfaceId: InterfaceNameSchema,
      ipv4Cidr: Ipv4CidrSchema,
      enabled: z.boolean(),
    })
  ),
  siteRoutes: z.array(
    z.strictObject({
      interfaceId: InterfaceNameSchema,
      prefixes: z.array(prefix()),
    })
  ),
  bypassPrefixes: z.array(prefix(4)),
  programs: z.array(
    z.strictObject({
      sources: z.array(source).min(1).max(POLICY_LIMITS.members),
      branches: z.array(branch),
    })
  ),
  groups: z
    .array(
      z.strictObject({
        id,
        routingSlot: RoutingSlotSchema,
        enabled: z.boolean(),
        allExitsDownPolicy: z.enum(['block', 'host']),
        natEnabled: z.boolean(),
        selectedExitClientId: id.nullable(),
        exitInterfaceId: InterfaceNameSchema.nullable(),
        serverIpv4Address: address.nullable(),
        effectivePrefixes: z.array(prefix(4)),
      })
    )
    .max(POLICY_LIMITS.groups),
  peers: z.array(
    z.strictObject({
      clientId: id,
      interfaceId: InterfaceNameSchema,
      peerId: fingerprint,
      prefixes: z.array(prefix()).min(1),
    })
  ),
});
const journalSchema = z.strictObject({
  revision: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  fingerprint,
  plan: planSchema,
});
const guardScope = z.strictObject({
  direction: z.enum(['input', 'forward', 'output']),
  inputInterface: InterfaceNameSchema.optional(),
  outputInterface: InterfaceNameSchema.optional(),
  source: prefix(4),
  destination: prefix(4),
});
const pendingSchema = journalSchema.extend({
  stage: z.enum([
    'prepared',
    'guarded',
    'peers',
    'classified',
    'verified',
    'restoring',
  ]),
  guardScopes: z.array(guardScope).max(POLICY_LIMITS.guardRules),
  backupBasenames: z
    .array(z.string().refine(isRoutingPolicyBackupReference))
    .min(1)
    .max(1),
  errorCode: z
    .string()
    .regex(/^[a-z][a-z0-9_]{0,95}$/)
    .nullable(),
});
function fail(): never {
  throw new RoutingPolicyJournalError('invalid_record');
}
function unique<T>(values: readonly T[]) {
  return new Set(values).size === values.length;
}
function ranges(prefixes: readonly string[]) {
  return prefixes.map((value) => {
    const parsed = parseCidr(value);
    return { start: Number(parsed.start), end: Number(parsed.end) + 1 };
  });
}
function validatePlan(plan: AppliedRoutingPolicyPlan) {
  const dispatch = plan.programs.reduce((n, p) => n + p.sources.length, 0),
    branches = plan.programs.reduce((n, p) => n + p.branches.length, 0),
    scaffold =
      plan.programs.length +
      plan.bypassPrefixes.length +
      plan.interfaces.length +
      3;
  if (
    dispatch + branches > POLICY_LIMITS.dispatch ||
    dispatch + 2 * branches + scaffold > POLICY_LIMITS.classifierRules ||
    scaffold > 4096
  )
    fail();
  const interfaces = new Map(plan.interfaces.map((i) => [i.interfaceId, i]));
  const groups = new Map(plan.groups.map((g) => [g.id, g]));
  const peers = new Map(plan.peers.map((p) => [p.clientId, p]));
  if (
    JSON.stringify(
      policyRangeCidrs(ranges(plan.interfaces.map((i) => i.ipv4Cidr)))
    ) !== JSON.stringify(plan.bypassPrefixes)
  )
    fail();
  if (
    interfaces.size !== plan.interfaces.length ||
    groups.size !== plan.groups.length ||
    peers.size !== plan.peers.length ||
    !unique(plan.groups.map((g) => g.routingSlot)) ||
    !unique(plan.peers.map((p) => p.peerId))
  )
    fail();
  for (const peer of plan.peers)
    if (!interfaces.get(peer.interfaceId)?.enabled || !unique(peer.prefixes))
      fail();
  for (const route of plan.siteRoutes) {
    if (
      !interfaces.get(route.interfaceId)?.enabled ||
      !unique(route.prefixes) ||
      route.prefixes.some((p) => Number(parseCidr(p).prefix) === 0)
    )
      fail();
  }
  const sourceKeys = new Set<string>(),
    sourceIds = new Set<number>(),
    byGroup = new Map<number, string[]>();
  for (const program of plan.programs) {
    const ordered = program.branches
      .map((b) => ({ ...ranges([b.prefix])[0]!, branch: b }))
      .sort((a, b) => a.start - b.start);
    for (let i = 1; i < ordered.length; i++)
      if (ordered[i]!.start < ordered[i - 1]!.end) fail();
    for (const member of program.sources) {
      const key = JSON.stringify([member.interfaceId, member.ipv4Address]),
        iface = interfaces.get(member.interfaceId);
      if (sourceKeys.has(key) || sourceIds.has(member.clientId) || !iface)
        fail();
      sourceKeys.add(key);
      sourceIds.add(member.clientId);
      const network = parseCidr(iface.ipv4Cidr),
        ip = parseCidr(`${member.ipv4Address}/32`).start;
      if (ip < network.start + 2n || ip >= network.end) fail();
      if (iface.enabled) {
        const peer = peers.get(member.clientId);
        if (
          !peer ||
          peer.interfaceId !== member.interfaceId ||
          !peer.prefixes.includes(`${member.ipv4Address}/32`)
        )
          fail();
      }
    }
    for (const b of program.branches) {
      const group = groups.get(b.groupId);
      if (!group?.enabled) fail();
      if (
        b.action === 'exit'
          ? group.selectedExitClientId === null
          : group.selectedExitClientId !== null ||
            b.action !== group.allExitsDownPolicy
      )
        fail();
      const list = byGroup.get(b.groupId) ?? [];
      list.push(b.prefix);
      byGroup.set(b.groupId, list);
      const r = parseCidr(b.prefix);
      for (const bypass of plan.bypassPrefixes) {
        const p = parseCidr(bypass);
        if (r.start <= p.end && p.start <= r.end) fail();
      }
    }
  }
  for (const group of plan.groups) {
    const selected = group.selectedExitClientId;
    if (selected === null) {
      if (group.exitInterfaceId !== null || group.serverIpv4Address !== null)
        fail();
    } else {
      const peer = peers.get(selected),
        iface = group.exitInterfaceId
          ? interfaces.get(group.exitInterfaceId)
          : undefined;
      if (
        !group.enabled ||
        !peer ||
        peer.interfaceId !== group.exitInterfaceId ||
        !iface?.enabled ||
        parseCidr(`${group.serverIpv4Address}/32`).start !==
          parseCidr(iface.ipv4Cidr).start + 1n ||
        group.effectivePrefixes.some((p) => !peer.prefixes.includes(p))
      )
        fail();
    }
    if (!group.enabled && group.effectivePrefixes.length) fail();
    if (
      JSON.stringify(policyRangeCidrs(ranges(byGroup.get(group.id) ?? []))) !==
      JSON.stringify(group.effectivePrefixes)
    )
      fail();
  }
}

/** Strict non-secret shape and semantic validation before recovery touches Linux. */
export function parseRoutingPolicyJournal(
  value: unknown
): RoutingPolicyJournal {
  try {
    const result = journalSchema.safeParse(value);
    if (!result.success) fail();
    validatePlan(result.data.plan);
    if (
      routingPolicyRuntimeFingerprint(result.data.plan) !==
      result.data.fingerprint
    )
      fail();
    return result.data;
  } catch {
    throw new RoutingPolicyJournalError('invalid_record');
  }
}
export function parsePendingPolicyTransition(
  value: unknown
): PendingPolicyTransition {
  try {
    const result = pendingSchema.safeParse(value);
    if (!result.success) fail();
    const { stage, guardScopes, backupBasenames, errorCode, ...journal } =
      result.data;
    const parsed = parseRoutingPolicyJournal(journal);
    const guard = buildRoutingGuard(guardScopes, { protectedPaths: [] });
    if (
      JSON.stringify(guard.scopes) !== JSON.stringify(guardScopes) ||
      !unique(backupBasenames) ||
      (stage === 'restoring' ? errorCode === null : errorCode !== null)
    )
      fail();
    return { ...parsed, stage, guardScopes, backupBasenames, errorCode };
  } catch {
    throw new RoutingPolicyJournalError('invalid_pending_transition');
  }
}
