import { normalizeCidr, parseCidr } from 'cidr-tools';
import { isIPv4, isIPv6 } from 'is-ip';
import z from 'zod';

import { buildRoutingGuard } from '#server/utils/routingGuard';
import { ClientFirewallPolicySchema } from '#server/utils/clientFirewallPolicy';
import { isRoutingPolicyBackupReference } from '#server/utils/routingPolicyBackups';
import { POLICY_LIMITS, policyRangeCidrs } from '#server/utils/routingPolicy';
import {
  routingPolicyRuntimeFingerprint,
  specializeRoutingPolicy,
} from '#server/utils/routingPolicyRuntime';
import { buildRoutingPlan } from '#server/utils/routing';
import { RoutingKernelNamespaceSchema } from '#server/utils/routingPolicyKernelContext';
import {
  InterfaceNameSchema,
  Ipv4CidrSchema,
  RoutingSlotSchema,
} from '#shared/utils/schemas';
import type {
  AppliedRoutingPolicyPlan,
  PendingPolicyTransition,
  RoutingPolicyJournal,
  PolicyBootstrapBaseline,
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
  namespaceId: RoutingKernelNamespaceSchema.optional(),
  clientFirewall: ClientFirewallPolicySchema,
  interfaces: z.array(
    z.strictObject({
      interfaceId: InterfaceNameSchema,
      ipv4Cidr: Ipv4CidrSchema,
      enabled: z.boolean(),
      observedUp: z.boolean(),
      hooksApplied: z.boolean().optional(),
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
  source: prefix(),
  destination: prefix(),
});
const bootstrapSchema = z.strictObject({
  interfaces: planSchema.shape.interfaces,
  clients: z.array(
    z.strictObject({
      id,
      interfaceId: InterfaceNameSchema,
      ipv4Address: address,
      ipv6Address: z.string().refine(isIPv6).nullable(),
      enabled: z.boolean(),
      serverAllowedIps: z.array(prefix()),
    })
  ),
  groups: z
    .array(
      z.strictObject({
        id,
        routingSlot: RoutingSlotSchema,
        enabled: z.boolean(),
        natEnabled: z.boolean(),
        allExitsDownPolicy: z.enum(['block', 'host']),
        routedIpv4Prefixes: z.array(prefix(4)).max(POLICY_LIMITS.prefixes),
        memberClientIds: z.array(id).max(POLICY_LIMITS.members),
        selectedExitClientId: id.nullable(),
      })
    )
    .max(POLICY_LIMITS.groups),
  peers: planSchema.shape.peers,
});
const pendingSchema = journalSchema.extend({
  bootstrap: bootstrapSchema.optional(),
  withdrawal: z
    .strictObject({
      unavailableInterfaceIds: z.array(InterfaceNameSchema).min(1),
      resetNamespace: z.boolean(),
    })
    .optional(),
  supersededGuardScopes: z
    .array(guardScope)
    .max(POLICY_LIMITS.guardRules)
    .optional(),
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
  for (const iface of plan.interfaces)
    if (
      (iface.observedUp && (!iface.enabled || iface.hooksApplied === false)) ||
      (iface.hooksApplied && !iface.enabled) ||
      (plan.namespaceId !== undefined && iface.hooksApplied === undefined)
    )
      fail();
  for (const iface of plan.clientFirewall.interfaces)
    if (!interfaces.get(iface.interfaceId)?.observedUp) fail();
  for (const entry of plan.clientFirewall.entries) {
    const peer = peers.get(entry.clientId);
    if (
      !peer ||
      peer.interfaceId !== entry.interfaceId ||
      !peer.prefixes.includes(
        normalizeCidr(`${entry.source}/${entry.family === 4 ? 32 : 128}`)
      )
    )
      fail();
  }
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
    if (!interfaces.get(peer.interfaceId)?.observedUp || !unique(peer.prefixes))
      fail();
  for (const route of plan.siteRoutes) {
    if (
      !interfaces.get(route.interfaceId)?.observedUp ||
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
      if (iface.observedUp) {
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
        !iface?.observedUp ||
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

/** The bridge can only replace the same fully converged v1 generation. */
function validateBootstrap(
  baseline: PolicyBootstrapBaseline,
  target: RoutingPolicyJournal
) {
  if (
    !unique(baseline.clients.map((c) => c.id)) ||
    !unique(baseline.groups.flatMap((g) => g.memberClientIds)) ||
    !unique(baseline.peers.map((p) => p.clientId)) ||
    !unique(baseline.peers.map((p) => p.peerId))
  )
    fail();
  const byId = new Map(target.plan.peers.map((p) => [p.clientId, p]));
  // Synthetic identities are used only to reconstruct the non-secret semantics;
  // the actual historical peer identities are independently checked below.
  const reconstructed = specializeRoutingPolicy(
    {
      interfaces: baseline.interfaces,
      clients: baseline.clients.map((c) => ({
        ...c,
        name: '',
        publicKey: `profile-${c.id}`,
      })),
      groups: baseline.groups.map((g) => ({
        ...g,
        name: '',
        exits:
          g.selectedExitClientId === null
            ? []
            : [
                {
                  clientId: g.selectedExitClientId,
                  enabled: true,
                  priority: 0,
                },
              ],
      })),
    },
    {
      selectedExitClientIds: new Map(
        baseline.groups.map((g) => [g.id, g.selectedExitClientId])
      ),
      enabledInterfaceIds: new Set(
        baseline.interfaces.filter((i) => i.enabled).map((i) => i.interfaceId)
      ),
      upInterfaceIds: new Set(
        baseline.interfaces
          .filter((i) => i.observedUp)
          .map((i) => i.interfaceId)
      ),
      enableIpv6: target.plan.clientFirewall.enableIpv6,
      clientFirewall: target.plan.clientFirewall,
      ...(target.plan.namespaceId !== undefined
        ? { namespaceId: target.plan.namespaceId }
        : {}),
      ...(target.plan.interfaces.some((i) => i.hooksApplied !== undefined)
        ? {
            hooksAppliedInterfaceIds: new Set(
              target.plan.interfaces
                .filter((i) => i.hooksApplied)
                .map((i) => i.interfaceId)
            ),
          }
        : {}),
    }
  ).plan;
  for (const p of reconstructed.peers) {
    const actual = byId.get(p.clientId);
    if (!actual || actual.interfaceId !== p.interfaceId) fail();
    p.peerId = actual.peerId;
  }
  if (routingPolicyRuntimeFingerprint(reconstructed) !== target.fingerprint)
    fail();
  const linux = buildRoutingPlan(baseline);
  const additions = new Map(
    linux.peerAllowedIps.map((p) => [p.clientId, p.prefixes])
  );
  const clients = new Map(baseline.clients.map((c) => [c.id, c]));
  if (baseline.peers.length !== target.plan.peers.length) fail();
  for (const peer of baseline.peers) {
    const client = clients.get(peer.clientId),
      expected = byId.get(peer.clientId);
    if (
      !client ||
      !expected ||
      peer.peerId !== expected.peerId ||
      peer.interfaceId !== expected.interfaceId
    )
      fail();
    const prefixes = [
      ...new Set(
        [
          `${client.ipv4Address}/32`,
          ...(target.plan.clientFirewall.enableIpv6 && client.ipv6Address
            ? [`${client.ipv6Address}/128`]
            : []),
          ...client.serverAllowedIps,
          ...(additions.get(client.id) ?? []),
        ].map((value) => normalizeCidr(value))
      ),
    ].sort();
    if (JSON.stringify(peer.prefixes) !== JSON.stringify(prefixes)) fail();
  }
}

export function parsePolicyBootstrapBaseline(
  value: unknown,
  target: RoutingPolicyJournal
): PolicyBootstrapBaseline {
  try {
    const parsed = bootstrapSchema.parse(value);
    validateBootstrap(parsed, target);
    return parsed;
  } catch {
    throw new RoutingPolicyJournalError('invalid_bootstrap_baseline');
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
    const {
      bootstrap,
      withdrawal,
      supersededGuardScopes,
      stage,
      guardScopes,
      backupBasenames,
      errorCode,
      ...journal
    } = result.data;
    const parsed = parseRoutingPolicyJournal(journal);
    if (bootstrap) parsePolicyBootstrapBaseline(bootstrap, parsed);
    if (withdrawal) {
      const unavailable = withdrawal.unavailableInterfaceIds;
      if (
        bootstrap ||
        !parsed.plan.namespaceId ||
        !unique(unavailable) ||
        JSON.stringify(unavailable) !==
          JSON.stringify([...unavailable].sort()) ||
        unavailable.some(
          (id) =>
            !parsed.plan.interfaces.some(
              (i) => i.interfaceId === id && !i.observedUp
            )
        ) ||
        (withdrawal.resetNamespace &&
          (unavailable.length !== parsed.plan.interfaces.length ||
            parsed.plan.interfaces.some((i) => i.hooksApplied !== false)))
      )
        fail();
    }
    const guard = buildRoutingGuard(guardScopes, { protectedPaths: [] });
    if (supersededGuardScopes) {
      const superseded = buildRoutingGuard(supersededGuardScopes, {
        protectedPaths: [],
      });
      if (
        !withdrawal?.resetNamespace ||
        JSON.stringify(superseded.scopes) !==
          JSON.stringify(supersededGuardScopes)
      )
        fail();
    }
    if (
      JSON.stringify(guard.scopes) !== JSON.stringify(guardScopes) ||
      !unique(backupBasenames) ||
      (stage === 'restoring' ? errorCode === null : errorCode !== null)
    )
      fail();
    return {
      ...parsed,
      ...(bootstrap ? { bootstrap } : {}),
      ...(withdrawal ? { withdrawal } : {}),
      ...(supersededGuardScopes ? { supersededGuardScopes } : {}),
      stage,
      guardScopes,
      backupBasenames,
      errorCode,
    };
  } catch {
    throw new RoutingPolicyJournalError('invalid_pending_transition');
  }
}
