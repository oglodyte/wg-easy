import { eq, lte } from 'drizzle-orm';

import {
  routingGroup,
  routingGroupExit,
  routingGroupMember,
  routingGroupRuntimeState,
  routingSlotTombstone,
} from './schema';
import type {
  RoutingGroupAggregate,
  RoutingGroupInput,
  RoutingGroupRuntimeStateType,
  RoutingGroupType,
  RoutingGroupSaveConditions,
  RoutingGroupPreviewInput,
} from './types';
import { RoutingGroupPreviewSchema } from './types';

import type { ClientType } from '#db/repositories/client/types';
import { bumpDesiredRevision } from '#db/repositories/runtime/service';
import { readProposedRoutingState } from '#db/repositories/runtime/policySnapshot';
import { readRoutingPolicyStateInTransaction } from '#db/repositories/runtime/policyService';
import type { DBType } from '#db/sqlite';
import {
  ROUTING_SLOT_MAX,
  ROUTING_SLOT_MIN,
  RoutingValidationError,
  findRoutingPrefixConflicts,
  findServerAllowedIpConflicts,
  type RoutingConflictGroup,
  type RoutingValidationIssue,
} from '#server/utils/routing';
import { RoutingGroupSchema, schemaLimits } from '#shared/utils/schemas';
import { assertRoutingPolicyVersion1 } from '#server/utils/routingPolicyValidation';
import {
  compileRoutingPolicy,
  PolicyValidationError,
} from '#server/utils/routingPolicy';
import {
  explainCompiledRoutingPolicy,
  compiledRoutingWinnerExamples,
} from '#server/utils/routingPolicyPreview';

const ROUTING_EXECUTION_PENDING =
  'Routing execution is waiting for runtime reconciliation and verification.';

type QueryDatabase = Pick<DBType, 'query'>;

type ValidationState = Awaited<ReturnType<typeof loadValidationState>>;

export class RoutingPolicyRevisionConflictError extends Error {
  constructor(readonly desiredRevision: number) {
    super('Routing policy changed; refresh the preview before saving');
  }
}
async function assertSaveConditions(
  database: QueryDatabase,
  conditions: RoutingGroupSaveConditions
) {
  if (
    conditions.expectedDesiredRevision === undefined &&
    conditions.expectedDesiredFingerprint === undefined
  )
    return;
  const runtime = await database.query.runtimeReconciliationState
    .findFirst()
    .execute();
  if (!runtime) throw new Error('Runtime reconciliation state not found');
  if (
    conditions.expectedDesiredRevision !== undefined &&
    conditions.expectedDesiredRevision !== runtime.desiredRevision
  )
    throw new RoutingPolicyRevisionConflictError(runtime.desiredRevision);
  if (conditions.expectedDesiredFingerprint !== undefined) {
    const { snapshot } = await readProposedRoutingState(database);
    if (
      compileRoutingPolicy(snapshot).fingerprint !==
      conditions.expectedDesiredFingerprint
    )
      throw new RoutingPolicyRevisionConflictError(runtime.desiredRevision);
  }
}

async function loadValidationState(database: QueryDatabase) {
  const [groups, exits, members, clients, interfaces, runtime, tombstones] =
    await Promise.all([
      database.query.routingGroup.findMany().execute(),
      database.query.routingGroupExit.findMany().execute(),
      database.query.routingGroupMember.findMany().execute(),
      database.query.client.findMany().execute(),
      database.query.wgInterface.findMany().execute(),
      database.query.routingGroupRuntimeState.findMany().execute(),
      database.query.routingSlotTombstone.findMany().execute(),
    ]);
  const general = await database.query.general.findFirst().execute();
  if (!general) throw new Error('General Config not found');
  if (general.routingPolicyVersion !== 2)
    assertRoutingPolicyVersion1(general.routingPolicyVersion);
  // The Phase 1 runtime cannot safely interpret advanced rows written by a
  // different image or manual SQL. Fail before constructing a baseline plan.
  if (
    general.routingPolicyVersion === 1 &&
    groups.some((group) => group.excludedIpv4Prefixes.length > 0)
  ) {
    throw new RoutingValidationError([
      {
        code: 'routing_policy_unavailable',
        message: 'Excluded routing policies are unavailable in this image.',
      },
    ]);
  }
  const assigned = new Set<number>();
  for (const member of members) {
    if (general.routingPolicyVersion === 1 && assigned.has(member.clientId))
      throw new RoutingValidationError([
        {
          code: 'routing_policy_unavailable',
          message:
            'Multiple routing memberships are unavailable in this image.',
        },
      ]);
    assigned.add(member.clientId);
  }
  return {
    groups,
    exits,
    members,
    clients,
    interfaces,
    runtime,
    tombstones,
    general,
  };
}

function persistedGroupInput(
  group: RoutingGroupType,
  state: Pick<ValidationState, 'exits' | 'members'>
): RoutingGroupInput {
  return {
    name: group.name,
    enabled: group.enabled,
    exits: state.exits
      .filter(({ groupId }) => groupId === group.id)
      .sort(
        (left, right) =>
          left.priority - right.priority || left.clientId - right.clientId
      )
      .map(({ clientId, priority, enabled }) => ({
        clientId,
        priority,
        enabled,
      })),
    natEnabled: group.natEnabled,
    allExitsDownPolicy: group.allExitsDownPolicy,
    routedIpv4Prefixes: group.routedIpv4Prefixes,
    excludedIpv4Prefixes: group.excludedIpv4Prefixes,
    memberClientIds: state.members
      .filter(({ groupId }) => groupId === group.id)
      .map(({ clientId }) => clientId)
      .sort((left, right) => left - right),
  };
}

function toConflictGroup(
  id: number,
  input: RoutingGroupInput,
  enabled = input.enabled
): RoutingConflictGroup {
  return {
    id,
    enabled,
    routedIpv4Prefixes: input.routedIpv4Prefixes,
    exits: input.exits.map(({ clientId, enabled: exitEnabled }) => ({
      clientId,
      enabled: exitEnabled,
    })),
  };
}

function clientReference(state: ValidationState, clientId: number) {
  const client = state.clients.find(({ id }) => id === clientId);
  return client
    ? `client “${client.name}” (#${client.id})`
    : `client #${clientId}`;
}

function groupReference(
  state: ValidationState,
  groupId: number,
  prospectiveGroupName?: string
) {
  if (groupId === 0 && prospectiveGroupName) {
    return `new routing group “${prospectiveGroupName}”`;
  }
  const group = state.groups.find(({ id }) => id === groupId);
  return group
    ? `routing group “${group.name}” (#${group.id})`
    : `routing group #${groupId}`;
}

function formatRoutingIssue(
  state: ValidationState,
  issue: RoutingValidationIssue,
  prospectiveGroupName?: string
) {
  const [firstClientId, secondClientId] = issue.clientIds ?? [];
  const [firstGroupId, secondGroupId] = issue.groupIds ?? [];
  const [firstPrefix, secondPrefix] = issue.prefixes ?? [];

  switch (issue.code) {
    case 'client_not_found':
      return `Routing group references missing ${clientReference(
        state,
        firstClientId!
      )}`;
    case 'member_already_assigned':
      return `${clientReference(state, firstClientId!)} already belongs to ${groupReference(state, firstGroupId!, prospectiveGroupName)}`;
    case 'exit_keepalive_invalid':
      return `Exit ${clientReference(state, firstClientId!)} persistent keepalive must be between 1 and ${Math.floor(
        state.general.routingExitHealthTimeoutSeconds / 3
      )} seconds`;
    case 'server_allowed_ip_conflict':
      return `Server allowed IP conflict: ${clientReference(state, firstClientId!)} uses ${firstPrefix}, which overlaps ${clientReference(state, secondClientId!)} using ${secondPrefix}`;
    case 'routing_group_overlap':
      return `${groupReference(state, firstGroupId!, prospectiveGroupName)} and ${groupReference(state, secondGroupId!, prospectiveGroupName)} have overlapping prefixes through ${clientReference(state, firstClientId!)} and ${clientReference(state, secondClientId!)}`;
    case 'routing_server_allowed_ip_overlap':
      return `${groupReference(state, firstGroupId!, prospectiveGroupName)} prefix ${firstPrefix} conflicts with server allowed IP ${secondPrefix} on ${clientReference(state, secondClientId!)}; choose a non-overlapping prefix or remove that server allowed IP from the client configuration`;
    default:
      return issue.message;
  }
}

function validationIssues(
  state: ValidationState,
  input: RoutingGroupInput,
  groupId: number | undefined
) {
  const issues: RoutingValidationIssue[] = [];
  const blockingIssues: RoutingValidationIssue[] = [];
  if (
    state.general.routingPolicyVersion === 1 &&
    input.excludedIpv4Prefixes?.length
  ) {
    const issue: RoutingValidationIssue = {
      code: 'routing_policy_unavailable',
      message: 'Excluded routing policies are unavailable in this image.',
    };
    issues.push(issue);
    blockingIssues.push(issue);
  }
  const clientById = new Map(
    state.clients.map((client) => [client.id, client])
  );
  const referencedIds = new Set([
    ...input.memberClientIds,
    ...input.exits.map(({ clientId }) => clientId),
  ]);
  for (const clientId of referencedIds) {
    if (clientById.has(clientId)) continue;
    const issue: RoutingValidationIssue = {
      code: 'client_not_found',
      message: `Routing group references missing client ${clientId}`,
      clientIds: [clientId],
    };
    issues.push(issue);
    blockingIssues.push(issue);
  }

  for (const memberClientId of input.memberClientIds) {
    if (state.general.routingPolicyVersion === 2) break;
    const assignment = state.members.find(
      ({ groupId: existingGroupId, clientId }) =>
        clientId === memberClientId && existingGroupId !== groupId
    );
    if (!assignment) continue;
    const issue: RoutingValidationIssue = {
      code: 'member_already_assigned',
      message: `Client ${memberClientId} already belongs to routing group ${assignment.groupId}`,
      clientIds: [memberClientId],
      groupIds: [assignment.groupId],
    };
    issues.push(issue);
    blockingIssues.push(issue);
  }

  const enabledExitCount = input.exits.filter(({ enabled }) => enabled).length;
  if (
    input.memberClientIds.length === 0 ||
    enabledExitCount === 0 ||
    input.routedIpv4Prefixes.length === 0
  ) {
    issues.push({
      code: 'enabled_group_incomplete',
      message:
        'An enabled routing group requires at least one member, enabled exit candidate, and IPv4 prefix',
      groupIds: groupId ? [groupId] : undefined,
    });
  }

  const maximumKeepalive = Math.floor(
    state.general.routingExitHealthTimeoutSeconds / 3
  );
  for (const exit of input.exits.filter(({ enabled }) => enabled)) {
    const exitClient = clientById.get(exit.clientId);
    if (
      !exitClient ||
      (exitClient.persistentKeepalive > 0 &&
        exitClient.persistentKeepalive <= maximumKeepalive)
    ) {
      continue;
    }
    issues.push({
      code: 'exit_keepalive_invalid',
      message: `Exit client ${exit.clientId} persistent keepalive must be between 1 and ${maximumKeepalive} seconds`,
      clientIds: [exit.clientId],
      groupIds: groupId ? [groupId] : undefined,
    });
  }

  const existingGroups = state.groups
    .filter(({ id }) => id !== groupId)
    .map((group) =>
      toConflictGroup(group.id, persistedGroupInput(group, state))
    );
  const prospectiveGroup = toConflictGroup(groupId ?? 0, input, true);
  if (state.general.routingPolicyVersion === 1)
    issues.push(
      ...findRoutingPrefixConflicts({
        clients: state.clients,
        groups: [...existingGroups, prospectiveGroup],
      })
    );

  const serverAllowedIssues = findServerAllowedIpConflicts(state.clients);
  issues.push(...serverAllowedIssues);
  blockingIssues.push(...serverAllowedIssues);

  const existingRuleCount = state.groups
    .filter(({ id, enabled }) => id !== groupId && enabled)
    .reduce((total, group) => {
      const persisted = persistedGroupInput(group, state);
      return (
        total +
        persisted.memberClientIds.length * persisted.routedIpv4Prefixes.length
      );
    }, 0);
  const prospectiveRuleCount =
    input.memberClientIds.length * input.routedIpv4Prefixes.length;
  if (
    state.general.routingPolicyVersion === 1 &&
    existingRuleCount + prospectiveRuleCount >
      schemaLimits.routingGlobalRuleLimit
  ) {
    issues.push({
      code: 'global_rule_limit',
      message: `Enabled routing groups may generate at most ${schemaLimits.routingGlobalRuleLimit} member-prefix rules globally`,
      groupIds: groupId ? [groupId] : undefined,
    });
  }

  if (input.enabled) {
    blockingIssues.push(
      ...issues.filter((issue) => !blockingIssues.includes(issue))
    );
  }

  return {
    issues: issues.map((issue) => ({
      ...issue,
      message: formatRoutingIssue(state, issue, input.name),
    })),
    blockingIssues: blockingIssues.map((issue) => ({
      ...issue,
      message: formatRoutingIssue(state, issue, input.name),
    })),
  };
}

function allocateRoutingSlot(state: ValidationState) {
  const occupied = new Set([
    ...state.groups.map(({ routingSlot }) => routingSlot),
    ...state.tombstones.map(({ routingSlot }) => routingSlot),
  ]);
  for (let slot = ROUTING_SLOT_MIN; slot <= ROUTING_SLOT_MAX; slot += 1) {
    if (!occupied.has(slot)) return slot;
  }
  throw new Error('No routing slots are available');
}

function clientSummary(client: ClientType) {
  return {
    id: client.id,
    name: client.name,
    interfaceId: client.interfaceId,
    enabled: client.enabled,
    persistentKeepalive: client.persistentKeepalive,
  };
}

function buildAggregates(state: ValidationState): RoutingGroupAggregate[] {
  const membershipCounts = new Map<number, number>();
  for (const member of state.members)
    membershipCounts.set(
      member.clientId,
      (membershipCounts.get(member.clientId) ?? 0) + 1
    );
  const clientById = new Map(
    state.clients.map((client) => [client.id, client])
  );
  const runtimeByGroup = new Map(
    state.runtime.map((runtime) => [runtime.groupId, runtime])
  );
  const inputByGroup = new Map(
    state.groups.map((group) => [group.id, persistedGroupInput(group, state)])
  );
  const warningsByGroup = new Map<number, string[]>();
  const addWarning = (groupId: number, warning: string) => {
    const warnings = warningsByGroup.get(groupId) ?? [];
    if (!warnings.includes(warning)) warnings.push(warning);
    warningsByGroup.set(groupId, warnings);
  };
  const maximumKeepalive = Math.floor(
    state.general.routingExitHealthTimeoutSeconds / 3
  );
  for (const group of state.groups) {
    const input = inputByGroup.get(group.id)!;
    if (
      input.memberClientIds.length === 0 ||
      !input.exits.some(({ enabled }) => enabled) ||
      input.routedIpv4Prefixes.length === 0
    ) {
      addWarning(
        group.id,
        'An enabled routing group requires at least one member, enabled exit candidate, and IPv4 prefix'
      );
    }
    for (const exit of input.exits.filter(({ enabled }) => enabled)) {
      const client = clientById.get(exit.clientId);
      if (
        client &&
        (client.persistentKeepalive <= 0 ||
          client.persistentKeepalive > maximumKeepalive)
      ) {
        addWarning(
          group.id,
          `Exit ${clientReference(state, exit.clientId)} persistent keepalive must be between 1 and ${maximumKeepalive} seconds`
        );
      }
    }
  }
  const aggregateIssues = [
    ...(state.general.routingPolicyVersion === 1
      ? findRoutingPrefixConflicts({
          clients: state.clients,
          groups: state.groups.map((group) =>
            toConflictGroup(group.id, inputByGroup.get(group.id)!, true)
          ),
        })
      : []),
    ...findServerAllowedIpConflicts(state.clients),
  ];
  for (const issue of aggregateIssues) {
    const affectedGroups = issue.groupIds ?? state.groups.map(({ id }) => id);
    affectedGroups.forEach((groupId) =>
      addWarning(groupId, formatRoutingIssue(state, issue))
    );
  }
  const enabledTogetherRuleCount = state.groups.reduce((total, group) => {
    const input = inputByGroup.get(group.id)!;
    return (
      total + input.memberClientIds.length * input.routedIpv4Prefixes.length
    );
  }, 0);
  if (
    state.general.routingPolicyVersion === 1 &&
    enabledTogetherRuleCount > schemaLimits.routingGlobalRuleLimit
  ) {
    for (const group of state.groups) {
      addWarning(
        group.id,
        `Enabled routing groups may generate at most ${schemaLimits.routingGlobalRuleLimit} member-prefix rules globally`
      );
    }
  }

  return [...state.groups]
    .sort((left, right) => left.id - right.id)
    .map((group) => {
      return {
        ...group,
        exits: state.exits
          .filter(({ groupId }) => groupId === group.id)
          .sort(
            (left, right) =>
              left.priority - right.priority || left.clientId - right.clientId
          )
          .map((exit) => {
            const client = clientById.get(exit.clientId);
            if (!client) throw new Error('Routing exit client not found');
            return { ...exit, client: clientSummary(client) };
          }),
        members: state.members
          .filter(({ groupId }) => groupId === group.id)
          .sort((left, right) => left.clientId - right.clientId)
          .map((member) => {
            const client = clientById.get(member.clientId);
            if (!client) throw new Error('Routing member client not found');
            return { ...member, client: clientSummary(client) };
          }),
        runtime: runtimeByGroup.get(group.id) ?? null,
        validationWarnings: warningsByGroup.get(group.id) ?? [],
        baselineEditable:
          group.excludedIpv4Prefixes.length === 0 &&
          !state.members.some(
            (m) =>
              m.groupId === group.id && membershipCounts.get(m.clientId)! > 1
          ),
        execution: {
          available: true,
          active: runtimeByGroup.get(group.id)?.status === 'active',
          reason:
            runtimeByGroup.get(group.id)?.reason ??
            (group.enabled
              ? ROUTING_EXECUTION_PENDING
              : 'Routing group is disabled.'),
        },
      } satisfies RoutingGroupAggregate;
    });
}

export class RoutingGroupNotFoundError extends Error {}

export class RoutingGroupService {
  #db: DBType;

  constructor(db: DBType) {
    this.#db = db;
  }

  async getAll() {
    return this.#db.transaction(async (tx) =>
      buildAggregates(await loadValidationState(tx))
    );
  }

  async getStatus() {
    return this.#db.transaction(async (tx) => {
      const state = await loadValidationState(tx),
        policy = await readRoutingPolicyStateInTransaction(tx);
      let desiredFingerprint: string | null = null;
      if (policy.version === 2) {
        try {
          desiredFingerprint = compileRoutingPolicy(
            (await readProposedRoutingState(tx)).snapshot
          ).fingerprint;
        } catch {
          /* Keep an invalid desired generation truthfully unavailable. */
        }
      }
      return {
        executionAvailable: true,
        executionReason: null,
        policyVersion: policy.version,
        desiredFingerprint,
        capabilities: {
          subnetPolicies: policy.version === 2,
          fullClientConfiguration: policy.version === 2,
          advancedGroupEditing: policy.version === 2,
        },
        desiredRevision: policy.runtime.desiredRevision,
        appliedRevision: policy.runtime.appliedRevision,
        policyAppliedRevision: policy.applied?.revision ?? null,
        pendingTransition: policy.pending !== null,
        pendingStage: policy.pending?.stage ?? null,
        guardStatus: policy.pending
          ? ('verification_pending' as const)
          : ('no_pending_transition' as const),
        status: policy.runtime.status,
        lastError: policy.runtime.lastError,
        groups: buildAggregates(state),
      };
    });
  }

  async get(id: number) {
    const group = (await this.getAll()).find(
      ({ id: groupId }) => groupId === id
    );
    if (!group) throw new RoutingGroupNotFoundError('Routing group not found');
    return group;
  }

  async getForMember(clientId: number) {
    return (await this.getAll()).filter((group) =>
      group.members.some((member) => member.clientId === clientId)
    );
  }

  async createAggregate(
    rawInput: RoutingGroupInput,
    conditions: RoutingGroupSaveConditions = {}
  ) {
    const input = RoutingGroupSchema.parse(rawInput);
    const { id, revision } = await this.#db.transaction(async (tx) => {
      await assertSaveConditions(tx, conditions);
      const state = await loadValidationState(tx);
      const { blockingIssues } = validationIssues(state, input, undefined);
      if (blockingIssues.length > 0) {
        throw new RoutingValidationError(blockingIssues);
      }
      const routingSlot = allocateRoutingSlot(state);
      const [created] = await tx
        .insert(routingGroup)
        .values({
          routingSlot,
          name: input.name,
          enabled: input.enabled,
          natEnabled: input.natEnabled,
          allExitsDownPolicy: input.allExitsDownPolicy,
          routedIpv4Prefixes: input.routedIpv4Prefixes,
          excludedIpv4Prefixes: input.excludedIpv4Prefixes ?? [],
        })
        .returning({ id: routingGroup.id })
        .execute();
      if (!created) throw new Error('Routing group was not created');
      if (input.exits.length > 0) {
        await tx
          .insert(routingGroupExit)
          .values(input.exits.map((exit) => ({ groupId: created.id, ...exit })))
          .execute();
      }
      if (input.memberClientIds.length > 0) {
        await tx
          .insert(routingGroupMember)
          .values(
            input.memberClientIds.map((clientId) => ({
              groupId: created.id,
              clientId,
            }))
          )
          .execute();
      }
      const revision = await bumpDesiredRevision(tx, []);
      await tx
        .insert(routingGroupRuntimeState)
        .values({
          groupId: created.id,
          evaluatedRevision: revision,
          status: input.enabled ? 'awaiting_exit' : 'disabled',
          reason: input.enabled ? ROUTING_EXECUTION_PENDING : null,
        })
        .execute();
      return { id: created.id, revision };
    });
    return { group: await this.get(id), revision };
  }

  async updateAggregate(
    id: number,
    rawInput: RoutingGroupInput,
    conditions: RoutingGroupSaveConditions = {}
  ) {
    const input = RoutingGroupSchema.parse(rawInput);
    const revision = await this.#db.transaction(async (tx) => {
      await assertSaveConditions(tx, conditions);
      const state = await loadValidationState(tx);
      if (!state.groups.some(({ id: groupId }) => groupId === id)) {
        throw new RoutingGroupNotFoundError('Routing group not found');
      }
      const { blockingIssues } = validationIssues(state, input, id);
      if (blockingIssues.length > 0) {
        throw new RoutingValidationError(blockingIssues);
      }

      await tx
        .update(routingGroup)
        .set({
          name: input.name,
          enabled: input.enabled,
          natEnabled: input.natEnabled,
          allExitsDownPolicy: input.allExitsDownPolicy,
          routedIpv4Prefixes: input.routedIpv4Prefixes,
          excludedIpv4Prefixes:
            input.excludedIpv4Prefixes ??
            state.groups.find((group) => group.id === id)!.excludedIpv4Prefixes,
        })
        .where(eq(routingGroup.id, id))
        .execute();
      await tx
        .delete(routingGroupExit)
        .where(eq(routingGroupExit.groupId, id))
        .execute();
      await tx
        .delete(routingGroupMember)
        .where(eq(routingGroupMember.groupId, id))
        .execute();
      if (input.exits.length > 0) {
        await tx
          .insert(routingGroupExit)
          .values(input.exits.map((exit) => ({ groupId: id, ...exit })))
          .execute();
      }
      if (input.memberClientIds.length > 0) {
        await tx
          .insert(routingGroupMember)
          .values(
            input.memberClientIds.map((clientId) => ({ groupId: id, clientId }))
          )
          .execute();
      }
      const revision = await bumpDesiredRevision(tx, []);
      await tx
        .insert(routingGroupRuntimeState)
        .values({
          groupId: id,
          evaluatedRevision: revision,
          status: input.enabled ? 'awaiting_exit' : 'disabled',
          reason: input.enabled ? ROUTING_EXECUTION_PENDING : null,
        })
        .onConflictDoUpdate({
          target: routingGroupRuntimeState.groupId,
          set: {
            selectedExitClientId: null,
            evaluatedRevision: revision,
            selectedSince: null,
            status: input.enabled ? 'selected_pending' : 'disabled',
            reason: input.enabled ? ROUTING_EXECUTION_PENDING : null,
          },
        })
        .execute();
      return revision;
    });
    return { group: await this.get(id), revision };
  }

  async previewAggregate(rawInput: RoutingGroupPreviewInput) {
    const request = RoutingGroupPreviewSchema.parse(rawInput);
    return this.#db.transaction(async (tx) => {
      const state = await loadValidationState(tx),
        proposed = await readProposedRoutingState(tx),
        policy = await readRoutingPolicyStateInTransaction(tx);
      if (proposed.version !== 2)
        throw new PolicyValidationError('policy_version_required');
      const existing =
        request.groupId === undefined
          ? undefined
          : state.groups.find((g) => g.id === request.groupId);
      if (request.groupId !== undefined && !existing)
        throw new RoutingGroupNotFoundError('Routing group not found');
      const canonicalInput = {
        ...request.group,
        excludedIpv4Prefixes:
          request.group.excludedIpv4Prefixes ??
          existing?.excludedIpv4Prefixes ??
          [],
      };
      const { blockingIssues } = validationIssues(
        state,
        canonicalInput,
        existing?.id
      );
      if (blockingIssues.length)
        throw new RoutingValidationError(blockingIssues);
      // This identity is explicitly preview-only; save allocates its real ID.
      let proposalGroupId = existing?.id ?? Number.MAX_SAFE_INTEGER;
      while (!existing && state.groups.some((g) => g.id === proposalGroupId))
        proposalGroupId--;
      const snapshot = {
          ...proposed.snapshot,
          groups: [
            ...proposed.snapshot.groups.filter((g) => g.id !== existing?.id),
            {
              ...canonicalInput,
              id: proposalGroupId,
              routingSlot: existing?.routingSlot ?? allocateRoutingSlot(state),
            },
          ],
        },
        compiled = compileRoutingPolicy(snapshot);
      let desiredFingerprint: string | null = null;
      try {
        desiredFingerprint = compileRoutingPolicy(
          proposed.snapshot
        ).fingerprint;
      } catch {
        /* A safe proposal can repair an invalid saved generation. */
      }
      if (
        request.memberClientId !== undefined &&
        !snapshot.clients.some((c) => c.id === request.memberClientId)
      )
        throw new PolicyValidationError('client_not_found', {
          clientIds: [request.memberClientId],
        });
      return {
        desiredRevision: policy.runtime.desiredRevision,
        desiredFingerprint,
        proposedFingerprint: compiled.fingerprint,
        proposalGroupId,
        newGroup: !existing,
        canonicalInput,
        counts: compiled.counts,
        bypassPrefixes: compiled.bypassPrefixes,
        groups: compiled.groups,
        winnerExamples: compiledRoutingWinnerExamples(compiled),
        explanation:
          request.memberClientId !== undefined &&
          request.destinationIpv4 !== undefined
            ? explainCompiledRoutingPolicy(
                compiled,
                request.memberClientId,
                request.destinationIpv4
              )
            : null,
        observed: {
          appliedRevision: policy.applied?.revision ?? null,
          appliedFingerprint: policy.applied?.fingerprint ?? null,
          guardStatus: policy.pending
            ? ('verification_pending' as const)
            : ('no_pending_transition' as const),
          pendingStage: policy.pending?.stage ?? null,
          groups: state.runtime.map((g) => ({
            groupId: g.groupId,
            status: g.status,
            selectedExitClientId: g.selectedExitClientId,
            appliedExitClientId: g.appliedExitClientId,
            evaluatedRevision: g.evaluatedRevision,
            appliedRevision: g.appliedRevision,
          })),
        },
      };
    });
  }

  async delete(id: number) {
    const result = await this.#db.transaction(async (tx) => {
      const state = await loadValidationState(tx);
      const group = state.groups.find(({ id: groupId }) => groupId === id);
      if (!group)
        throw new RoutingGroupNotFoundError('Routing group not found');
      await tx.delete(routingGroup).where(eq(routingGroup.id, id)).execute();
      const revision = await bumpDesiredRevision(tx, []);
      await tx
        .insert(routingSlotTombstone)
        .values({
          routingSlot: group.routingSlot,
          releasedAfterRevision: revision,
        })
        .execute();
      return { routingSlot: group.routingSlot, revision };
    });
    return result;
  }

  async getRuntimeState(groupId: number) {
    const runtime = await this.#db.query.routingGroupRuntimeState
      .findFirst({
        where: eq(routingGroupRuntimeState.groupId, groupId),
      })
      .execute();
    if (!runtime) {
      throw new RoutingGroupNotFoundError(
        'Routing group runtime state not found'
      );
    }
    return runtime;
  }

  async updateRuntimeState(
    groupId: number,
    state: Partial<
      Omit<RoutingGroupRuntimeStateType, 'groupId' | 'createdAt' | 'updatedAt'>
    >
  ) {
    const result = await this.#db
      .update(routingGroupRuntimeState)
      .set(state)
      .where(eq(routingGroupRuntimeState.groupId, groupId))
      .execute();
    if (result.rowsAffected === 0) {
      throw new RoutingGroupNotFoundError(
        'Routing group runtime state not found'
      );
    }
  }

  async updateRuntimeStates(
    updates: readonly {
      groupId: number;
      state: Partial<
        Omit<
          RoutingGroupRuntimeStateType,
          'groupId' | 'createdAt' | 'updatedAt'
        >
      >;
    }[]
  ) {
    await this.#db.transaction(async (tx) => {
      for (const { groupId, state } of updates) {
        await tx
          .update(routingGroupRuntimeState)
          .set(state)
          .where(eq(routingGroupRuntimeState.groupId, groupId))
          .execute();
      }
    });
  }

  releaseTombstones(appliedRevision: number) {
    return this.#db
      .delete(routingSlotTombstone)
      .where(lte(routingSlotTombstone.releasedAfterRevision, appliedRevision))
      .execute();
  }

  async hasDeferredRoutingState() {
    const state = await loadValidationState(this.#db);
    return (
      state.groups.length > 0 ||
      state.tombstones.length > 0 ||
      state.clients.some(
        ({ enabled, serverAllowedIps }) =>
          enabled && serverAllowedIps.length > 0
      )
    );
  }

  async getPlannerSnapshot() {
    const state = await loadValidationState(this.#db);
    // The v1 bridge is never an advanced-policy runtime engine.
    assertRoutingPolicyVersion1(state.general.routingPolicyVersion);
    const runtimeByInterface = new Map(
      (await this.#db.query.interfaceRuntimeState.findMany().execute()).map(
        (runtime) => [runtime.interfaceId, runtime]
      )
    );
    const runtimeByGroup = new Map(
      state.runtime.map((runtime) => [runtime.groupId, runtime])
    );
    const globalRuntime = await this.#db.query.runtimeReconciliationState
      .findFirst()
      .execute();
    if (!globalRuntime)
      throw new Error('Runtime reconciliation state not found');

    return {
      settings: {
        healthCheckIntervalSeconds:
          state.general.routingExitHealthCheckIntervalSeconds,
        healthTimeoutSeconds: state.general.routingExitHealthTimeoutSeconds,
        minHoldSeconds: state.general.routingExitMinHoldSeconds,
        failbackDelaySeconds: state.general.routingExitFailbackDelaySeconds,
      },
      runtime: globalRuntime,
      interfaces: state.interfaces.map((wgInterface) => ({
        interfaceId: wgInterface.name,
        ipv4Cidr: wgInterface.ipv4Cidr,
        enabled: wgInterface.enabled && !wgInterface.pendingDelete,
        observedUp:
          runtimeByInterface.get(wgInterface.name)?.observedUp === true,
        runtimeStatus:
          runtimeByInterface.get(wgInterface.name)?.status ?? 'pending',
      })),
      clients: state.clients.map((client) => ({
        id: client.id,
        name: client.name,
        interfaceId: client.interfaceId,
        publicKey: client.publicKey,
        ipv4Address: client.ipv4Address,
        enabled: client.enabled,
        persistentKeepalive: client.persistentKeepalive,
        serverAllowedIps: client.serverAllowedIps,
      })),
      groups: state.groups.map((group) => {
        const input = persistedGroupInput(group, state);
        return {
          id: group.id,
          routingSlot: group.routingSlot,
          enabled: group.enabled,
          natEnabled: group.natEnabled,
          allExitsDownPolicy: group.allExitsDownPolicy,
          routedIpv4Prefixes: group.routedIpv4Prefixes,
          memberClientIds: input.memberClientIds,
          exits: input.exits,
          runtime: runtimeByGroup.get(group.id) ?? null,
        };
      }),
      tombstones: state.tombstones,
    };
  }
}

export { ROUTING_EXECUTION_PENDING };
