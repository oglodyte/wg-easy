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
} from './types';

import type { ClientType } from '#db/repositories/client/types';
import { bumpDesiredRevision } from '#db/repositories/runtime/service';
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

const ROUTING_EXECUTION_UNAVAILABLE =
  'Routing plans are preview-only until Phase 6; no Linux routing state has been applied.';

type QueryDatabase = Pick<DBType, 'query'>;

type ValidationState = Awaited<ReturnType<typeof loadValidationState>>;

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

function validationIssues(
  state: ValidationState,
  input: RoutingGroupInput,
  groupId: number | undefined
) {
  const issues: RoutingValidationIssue[] = [];
  const blockingIssues: RoutingValidationIssue[] = [];
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
    issues,
    blockingIssues,
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
          `Exit client ${exit.clientId} persistent keepalive must be between 1 and ${maximumKeepalive} seconds`
        );
      }
    }
  }
  const aggregateIssues = [
    ...findRoutingPrefixConflicts({
      clients: state.clients,
      groups: state.groups.map((group) =>
        toConflictGroup(group.id, inputByGroup.get(group.id)!, true)
      ),
    }),
    ...findServerAllowedIpConflicts(state.clients),
  ];
  for (const issue of aggregateIssues) {
    const affectedGroups = issue.groupIds ?? state.groups.map(({ id }) => id);
    affectedGroups.forEach((groupId) => addWarning(groupId, issue.message));
  }
  const enabledTogetherRuleCount = state.groups.reduce((total, group) => {
    const input = inputByGroup.get(group.id)!;
    return (
      total + input.memberClientIds.length * input.routedIpv4Prefixes.length
    );
  }, 0);
  if (enabledTogetherRuleCount > schemaLimits.routingGlobalRuleLimit) {
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
        execution: {
          available: false,
          active: false,
          reason: ROUTING_EXECUTION_UNAVAILABLE,
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
    return buildAggregates(await loadValidationState(this.#db));
  }

  async get(id: number) {
    const group = (await this.getAll()).find(
      ({ id: groupId }) => groupId === id
    );
    if (!group) throw new RoutingGroupNotFoundError('Routing group not found');
    return group;
  }

  async createAggregate(rawInput: RoutingGroupInput) {
    const input = RoutingGroupSchema.parse(rawInput);
    const { id, revision } = await this.#db.transaction(async (tx) => {
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
          reason: input.enabled ? ROUTING_EXECUTION_UNAVAILABLE : null,
        })
        .execute();
      return { id: created.id, revision };
    });
    return { group: await this.get(id), revision };
  }

  async updateAggregate(id: number, rawInput: RoutingGroupInput) {
    const input = RoutingGroupSchema.parse(rawInput);
    const revision = await this.#db.transaction(async (tx) => {
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
          reason: input.enabled ? ROUTING_EXECUTION_UNAVAILABLE : null,
        })
        .onConflictDoUpdate({
          target: routingGroupRuntimeState.groupId,
          set: {
            selectedExitClientId: null,
            appliedExitClientId: null,
            evaluatedRevision: revision,
            appliedRevision: null,
            selectedSince: null,
            appliedSince: null,
            status: input.enabled ? 'awaiting_exit' : 'disabled',
            reason: input.enabled ? ROUTING_EXECUTION_UNAVAILABLE : null,
          },
        })
        .execute();
      return revision;
    });
    return { group: await this.get(id), revision };
  }

  async delete(id: number) {
    const result = await this.#db.transaction(async (tx) => {
      const state = await loadValidationState(tx);
      const group = state.groups.find(({ id: groupId }) => groupId === id);
      if (!group)
        throw new RoutingGroupNotFoundError('Routing group not found');
      const revision = await bumpDesiredRevision(tx, []);
      await tx
        .insert(routingSlotTombstone)
        .values({
          routingSlot: group.routingSlot,
          releasedAfterRevision: revision,
        })
        .execute();
      await tx.delete(routingGroup).where(eq(routingGroup.id, id)).execute();
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
    if (
      state.status === 'active' ||
      state.appliedExitClientId != null ||
      state.appliedRevision != null
    ) {
      throw new Error(
        'Routing runtime cannot be marked applied before Phase 6 execution and verification'
      );
    }
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

export { ROUTING_EXECUTION_UNAVAILABLE };
