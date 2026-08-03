import { relations, sql } from 'drizzle-orm';
import {
  index,
  int,
  primaryKey,
  sqliteTable,
  text,
  uniqueIndex,
} from 'drizzle-orm/sqlite-core';

import { client } from '../client/schema';

export const routingGroup = sqliteTable('routing_groups_table', {
  id: int().primaryKey({ autoIncrement: true }),
  routingSlot: int('routing_slot').notNull().unique(),
  name: text().notNull(),
  enabled: int({ mode: 'boolean' }).notNull().default(true),
  natEnabled: int('nat_enabled', { mode: 'boolean' }).notNull().default(true),
  allExitsDownPolicy: text('all_exits_down_policy')
    .$type<'block' | 'host'>()
    .notNull()
    .default('block'),
  routedIpv4Prefixes: text('routed_ipv4_prefixes', { mode: 'json' })
    .$type<string[]>()
    .notNull()
    .default(['0.0.0.0/0']),
  createdAt: text('created_at')
    .notNull()
    .default(sql`(CURRENT_TIMESTAMP)`),
  updatedAt: text('updated_at')
    .notNull()
    .default(sql`(CURRENT_TIMESTAMP)`)
    .$onUpdate(() => sql`(CURRENT_TIMESTAMP)`),
});

export const routingGroupExit = sqliteTable(
  'routing_group_exits_table',
  {
    groupId: int('group_id')
      .notNull()
      .references(() => routingGroup.id, {
        onDelete: 'cascade',
        onUpdate: 'cascade',
      }),
    clientId: int('client_id')
      .notNull()
      .references(() => client.id, {
        onDelete: 'restrict',
        onUpdate: 'cascade',
      }),
    priority: int().notNull(),
    enabled: int({ mode: 'boolean' }).notNull().default(true),
    createdAt: text('created_at')
      .notNull()
      .default(sql`(CURRENT_TIMESTAMP)`),
    updatedAt: text('updated_at')
      .notNull()
      .default(sql`(CURRENT_TIMESTAMP)`)
      .$onUpdate(() => sql`(CURRENT_TIMESTAMP)`),
  },
  (table) => [
    primaryKey({ columns: [table.groupId, table.clientId] }),
    uniqueIndex('routing_group_exits_priority_unique').on(
      table.groupId,
      table.priority
    ),
    index('routing_group_exits_client_idx').on(table.clientId),
  ]
);

export const routingGroupMember = sqliteTable(
  'routing_group_members_table',
  {
    groupId: int('group_id')
      .notNull()
      .references(() => routingGroup.id, {
        onDelete: 'cascade',
        onUpdate: 'cascade',
      }),
    clientId: int('client_id')
      .notNull()
      .references(() => client.id, {
        onDelete: 'cascade',
        onUpdate: 'cascade',
      }),
    createdAt: text('created_at')
      .notNull()
      .default(sql`(CURRENT_TIMESTAMP)`),
    updatedAt: text('updated_at')
      .notNull()
      .default(sql`(CURRENT_TIMESTAMP)`)
      .$onUpdate(() => sql`(CURRENT_TIMESTAMP)`),
  },
  (table) => [
    primaryKey({ columns: [table.groupId, table.clientId] }),
    uniqueIndex('routing_group_members_client_unique').on(table.clientId),
  ]
);

export const routingSlotTombstone = sqliteTable(
  'routing_slot_tombstones_table',
  {
    routingSlot: int('routing_slot').primaryKey(),
    releasedAfterRevision: int('released_after_revision').notNull(),
    createdAt: text('created_at')
      .notNull()
      .default(sql`(CURRENT_TIMESTAMP)`),
  }
);

export const routingGroupRuntimeState = sqliteTable(
  'routing_group_runtime_state_table',
  {
    groupId: int('group_id')
      .primaryKey()
      .references(() => routingGroup.id, {
        onDelete: 'cascade',
        onUpdate: 'cascade',
      }),
    selectedExitClientId: int('selected_exit_client_id').references(
      () => client.id,
      { onDelete: 'set null', onUpdate: 'cascade' }
    ),
    appliedExitClientId: int('applied_exit_client_id').references(
      () => client.id,
      { onDelete: 'set null', onUpdate: 'cascade' }
    ),
    evaluatedRevision: int('evaluated_revision').notNull(),
    appliedRevision: int('applied_revision'),
    selectedSince: text('selected_since'),
    appliedSince: text('applied_since'),
    lastEvaluatedAt: text('last_evaluated_at'),
    lastFailoverAt: text('last_failover_at'),
    status: text()
      .$type<
        | 'disabled'
        | 'draft_invalid'
        | 'awaiting_exit'
        | 'selected_pending'
        | 'active'
        | 'blocked'
        | 'host_fallback'
        | 'degraded'
      >()
      .notNull(),
    reason: text(),
    createdAt: text('created_at')
      .notNull()
      .default(sql`(CURRENT_TIMESTAMP)`),
    updatedAt: text('updated_at')
      .notNull()
      .default(sql`(CURRENT_TIMESTAMP)`)
      .$onUpdate(() => sql`(CURRENT_TIMESTAMP)`),
  },
  (table) => [
    index('routing_group_runtime_selected_exit_idx').on(
      table.selectedExitClientId
    ),
    index('routing_group_runtime_applied_exit_idx').on(
      table.appliedExitClientId
    ),
  ]
);

export const routingGroupRelations = relations(
  routingGroup,
  ({ many, one }) => ({
    exits: many(routingGroupExit),
    members: many(routingGroupMember),
    runtimeState: one(routingGroupRuntimeState),
  })
);

export const routingGroupExitRelations = relations(
  routingGroupExit,
  ({ one }) => ({
    group: one(routingGroup, {
      fields: [routingGroupExit.groupId],
      references: [routingGroup.id],
    }),
    client: one(client, {
      fields: [routingGroupExit.clientId],
      references: [client.id],
    }),
  })
);

export const routingGroupMemberRelations = relations(
  routingGroupMember,
  ({ one }) => ({
    group: one(routingGroup, {
      fields: [routingGroupMember.groupId],
      references: [routingGroup.id],
    }),
    client: one(client, {
      fields: [routingGroupMember.clientId],
      references: [client.id],
    }),
  })
);

export const routingGroupRuntimeStateRelations = relations(
  routingGroupRuntimeState,
  ({ one }) => ({
    group: one(routingGroup, {
      fields: [routingGroupRuntimeState.groupId],
      references: [routingGroup.id],
    }),
    selectedExitClient: one(client, {
      fields: [routingGroupRuntimeState.selectedExitClientId],
      references: [client.id],
      relationName: 'selectedExitClient',
    }),
    appliedExitClient: one(client, {
      fields: [routingGroupRuntimeState.appliedExitClientId],
      references: [client.id],
      relationName: 'appliedExitClient',
    }),
  })
);
