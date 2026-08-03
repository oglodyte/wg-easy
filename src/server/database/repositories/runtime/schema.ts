import { sql } from 'drizzle-orm';
import { int, sqliteTable, text } from 'drizzle-orm/sqlite-core';

import { wgInterface } from '../interface/schema';

export const interfaceRuntimeState = sqliteTable(
  'interface_runtime_state_table',
  {
    interfaceId: text('interface_id')
      .primaryKey()
      .references(() => wgInterface.name, {
        onDelete: 'cascade',
        onUpdate: 'cascade',
      }),
    desiredRevision: int('desired_revision').notNull().default(1),
    appliedRevision: int('applied_revision').notNull().default(0),
    status: text()
      .$type<
        'disabled' | 'pending' | 'starting' | 'up' | 'degraded' | 'stopping'
      >()
      .notNull()
      .default('pending'),
    observedUp: int('observed_up', { mode: 'boolean' })
      .notNull()
      .default(false),
    restartRequired: int('restart_required', { mode: 'boolean' })
      .notNull()
      .default(false),
    lastStartedAt: text('last_started_at'),
    lastStoppedAt: text('last_stopped_at'),
    lastAppliedAt: text('last_applied_at'),
    lastError: text('last_error'),
    updatedAt: text('updated_at')
      .notNull()
      .default(sql`(CURRENT_TIMESTAMP)`)
      .$onUpdate(() => sql`(CURRENT_TIMESTAMP)`),
  }
);

export const runtimeReconciliationState = sqliteTable(
  'runtime_reconciliation_state_table',
  {
    id: int().primaryKey({ autoIncrement: false }).default(1),
    desiredRevision: int('desired_revision').notNull().default(1),
    appliedRevision: int('applied_revision').notNull().default(0),
    status: text()
      .$type<'idle' | 'pending' | 'applying' | 'degraded'>()
      .notNull()
      .default('pending'),
    lastStartedAt: text('last_started_at'),
    lastSucceededAt: text('last_succeeded_at'),
    lastError: text('last_error'),
    updatedAt: text('updated_at')
      .notNull()
      .default(sql`(CURRENT_TIMESTAMP)`)
      .$onUpdate(() => sql`(CURRENT_TIMESTAMP)`),
  }
);
