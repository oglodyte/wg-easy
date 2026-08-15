import { sql } from 'drizzle-orm';
import { sqliteTable, text, int } from 'drizzle-orm/sqlite-core';

import { wgInterface } from '../interface/schema';

export const general = sqliteTable('general_table', {
  id: int().primaryKey({ autoIncrement: false }).default(1),

  setupStep: int('setup_step').notNull(),

  sessionPassword: text('session_password').notNull(),
  sessionTimeout: int('session_timeout').notNull(),

  metricsPrometheus: int('metrics_prometheus', { mode: 'boolean' }).notNull(),
  metricsJson: int('metrics_json', { mode: 'boolean' }).notNull(),
  metricsPassword: text('metrics_password'),

  defaultInterfaceId: text('default_interface_id')
    .notNull()
    .default('wg0')
    .references(() => wgInterface.name, {
      onDelete: 'restrict',
      onUpdate: 'cascade',
    }),

  routingExitHealthCheckIntervalSeconds: int(
    'routing_exit_health_check_interval_seconds'
  )
    .notNull()
    .default(60),
  routingExitHealthTimeoutSeconds: int('routing_exit_health_timeout_seconds')
    .notNull()
    .default(180),
  routingExitMinHoldSeconds: int('routing_exit_min_hold_seconds')
    .notNull()
    .default(60),
  routingExitFailbackDelaySeconds: int('routing_exit_failback_delay_seconds')
    .notNull()
    .default(180),

  createdAt: text('created_at')
    .notNull()
    .default(sql`(CURRENT_TIMESTAMP)`),
  updatedAt: text('updated_at')
    .notNull()
    .default(sql`(CURRENT_TIMESTAMP)`)
    .$onUpdate(() => sql`(CURRENT_TIMESTAMP)`),
});
