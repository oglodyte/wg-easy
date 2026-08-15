CREATE TABLE `routing_groups_table` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`routing_slot` integer NOT NULL,
	`name` text NOT NULL,
	`enabled` integer DEFAULT true NOT NULL,
	`nat_enabled` integer DEFAULT true NOT NULL,
	`all_exits_down_policy` text DEFAULT 'block' NOT NULL,
	`routed_ipv4_prefixes` text DEFAULT '["0.0.0.0/0"]' NOT NULL,
	`created_at` text DEFAULT (CURRENT_TIMESTAMP) NOT NULL,
	`updated_at` text DEFAULT (CURRENT_TIMESTAMP) NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `routing_groups_table_routing_slot_unique` ON `routing_groups_table` (`routing_slot`);--> statement-breakpoint
CREATE TABLE `routing_group_exits_table` (
	`group_id` integer NOT NULL,
	`client_id` integer NOT NULL,
	`priority` integer NOT NULL,
	`enabled` integer DEFAULT true NOT NULL,
	`created_at` text DEFAULT (CURRENT_TIMESTAMP) NOT NULL,
	`updated_at` text DEFAULT (CURRENT_TIMESTAMP) NOT NULL,
	PRIMARY KEY(`group_id`, `client_id`),
	FOREIGN KEY (`group_id`) REFERENCES `routing_groups_table`(`id`) ON UPDATE cascade ON DELETE cascade,
	FOREIGN KEY (`client_id`) REFERENCES `clients_table`(`id`) ON UPDATE cascade ON DELETE restrict
);
--> statement-breakpoint
CREATE UNIQUE INDEX `routing_group_exits_priority_unique` ON `routing_group_exits_table` (`group_id`,`priority`);--> statement-breakpoint
CREATE INDEX `routing_group_exits_client_idx` ON `routing_group_exits_table` (`client_id`);--> statement-breakpoint
CREATE TABLE `routing_group_members_table` (
	`group_id` integer NOT NULL,
	`client_id` integer NOT NULL,
	`created_at` text DEFAULT (CURRENT_TIMESTAMP) NOT NULL,
	`updated_at` text DEFAULT (CURRENT_TIMESTAMP) NOT NULL,
	PRIMARY KEY(`group_id`, `client_id`),
	FOREIGN KEY (`group_id`) REFERENCES `routing_groups_table`(`id`) ON UPDATE cascade ON DELETE cascade,
	FOREIGN KEY (`client_id`) REFERENCES `clients_table`(`id`) ON UPDATE cascade ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `routing_group_members_client_unique` ON `routing_group_members_table` (`client_id`);--> statement-breakpoint
CREATE TABLE `routing_group_runtime_state_table` (
	`group_id` integer PRIMARY KEY NOT NULL,
	`selected_exit_client_id` integer,
	`applied_exit_client_id` integer,
	`evaluated_revision` integer NOT NULL,
	`applied_revision` integer,
	`selected_since` text,
	`applied_since` text,
	`last_evaluated_at` text,
	`last_failover_at` text,
	`status` text NOT NULL,
	`reason` text,
	`created_at` text DEFAULT (CURRENT_TIMESTAMP) NOT NULL,
	`updated_at` text DEFAULT (CURRENT_TIMESTAMP) NOT NULL,
	FOREIGN KEY (`group_id`) REFERENCES `routing_groups_table`(`id`) ON UPDATE cascade ON DELETE cascade,
	FOREIGN KEY (`selected_exit_client_id`) REFERENCES `clients_table`(`id`) ON UPDATE cascade ON DELETE set null,
	FOREIGN KEY (`applied_exit_client_id`) REFERENCES `clients_table`(`id`) ON UPDATE cascade ON DELETE set null
);
--> statement-breakpoint
CREATE INDEX `routing_group_runtime_selected_exit_idx` ON `routing_group_runtime_state_table` (`selected_exit_client_id`);--> statement-breakpoint
CREATE INDEX `routing_group_runtime_applied_exit_idx` ON `routing_group_runtime_state_table` (`applied_exit_client_id`);--> statement-breakpoint
CREATE TABLE `routing_slot_tombstones_table` (
	`routing_slot` integer PRIMARY KEY NOT NULL,
	`released_after_revision` integer NOT NULL,
	`created_at` text DEFAULT (CURRENT_TIMESTAMP) NOT NULL
);
--> statement-breakpoint
CREATE TABLE `interface_runtime_state_table` (
	`interface_id` text PRIMARY KEY NOT NULL,
	`desired_revision` integer DEFAULT 1 NOT NULL,
	`applied_revision` integer DEFAULT 0 NOT NULL,
	`status` text DEFAULT 'pending' NOT NULL,
	`observed_up` integer DEFAULT false NOT NULL,
	`restart_required` integer DEFAULT false NOT NULL,
	`last_started_at` text,
	`last_stopped_at` text,
	`last_applied_at` text,
	`last_error` text,
	`updated_at` text DEFAULT (CURRENT_TIMESTAMP) NOT NULL,
	FOREIGN KEY (`interface_id`) REFERENCES `interfaces_table`(`name`) ON UPDATE cascade ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `runtime_reconciliation_state_table` (
	`id` integer PRIMARY KEY DEFAULT 1 NOT NULL,
	`desired_revision` integer DEFAULT 1 NOT NULL,
	`applied_revision` integer DEFAULT 0 NOT NULL,
	`status` text DEFAULT 'pending' NOT NULL,
	`last_started_at` text,
	`last_succeeded_at` text,
	`last_error` text,
	`updated_at` text DEFAULT (CURRENT_TIMESTAMP) NOT NULL
);
--> statement-breakpoint
PRAGMA foreign_keys=OFF;--> statement-breakpoint
CREATE TABLE `__new_clients_table` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`user_id` integer NOT NULL,
	`interface_id` text NOT NULL,
	`name` text NOT NULL,
	`ipv4_address` text NOT NULL,
	`ipv6_address` text NOT NULL,
	`pre_up` text DEFAULT '' NOT NULL,
	`post_up` text DEFAULT '' NOT NULL,
	`pre_down` text DEFAULT '' NOT NULL,
	`post_down` text DEFAULT '' NOT NULL,
	`private_key` text NOT NULL,
	`public_key` text NOT NULL,
	`pre_shared_key` text NOT NULL,
	`expires_at` text,
	`allowed_ips` text,
	`server_allowed_ips` text NOT NULL,
	`firewall_ips` text,
	`persistent_keepalive` integer NOT NULL,
	`mtu` integer NOT NULL,
	`j_c` integer,
	`j_min` integer,
	`j_max` integer,
	`i1` text,
	`i2` text,
	`i3` text,
	`i4` text,
	`i5` text,
	`dns` text,
	`server_endpoint` text,
	`preferred_config_format` text DEFAULT 'auto' NOT NULL,
	`enabled` integer NOT NULL,
	`created_at` text DEFAULT (CURRENT_TIMESTAMP) NOT NULL,
	`updated_at` text DEFAULT (CURRENT_TIMESTAMP) NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `users_table`(`id`) ON UPDATE cascade ON DELETE restrict,
	FOREIGN KEY (`interface_id`) REFERENCES `interfaces_table`(`name`) ON UPDATE cascade ON DELETE restrict
);
--> statement-breakpoint
INSERT INTO `__new_clients_table`("id", "user_id", "interface_id", "name", "ipv4_address", "ipv6_address", "pre_up", "post_up", "pre_down", "post_down", "private_key", "public_key", "pre_shared_key", "expires_at", "allowed_ips", "server_allowed_ips", "firewall_ips", "persistent_keepalive", "mtu", "j_c", "j_min", "j_max", "i1", "i2", "i3", "i4", "i5", "dns", "server_endpoint", "preferred_config_format", "enabled", "created_at", "updated_at") SELECT "id", "user_id", "interface_id", "name", "ipv4_address", "ipv6_address", "pre_up", "post_up", "pre_down", "post_down", "private_key", "public_key", "pre_shared_key", "expires_at", "allowed_ips", "server_allowed_ips", "firewall_ips", "persistent_keepalive", "mtu", "j_c", "j_min", "j_max", "i1", "i2", "i3", "i4", "i5", "dns", "server_endpoint", 'auto', "enabled", "created_at", "updated_at" FROM `clients_table`;--> statement-breakpoint
DROP TABLE `clients_table`;--> statement-breakpoint
ALTER TABLE `__new_clients_table` RENAME TO `clients_table`;--> statement-breakpoint
PRAGMA foreign_keys=ON;--> statement-breakpoint
CREATE UNIQUE INDEX `clients_table_ipv4_address_unique` ON `clients_table` (`ipv4_address`);--> statement-breakpoint
CREATE UNIQUE INDEX `clients_table_ipv6_address_unique` ON `clients_table` (`ipv6_address`);--> statement-breakpoint
CREATE UNIQUE INDEX `public_key_interface_unique` ON `clients_table` (`public_key`,`interface_id`);--> statement-breakpoint
PRAGMA foreign_keys=OFF;--> statement-breakpoint
CREATE TABLE `__new_general_table` (
	`id` integer PRIMARY KEY DEFAULT 1 NOT NULL,
	`setup_step` integer NOT NULL,
	`session_password` text NOT NULL,
	`session_timeout` integer NOT NULL,
	`metrics_prometheus` integer NOT NULL,
	`metrics_json` integer NOT NULL,
	`metrics_password` text,
	`default_interface_id` text DEFAULT 'wg0' NOT NULL,
	`created_at` text DEFAULT (CURRENT_TIMESTAMP) NOT NULL,
	`updated_at` text DEFAULT (CURRENT_TIMESTAMP) NOT NULL,
	FOREIGN KEY (`default_interface_id`) REFERENCES `interfaces_table`(`name`) ON UPDATE cascade ON DELETE restrict
);--> statement-breakpoint
INSERT INTO `__new_general_table`("id", "setup_step", "session_password", "session_timeout", "metrics_prometheus", "metrics_json", "metrics_password", "default_interface_id", "created_at", "updated_at") SELECT "id", "setup_step", "session_password", "session_timeout", "metrics_prometheus", "metrics_json", "metrics_password", 'wg0', "created_at", "updated_at" FROM `general_table`;--> statement-breakpoint
DROP TABLE `general_table`;--> statement-breakpoint
ALTER TABLE `__new_general_table` RENAME TO `general_table`;--> statement-breakpoint
PRAGMA foreign_keys=ON;--> statement-breakpoint
ALTER TABLE `general_table` ADD `routing_exit_health_check_interval_seconds` integer DEFAULT 60 NOT NULL;--> statement-breakpoint
ALTER TABLE `general_table` ADD `routing_exit_health_timeout_seconds` integer DEFAULT 180 NOT NULL;--> statement-breakpoint
ALTER TABLE `general_table` ADD `routing_exit_min_hold_seconds` integer DEFAULT 60 NOT NULL;--> statement-breakpoint
ALTER TABLE `general_table` ADD `routing_exit_failback_delay_seconds` integer DEFAULT 180 NOT NULL;--> statement-breakpoint
ALTER TABLE `interfaces_table` ADD `awg_parameters_enabled` integer DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE `interfaces_table` ADD `default_config_format` text DEFAULT 'wireguard' NOT NULL;--> statement-breakpoint
ALTER TABLE `interfaces_table` ADD `pending_delete` integer DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE `one_time_links_table` ADD `config_format` text DEFAULT 'wireguard' NOT NULL;--> statement-breakpoint
UPDATE `interfaces_table` SET `default_config_format` = 'migration_pending';--> statement-breakpoint
UPDATE `one_time_links_table` SET `config_format` = 'migration_pending';--> statement-breakpoint
INSERT INTO `interface_runtime_state_table` (`interface_id`, `desired_revision`, `applied_revision`, `status`, `observed_up`, `restart_required`)
SELECT `name`, 1, 0, 'pending', false, false FROM `interfaces_table`;--> statement-breakpoint
INSERT INTO `runtime_reconciliation_state_table` (`id`, `desired_revision`, `applied_revision`, `status`)
VALUES (1, 1, 0, 'pending');
