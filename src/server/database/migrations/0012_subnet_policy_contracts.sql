CREATE TABLE `routing_policy_runtime_table` (
	`id` integer PRIMARY KEY DEFAULT 1 NOT NULL,
	`applied` text,
	`pending` text,
	CONSTRAINT "routing_policy_singleton" CHECK("routing_policy_runtime_table"."id" = 1)
);
--> statement-breakpoint
INSERT INTO `routing_policy_runtime_table` (`id`) VALUES (1);
--> statement-breakpoint
DROP INDEX `routing_group_members_client_unique`;--> statement-breakpoint
CREATE INDEX `routing_group_members_client_idx` ON `routing_group_members_table` (`client_id`);--> statement-breakpoint
ALTER TABLE `general_table` ADD `routing_policy_version` integer DEFAULT 1 NOT NULL;--> statement-breakpoint
ALTER TABLE `routing_groups_table` ADD `excluded_ipv4_prefixes` text DEFAULT '[]' NOT NULL;
