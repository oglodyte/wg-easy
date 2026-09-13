DROP INDEX `clients_table_ipv4_address_unique`;--> statement-breakpoint
DROP INDEX `clients_table_ipv6_address_unique`;--> statement-breakpoint
CREATE UNIQUE INDEX `enabled_client_ipv4_unique` ON `clients_table` (`ipv4_address`) WHERE "clients_table"."enabled" = 1;--> statement-breakpoint
CREATE UNIQUE INDEX `enabled_client_ipv6_unique` ON `clients_table` (`ipv6_address`) WHERE "clients_table"."enabled" = 1;