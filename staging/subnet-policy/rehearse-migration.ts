/** Run only against a restored staging clone; never the live or golden volume. */
import { createHash } from "node:crypto";
import path from "node:path";

import { createNodeSqliteDatabase } from "../../src/server/database/nodeSqlite";
import { finalizePhase1DataMigration } from "../../src/server/database/phase1Migration";
import * as schema from "../../src/server/database/schema";
import { compileRoutingPolicy } from "../../src/server/utils/routingPolicy";

const directory = process.argv[2];
if (!directory || !path.isAbsolute(directory))
  throw new Error("An absolute clone directory is required");
const database = createNodeSqliteDatabase(
  path.join(directory, "wg-easy.db"),
  schema,
);
const hash = (value: unknown) =>
  createHash("sha256").update(JSON.stringify(value)).digest("hex");
try {
  const names = (
    await database.raw.execute(
      "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '%runtime%' AND name NOT LIKE '%reconciliation%' AND name NOT LIKE '%tombstone%' AND name <> '__drizzle_migrations' ORDER BY name",
    )
  ).rows.map((r) => String(r.name));
  const records: {
    table: string;
    columns: string[];
    checksum: string;
    count: number;
  }[] = [];
  for (const table of names) {
    if (!/^[a-z_]+$/.test(table)) throw new Error("Unexpected table identity");
    const columns = (
      await database.raw.execute(`PRAGMA table_info("${table}")`)
    ).rows.map((r) => String(r.name));
    // The accepted 0007 compatibility backfill updates only these timestamps.
    // Preserve them strictly for already-migrated current-volume snapshots.
    const legacyBackfill =
      (table === "interfaces_table" &&
        !columns.includes("awg_parameters_enabled")) ||
      (table === "one_time_links_table" && !columns.includes("config_format"));
    const kept = columns.filter(
      (column) => column !== "updated_at" || !legacyBackfill,
    );
    const values = (
      await database.raw.execute(
        `SELECT ${kept.map((c) => `"${c}"`).join(",")} FROM "${table}" ORDER BY rowid`,
      )
    ).rows;
    records.push({
      table,
      columns: kept,
      checksum: hash(values),
      count: values.length,
    });
  }
  await database.migrate({
    migrationsFolder: "/app/server/database/migrations",
  });
  const result = await finalizePhase1DataMigration(database.raw, {
    configDirectory: directory,
    legacyEnvironment: {},
  });
  if (result.unresolved.length)
    throw new Error("Compatibility resolution is unavailable");
  for (const record of records) {
    const values = (
      await database.raw.execute(
        `SELECT ${record.columns.map((c) => `"${c}"`).join(",")} FROM "${record.table}" ORDER BY rowid`,
      )
    ).rows;
    if (hash(values) !== record.checksum)
      throw new Error(`Preservation failed for ${record.table}`);
  }
  await database.migrate({
    migrationsFolder: "/app/server/database/migrations",
  });
  if ((await database.raw.execute("PRAGMA foreign_key_check")).rows.length)
    throw new Error("Foreign key failure");
  if (
    (await database.raw.execute("PRAGMA integrity_check")).rows[0]
      ?.integrity_check !== "ok"
  )
    throw new Error("Integrity failure");
  const groups = await database.db.query.routingGroup.findMany();
  const exits = await database.db.query.routingGroupExit.findMany();
  const members = await database.db.query.routingGroupMember.findMany();
  const interfaces = await database.db.query.wgInterface.findMany();
  const clients = await database.db.query.client.findMany();
  const general = await database.db.query.general.findFirst();
  const journal = await database.db.query.routingPolicyRuntime.findFirst();
  if (
    general?.routingPolicyVersion !== 1 ||
    !journal ||
    journal.applied !== null ||
    journal.pending !== null ||
    groups.some((g) => g.excludedIpv4Prefixes.length)
  )
    throw new Error("Inactive contract failure");
  const compiled = compileRoutingPolicy({
    interfaces: interfaces.map((i) => ({
      interfaceId: i.name,
      ipv4Cidr: i.ipv4Cidr,
      publicKey: i.publicKey,
    })),
    clients,
    groups: groups.map((g) => ({
      ...g,
      memberClientIds: members
        .filter((m) => m.groupId === g.id)
        .map((m) => m.clientId),
      exits: exits.filter((e) => e.groupId === g.id),
    })),
  });
  console.log(
    JSON.stringify(
      {
        preservation: true,
        integrity: true,
        foreignKeys: true,
        migrationRerun: true,
        policyVersion: general.routingPolicyVersion,
        inactiveJournal: true,
        tableEvidence: records.map(({ table, checksum, count }) => ({
          table,
          checksum,
          count,
        })),
        compiler: {
          fingerprint: compiled.fingerprint,
          counts: compiled.counts,
        },
      },
      null,
      2,
    ),
  );
} finally {
  await database.close();
}
