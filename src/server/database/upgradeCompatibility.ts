import type { NodeSqliteExecutor } from '#db/nodeSqlite';

export async function assertSupportedUpgradeDatabase(
  database: NodeSqliteExecutor
) {
  const fields = (await database.execute('PRAGMA table_info(interfaces_table)'))
    .rows;
  if (!fields.some((field) => field.name === 'header_protection_key')) return;
  const general = (await database.execute('PRAGMA table_info(general_table)'))
    .rows;
  if (!general.some((field) => field.name === 'default_interface_id')) {
    throw new Error(
      'Native upstream 15.5 databases require an explicit import; this fork only upgrades its supported migration history'
    );
  }
}
