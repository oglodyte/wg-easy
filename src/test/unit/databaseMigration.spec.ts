import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, describe, expect, test } from 'vitest';

import { finalizePhase1DataMigration } from '#db/phase1Migration';
import { createNodeSqliteDatabase } from '#db/nodeSqlite';
import * as schema from '#db/schema';

const migrationsDirectory = fileURLToPath(
  new URL('../../server/database/migrations', import.meta.url)
);
const temporaryRoots: string[] = [];
const databases: Array<ReturnType<typeof createNodeSqliteDatabase>> = [];

afterEach(async () => {
  await Promise.all(databases.splice(0).map((database) => database.close()));
  await Promise.all(
    temporaryRoots.splice(0).map((root) =>
      fs.rm(root, {
        recursive: true,
        force: true,
      })
    )
  );
});

async function createMigrationSubset(root: string, throughIndex: number) {
  const target = path.join(root, `migrations-through-${throughIndex}`);
  const targetMeta = path.join(target, 'meta');
  await fs.mkdir(targetMeta, { recursive: true });

  const journal = JSON.parse(
    await fs.readFile(
      path.join(migrationsDirectory, 'meta/_journal.json'),
      'utf8'
    )
  ) as {
    version: string;
    dialect: string;
    entries: Array<{ idx: number; tag: string }>;
  };
  const entries = journal.entries.filter((entry) => entry.idx <= throughIndex);

  for (const entry of entries) {
    await fs.copyFile(
      path.join(migrationsDirectory, `${entry.tag}.sql`),
      path.join(target, `${entry.tag}.sql`)
    );
  }
  await fs.writeFile(
    path.join(targetMeta, '_journal.json'),
    JSON.stringify({ ...journal, entries }, null, 2)
  );

  return target;
}

function openDatabase(databasePath: string) {
  const database = createNodeSqliteDatabase(databasePath, schema);
  databases.push(database);
  return database;
}

type TestDatabase = ReturnType<typeof openDatabase>;

async function runMigrations(client: TestDatabase, directory: string) {
  await client.migrate({ migrationsFolder: directory });
}

async function seedRepresentativeData(client: TestDatabase) {
  await client.raw.transaction(async (transaction) => {
    for (const statement of [
      {
        sql: `
          INSERT INTO users_table
            (id, username, password, email, name, role, totp_key, totp_verified, enabled)
          VALUES
            (7, 'phase1-user', 'password-hash', 'phase1@example.test', 'Phase One', 1, NULL, 0, 1)
        `,
        args: [],
      },
      {
        sql: `
          UPDATE interfaces_table
          SET private_key = 'interface-private-preserved',
              public_key = 'interface-public-preserved',
              ipv4_cidr = '10.251.0.0/24',
              ipv6_cidr = 'fd42:251::/64'
          WHERE name = 'wg0'
        `,
        args: [],
      },
      {
        sql: `
          UPDATE hooks_table
          SET pre_up = ': phase1-pre-up', post_down = ': phase1-post-down'
          WHERE id = 'wg0'
        `,
        args: [],
      },
      {
        sql: `
          UPDATE user_configs_table
          SET host = 'wg-easy-stage.lan', port = 51820,
              default_dns = '["1.1.1.1"]',
              default_allowed_ips = '["0.0.0.0/0"]'
          WHERE id = 'wg0'
        `,
        args: [],
      },
      {
        sql: `
          INSERT INTO clients_table
            (id, user_id, interface_id, name, ipv4_address, ipv6_address,
             private_key, public_key, pre_shared_key, server_allowed_ips,
             persistent_keepalive, mtu, enabled)
          VALUES
            (42, 7, 'wg0', 'phase1-client', '10.251.0.42', 'fd42:251::42',
             'client-private-preserved', 'client-public-preserved',
             'client-psk-preserved', '["192.0.2.0/24"]', 25, 1380, 1)
        `,
        args: [],
      },
      {
        sql: `
          INSERT INTO one_time_links_table
            (id, one_time_link, expires_at)
          VALUES
            (42, 'preserved-link-id', '2037-01-01T00:00:00.000Z')
        `,
        args: [],
      },
      {
        sql: `UPDATE general_table SET setup_step = 0 WHERE id = 1`,
        args: [],
      },
    ]) {
      await transaction.execute(statement);
    }
  });
}

async function readPreservationManifest(client: TestDatabase) {
  const result = await client.execute({
    sql: `
      SELECT
        c.id AS client_id,
        c.interface_id,
        c.private_key AS client_private_key,
        c.public_key AS client_public_key,
        c.pre_shared_key,
        c.preferred_config_format,
        i.private_key AS interface_private_key,
        i.public_key AS interface_public_key,
        i.awg_parameters_enabled,
        i.default_config_format,
        i.pending_delete,
        o.id AS link_id,
        o.one_time_link,
        o.config_format AS link_config_format,
        h.pre_up,
        h.post_down,
        u.host,
        u.port,
        g.default_interface_id
      FROM clients_table c
      JOIN interfaces_table i ON i.name = c.interface_id
      JOIN one_time_links_table o ON o.id = c.id
      JOIN hooks_table h ON h.id = i.name
      JOIN user_configs_table u ON u.id = i.name
      JOIN general_table g ON g.id = 1
      WHERE c.id = 42
    `,
    args: [],
  });
  return result.rows[0];
}

describe('Phase 1 schema migration', () => {
  test('loads the complete relational schema without circular initialization errors', () => {
    expect(schema.wgInterface).toBeDefined();
    expect(schema.routingGroup).toBeDefined();
    expect(schema.interfaceRuntimeState).toBeDefined();
    expect(schema.runtimeReconciliationState).toBeDefined();
  });

  test.each([1, 2, 3, 4, 5, 6])(
    'preserves and upgrades the schema recorded after migration 000%d',
    async (startingMigration) => {
      const root = await fs.mkdtemp(path.join(os.tmpdir(), 'wg-easy-p1-'));
      temporaryRoots.push(root);
      const databasePath = path.join(root, 'fixture.db');
      const backupPath = path.join(root, 'fixture.pre-phase1.db');
      const restoredPath = path.join(root, 'fixture.restored.db');
      const configDirectory = path.join(root, 'configs');
      await fs.mkdir(configDirectory, { mode: 0o700 });

      const subsetDirectory = await createMigrationSubset(
        root,
        startingMigration
      );
      let client = openDatabase(databasePath);
      await runMigrations(client, subsetDirectory);
      await seedRepresentativeData(client);
      await client.close();
      await fs.copyFile(databasePath, backupPath);

      const awgMode = startingMigration === 6;
      await fs.writeFile(
        path.join(configDirectory, 'wg0.conf'),
        [
          '[Interface]',
          'PrivateKey = hidden',
          'ListenPort = 51820',
          ...(awgMode ? ['Jc = 7', 'H1 = 12345'] : []),
        ].join('\n'),
        { mode: 0o600 }
      );

      client = openDatabase(databasePath);
      await runMigrations(client, migrationsDirectory);
      const finalized = await finalizePhase1DataMigration(client.raw, {
        configDirectory,
        legacyEnvironment: {},
      });
      expect(finalized.unresolved).toEqual([]);
      expect(finalized.migrated).toHaveLength(1);

      const manifest = await readPreservationManifest(client);
      expect(manifest).toMatchObject({
        client_id: 42,
        interface_id: 'wg0',
        client_private_key: 'client-private-preserved',
        client_public_key: 'client-public-preserved',
        pre_shared_key: 'client-psk-preserved',
        preferred_config_format: 'auto',
        interface_private_key: 'interface-private-preserved',
        interface_public_key: 'interface-public-preserved',
        default_config_format: awgMode ? 'amneziawg' : 'wireguard',
        link_id: 42,
        one_time_link: 'preserved-link-id',
        link_config_format: awgMode ? 'amneziawg' : 'wireguard',
        pre_up: ': phase1-pre-up',
        post_down: ': phase1-post-down',
        host: 'wg-easy-stage.lan',
        port: 51820,
        default_interface_id: 'wg0',
      });
      expect(Number(manifest?.awg_parameters_enabled)).toBe(awgMode ? 1 : 0);
      expect(Number(manifest?.pending_delete)).toBe(0);

      const foreignKeys = await client.execute(
        `PRAGMA foreign_key_list('clients_table')`
      );
      const interfaceForeignKey = foreignKeys.rows.find(
        (row) => row.from === 'interface_id'
      );
      expect(String(interfaceForeignKey?.on_delete).toUpperCase()).toBe(
        'RESTRICT'
      );

      const foreignKeyErrors = await client.execute('PRAGMA foreign_key_check');
      expect(foreignKeyErrors.rows).toEqual([]);
      await client.execute('PRAGMA foreign_keys = ON');
      await expect(
        client.execute(`DELETE FROM interfaces_table WHERE name = 'wg0'`)
      ).rejects.toThrow();

      const runtime = await client.execute(
        `SELECT desired_revision, applied_revision, status FROM runtime_reconciliation_state_table WHERE id = 1`
      );
      expect(runtime.rows[0]).toMatchObject({
        desired_revision: 1,
        applied_revision: 0,
        status: 'pending',
      });
      const groups = await client.execute(
        `SELECT COUNT(*) AS count FROM routing_groups_table`
      );
      expect(Number(groups.rows[0]?.count)).toBe(0);

      await runMigrations(client, migrationsDirectory);
      await expect(
        finalizePhase1DataMigration(client.raw, {
          configDirectory,
          legacyEnvironment: {},
        })
      ).resolves.toEqual({ migrated: [], unresolved: [] });
      expect(await readPreservationManifest(client)).toEqual(manifest);
      await client.close();

      await fs.copyFile(backupPath, restoredPath);
      const restored = openDatabase(restoredPath);
      const restoredColumns = await restored.execute(
        `PRAGMA table_info('interfaces_table')`
      );
      expect(
        restoredColumns.rows.some(
          (row) => row.name === 'awg_parameters_enabled'
        )
      ).toBe(false);
      const restoredClient = await restored.execute(
        `SELECT id, private_key, public_key FROM clients_table WHERE id = 42`
      );
      expect(restoredClient.rows[0]).toMatchObject({
        id: 42,
        private_key: 'client-private-preserved',
        public_key: 'client-public-preserved',
      });
      await restored.close();
    },
    30_000
  );

  test('defaults a new uninitialized database to WireGuard compatibility', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'wg-easy-p1-fresh-'));
    temporaryRoots.push(root);
    const client = openDatabase(path.join(root, 'fresh.db'));
    await runMigrations(client, migrationsDirectory);

    await expect(
      finalizePhase1DataMigration(client.raw, {
        configDirectory: root,
        legacyEnvironment: {},
      })
    ).resolves.toMatchObject({
      migrated: [
        {
          interfaceId: 'wg0',
          awgParametersEnabled: false,
          configFormat: 'wireguard',
          source: 'fresh_install',
        },
      ],
      unresolved: [],
    });
    const interfaceResult = await client.execute(
      `SELECT awg_parameters_enabled, default_config_format FROM interfaces_table WHERE name = 'wg0'`
    );
    expect(interfaceResult.rows[0]).toMatchObject({
      awg_parameters_enabled: 0,
      default_config_format: 'wireguard',
    });
    await client.close();
  });

  test('keeps ambiguous upgrades pending and retryable without guessing', async () => {
    const root = await fs.mkdtemp(
      path.join(os.tmpdir(), 'wg-easy-p1-ambiguous-')
    );
    temporaryRoots.push(root);
    const databasePath = path.join(root, 'ambiguous.db');
    const subsetDirectory = await createMigrationSubset(root, 6);
    const client = openDatabase(databasePath);
    await runMigrations(client, subsetDirectory);
    await seedRepresentativeData(client);
    await runMigrations(client, migrationsDirectory);

    await expect(
      finalizePhase1DataMigration(client.raw, {
        configDirectory: root,
        legacyEnvironment: {},
      })
    ).resolves.toEqual({ migrated: [], unresolved: ['wg0'] });
    const degraded = await client.execute(
      `SELECT status, last_error FROM interface_runtime_state_table WHERE interface_id = 'wg0'`
    );
    expect(degraded.rows[0]).toMatchObject({ status: 'degraded' });
    expect(String(degraded.rows[0]?.last_error)).toContain(
      'Compatibility mode could not be inferred'
    );
    const pending = await client.execute(
      `SELECT default_config_format FROM interfaces_table WHERE name = 'wg0'`
    );
    expect(pending.rows[0]?.default_config_format).toBe('migration_pending');

    await expect(
      finalizePhase1DataMigration(client.raw, {
        configDirectory: root,
        legacyEnvironment: { EXPERIMENTAL_AWG: 'false' },
      })
    ).resolves.toMatchObject({
      migrated: [
        {
          interfaceId: 'wg0',
          awgParametersEnabled: false,
          configFormat: 'wireguard',
          source: 'legacy_environment',
        },
      ],
      unresolved: [],
    });
    await client.close();
  });
});
