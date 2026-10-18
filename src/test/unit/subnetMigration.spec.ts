import { randomBytes } from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, test } from 'vitest';

import { createNodeSqliteDatabase } from '#db/nodeSqlite';
import * as schema from '#db/schema';

const migrationsFolder = fileURLToPath(
  new URL('../../server/database/migrations', import.meta.url)
);

describe('subnet contract migration', () => {
  test.each(Array.from({ length: 12 }, (_, i) => i))(
    'preserves supported start %s and paired old snapshot; rerun and constraints',
    async (index) => {
      const root = await fs.mkdtemp(
        path.join(os.tmpdir(), 'subnet-migration-')
      );
      let database = createNodeSqliteDatabase(
        path.join(root, 'data.db'),
        schema
      );
      try {
        const subset = path.join(root, 'subset');
        await fs.mkdir(path.join(subset, 'meta'), { recursive: true });
        const journal = JSON.parse(
          await fs.readFile(
            path.join(migrationsFolder, 'meta/_journal.json'),
            'utf8'
          )
        );
        const entries = journal.entries.filter(
          (e: { idx: number }) => e.idx <= index
        );
        for (const e of entries)
          await fs.copyFile(
            path.join(migrationsFolder, `${e.tag}.sql`),
            path.join(subset, `${e.tag}.sql`)
          );
        await fs.writeFile(
          path.join(subset, 'meta/_journal.json'),
          JSON.stringify({ ...journal, entries })
        );
        await database.migrate({ migrationsFolder: subset });
        if (index === 0) {
          // 0000 precedes the production seed. Verify this path through that seed.
          await database.migrate({ migrationsFolder });
        } else {
          await database.raw.execute(
            "INSERT INTO users_table (id,username,password,email,name,role,totp_key,totp_verified,enabled) VALUES (1,'admin','hash','admin@example.test','Admin',1,NULL,0,1)"
          );
          const keys = Array.from({ length: 3 }, () =>
            randomBytes(32).toString('base64')
          );
          await database.raw.execute({
            sql: "INSERT INTO clients_table (id,user_id,interface_id,name,ipv4_address,ipv6_address,private_key,public_key,pre_shared_key,server_allowed_ips,persistent_keepalive,mtu,enabled) VALUES (42,1,'wg0','preserved','10.8.0.2','fd42::2',?,?,?,'[]',25,1420,1)",
            args: keys,
          });
          await database.raw.execute(
            "INSERT INTO one_time_links_table (id,one_time_link,expires_at) VALUES (42,'synthetic-test-link','2099-01-01T00:00:00Z')"
          );
          if (index >= 7) {
            await database.raw.execute(
              "INSERT INTO routing_groups_table (id,routing_slot,name) VALUES (17,17,'preserved')"
            );
            await database.raw.execute(
              'INSERT INTO routing_group_members_table (group_id,client_id) VALUES (17,42)'
            );
            await database.raw.execute(
              'INSERT INTO routing_group_exits_table (group_id,client_id,priority) VALUES (17,42,1)'
            );
            await database.raw.execute(
              "INSERT INTO routing_group_runtime_state_table (group_id,evaluated_revision,status) VALUES (17,3,'disabled')"
            );
            await database.raw.execute(
              'INSERT INTO routing_slot_tombstones_table (routing_slot,released_after_revision) VALUES (18,3)'
            );
          }
          const tables = [
            'clients_table',
            'one_time_links_table',
            'hooks_table',
            'user_configs_table',
            ...(index >= 7
              ? [
                  'routing_groups_table',
                  'routing_group_exits_table',
                  'routing_group_members_table',
                  'routing_group_runtime_state_table',
                  'routing_slot_tombstones_table',
                  'runtime_reconciliation_state_table',
                ]
              : []),
          ];
          const before = new Map<string, Record<string, unknown>[]>();
          for (const t of tables)
            before.set(
              t,
              (await database.raw.execute(`SELECT * FROM ${t}`)).rows
            );
          await database.close();
          await fs.copyFile(
            path.join(root, 'data.db'),
            path.join(root, 'before.db')
          );
          database = createNodeSqliteDatabase(
            path.join(root, 'data.db'),
            schema
          );
          await database.migrate({ migrationsFolder });
          await database.migrate({ migrationsFolder });
          for (const [table, rows] of before) {
            const after = (await database.raw.execute(`SELECT * FROM ${table}`))
              .rows;
            expect(
              rows.every((row, i) =>
                Object.entries(row).every(([k, v]) => after[i]?.[k] === v)
              )
            ).toBe(true);
          }
          const rollback = createNodeSqliteDatabase(
            path.join(root, 'before.db'),
            schema
          );
          try {
            expect(
              (await rollback.raw.execute('PRAGMA integrity_check')).rows
            ).toEqual([{ integrity_check: 'ok' }]);
            expect(
              (await rollback.raw.execute('PRAGMA foreign_key_check')).rows
            ).toEqual([]);
            for (const [table, rows] of before)
              expect(
                JSON.stringify(
                  (await rollback.raw.execute(`SELECT * FROM ${table}`)).rows
                ) === JSON.stringify(rows)
              ).toBe(true);
          } finally {
            await rollback.close();
          }
        }
        expect(
          (await database.raw.execute('PRAGMA foreign_key_check')).rows
        ).toEqual([]);
        expect(
          (
            await database.raw.execute(
              'SELECT DISTINCT routing_policy_version FROM general_table'
            )
          ).rows
        ).toEqual([{ routing_policy_version: 1 }]);
        expect(
          (
            await database.raw.execute(
              'SELECT * FROM routing_policy_runtime_table'
            )
          ).rows
        ).toEqual([{ id: 1, applied: null, pending: null }]);
        expect(
          (
            await database.raw.execute(
              'SELECT excluded_ipv4_prefixes FROM routing_groups_table'
            )
          ).rows.every((r) => r.excluded_ipv4_prefixes === '[]')
        ).toBe(true);
        expect(
          await database.raw
            .execute('INSERT INTO routing_policy_runtime_table (id) VALUES (2)')
            .then(
              () => false,
              () => true
            )
        ).toBe(true);
        const indexes = (
          await database.raw.execute(
            'PRAGMA index_list(routing_group_members_table)'
          )
        ).rows;
        expect(
          indexes.some((r) => r.name === 'routing_group_members_client_unique')
        ).toBe(false);
        expect(
          indexes.some(
            (r) =>
              r.name === 'routing_group_members_client_idx' && r.unique === 0
          )
        ).toBe(true);
        if (index >= 7) {
          await database.raw.execute(
            "INSERT INTO routing_groups_table (id,routing_slot,name) VALUES (19,19,'second')"
          );
          await database.raw.execute(
            'INSERT INTO routing_group_members_table (group_id,client_id) VALUES (19,42)'
          );
          expect(
            await database.raw
              .execute(
                'INSERT INTO routing_group_members_table (group_id,client_id) VALUES (19,42)'
              )
              .then(
                () => false,
                () => true
              )
          ).toBe(true);
          expect(
            await database.raw
              .execute(
                'INSERT INTO routing_group_members_table (group_id,client_id) VALUES (19,9999)'
              )
              .then(
                () => false,
                () => true
              )
          ).toBe(true);
          expect(
            await database.raw
              .execute('DELETE FROM clients_table WHERE id=42')
              .then(
                () => false,
                () => true
              )
          ).toBe(true);
        }
      } finally {
        await database.close();
        await fs.rm(root, { recursive: true, force: true });
      }
    }
  );
  test('mid-migration failure rolls back storage, indexes, settings and migration markers', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'subnet-failure-'));
    const database = createNodeSqliteDatabase(
      path.join(root, 'data.db'),
      schema
    );
    try {
      const subset = path.join(root, 'subset');
      await fs.mkdir(path.join(subset, 'meta'), { recursive: true });
      const journal = JSON.parse(
        await fs.readFile(
          path.join(migrationsFolder, 'meta/_journal.json'),
          'utf8'
        )
      );
      for (const e of journal.entries)
        await fs.copyFile(
          path.join(migrationsFolder, `${e.tag}.sql`),
          path.join(subset, `${e.tag}.sql`)
        );
      const current = journal.entries.at(-1);
      await fs.writeFile(
        path.join(subset, 'meta/_journal.json'),
        JSON.stringify({ ...journal, entries: journal.entries.slice(0, -1) })
      );
      await database.migrate({ migrationsFolder: subset });
      const before = (
        await database.raw.execute('SELECT * FROM __drizzle_migrations')
      ).rows;
      const sql = await fs.readFile(
        path.join(subset, `${current.tag}.sql`),
        'utf8'
      );
      await fs.writeFile(
        path.join(subset, `${current.tag}.sql`),
        `${sql}--> statement-breakpoint\nSELECT * FROM injected_missing_table;`
      );
      await fs.writeFile(
        path.join(subset, 'meta/_journal.json'),
        JSON.stringify(journal)
      );
      expect(
        await database.migrate({ migrationsFolder: subset }).then(
          () => false,
          () => true
        )
      ).toBe(true);
      expect(
        (
          await database.raw.execute('PRAGMA table_info(general_table)')
        ).rows.some((r) => r.name === 'routing_policy_version')
      ).toBe(false);
      expect(
        (
          await database.raw.execute(
            'PRAGMA index_list(routing_group_members_table)'
          )
        ).rows.some(
          (r) =>
            r.name === 'routing_group_members_client_unique' && r.unique === 1
        )
      ).toBe(true);
      expect(
        (await database.raw.execute('SELECT * FROM __drizzle_migrations')).rows
      ).toEqual(before);
      expect(
        (await database.raw.execute('PRAGMA foreign_key_check')).rows
      ).toEqual([]);
      await database.migrate({ migrationsFolder });
    } finally {
      await database.close();
      await fs.rm(root, { recursive: true, force: true });
    }
  });
});
