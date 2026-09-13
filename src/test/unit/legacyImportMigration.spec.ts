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
describe('nullable legacy PSK and IPv6 migrations', () => {
  test.each([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10])(
    'preserves schema %s, foreign keys, rerun and snapshot rollback',
    async (index) => {
      const root = await fs.mkdtemp(
        path.join(os.tmpdir(), 'import-migration-')
      );
      const filename = path.join(root, 'test.db');
      let db = createNodeSqliteDatabase(filename, schema);
      try {
        const subset = path.join(root, 'subset');
        await fs.mkdir(path.join(subset, 'meta'), { recursive: true });
        const journal = JSON.parse(
          await fs.readFile(
            path.join(migrationsFolder, 'meta/_journal.json'),
            'utf8'
          )
        );
        journal.entries = journal.entries.filter(
          (entry: { idx: number }) => entry.idx <= index
        );
        for (const entry of journal.entries)
          await fs.copyFile(
            path.join(migrationsFolder, `${entry.tag}.sql`),
            path.join(subset, `${entry.tag}.sql`)
          );
        await fs.writeFile(
          path.join(subset, 'meta/_journal.json'),
          JSON.stringify(journal)
        );
        await db.migrate({ migrationsFolder: subset });
        if (index === 0) {
          // 0000 has tables but no application data; use its production seed next.
          await db.migrate({ migrationsFolder });
        } else {
          await db.raw.execute(
            "INSERT INTO users_table (id,username,password,email,name,role,totp_key,totp_verified,enabled) VALUES (1,'admin','hash','admin@example.test','Admin',1,NULL,0,1)"
          );
          const psk = randomBytes(32).toString('base64');
          await db.raw.execute({
            sql: "INSERT INTO clients_table (id,user_id,interface_id,name,ipv4_address,ipv6_address,private_key,public_key,pre_shared_key,server_allowed_ips,persistent_keepalive,mtu,enabled) VALUES (42,1,'wg0','preserved','10.8.0.2','fd42::2',?,?,?,'[]',25,1420,1)",
            args: [
              randomBytes(32).toString('base64'),
              randomBytes(32).toString('base64'),
              psk,
            ],
          });
          await db.raw.execute(
            "UPDATE sqlite_sequence SET seq=1000 WHERE name='clients_table'"
          );
          await db.raw.execute(
            "INSERT INTO one_time_links_table (id,one_time_link,expires_at) VALUES (42,'nonsecret-test-link','2099-01-01T00:00:00Z')"
          );
          const beforeInterface = (
            await db.raw.execute('SELECT * FROM interfaces_table')
          ).rows[0]!;
          const before = (await db.raw.execute('SELECT * FROM clients_table'))
            .rows[0]!;
          if (index >= 7) {
            await db.raw.execute(
              "INSERT INTO routing_groups_table (id,routing_slot,name) VALUES (1,1,'preserved')"
            );
            await db.raw.execute(
              'INSERT INTO routing_group_members_table (group_id,client_id) VALUES (1,42)'
            );
            await db.raw.execute(
              'INSERT INTO routing_group_exits_table (group_id,client_id,priority) VALUES (1,42,1)'
            );
          }
          await db.close();
          await fs.copyFile(filename, path.join(root, 'backup.db'));
          db = createNodeSqliteDatabase(filename, schema);
          if (index === 8) {
            const fullJournal = JSON.parse(
              await fs.readFile(
                path.join(migrationsFolder, 'meta/_journal.json'),
                'utf8'
              )
            );
            fullJournal.entries = fullJournal.entries.filter(
              (entry: { idx: number }) => entry.idx <= 9
            );
            const latest = fullJournal.entries.at(-1);
            const sql = await fs.readFile(
              path.join(migrationsFolder, `${latest.tag}.sql`),
              'utf8'
            );
            await fs.writeFile(
              path.join(subset, `${latest.tag}.sql`),
              sql.replace(
                'CREATE TABLE `__new_interfaces_table`',
                'SELECT * FROM injected_missing_table;--> statement-breakpoint\nCREATE TABLE `__new_interfaces_table`'
              )
            );
            await fs.writeFile(
              path.join(subset, 'meta/_journal.json'),
              JSON.stringify(fullJournal)
            );
            expect(
              await db.migrate({ migrationsFolder: subset }).then(
                () => false,
                () => true
              )
            ).toBe(true);
            expect(
              (
                await db.raw.execute('PRAGMA table_info(clients_table)')
              ).rows.find((c) => c.name === 'ipv6_address')?.notnull
            ).toBe(1);
            expect(
              (await db.raw.execute('PRAGMA foreign_key_check')).rows
            ).toEqual([]);
            await fs.writeFile(
              path.join(subset, 'meta/_journal.json'),
              JSON.stringify(journal)
            );
          }
          await db.migrate({ migrationsFolder });
          const afterInterface = (
            await db.raw.execute('SELECT * FROM interfaces_table')
          ).rows[0]!;
          expect(
            Object.entries(beforeInterface).every(
              ([k, v]) =>
                afterInterface[k] ===
                (index === 2 && /^h[1-4]$/.test(k) && v !== null
                  ? String(v)
                  : v)
            )
          ).toBe(true);
          const after = (await db.raw.execute('SELECT * FROM clients_table'))
            .rows[0]!;
          expect(Object.entries(before).every(([k, v]) => after[k] === v)).toBe(
            true
          );
          expect(
            (await db.raw.execute('SELECT id FROM one_time_links_table')).rows
          ).toEqual([{ id: 42 }]);
          if (index >= 7) {
            expect(
              (
                await db.raw.execute(
                  'SELECT client_id FROM routing_group_members_table'
                )
              ).rows
            ).toEqual([{ client_id: 42 }]);
            expect(
              (
                await db.raw.execute(
                  'SELECT client_id FROM routing_group_exits_table'
                )
              ).rows
            ).toEqual([{ client_id: 42 }]);
            expect(
              (
                await db.raw.execute(
                  "SELECT seq FROM sqlite_sequence WHERE name='clients_table'"
                )
              ).rows
            ).toEqual([{ seq: 1000 }]);
          }
          await db.raw.execute(
            'UPDATE clients_table SET pre_shared_key=NULL WHERE id=42'
          );
          const rollback = createNodeSqliteDatabase(
            path.join(root, 'backup.db'),
            schema
          );
          try {
            await rollback.migrate({ migrationsFolder: subset });
            expect(
              (
                await rollback.raw.execute(
                  'SELECT pre_shared_key FROM clients_table WHERE id=42'
                )
              ).rows[0]?.pre_shared_key === psk
            ).toBe(true);
          } finally {
            await rollback.close();
          }
        }
        expect((await db.raw.execute('PRAGMA foreign_key_check')).rows).toEqual(
          []
        );
        const beforeRerun = JSON.stringify(
          (await db.raw.execute('SELECT * FROM clients_table')).rows
        );
        await db.migrate({ migrationsFolder });
        expect(
          JSON.stringify(
            (await db.raw.execute('SELECT * FROM clients_table')).rows
          ) === beforeRerun
        ).toBe(true);
        expect((await db.raw.execute('PRAGMA integrity_check')).rows).toEqual([
          { integrity_check: 'ok' },
        ]);
        expect(
          (
            await db.raw.execute('PRAGMA table_info(interfaces_table)')
          ).rows.find((c) => c.name === 'ipv6_cidr')?.notnull
        ).toBe(0);
        const columns = (
          await db.raw.execute('PRAGMA table_info(clients_table)')
        ).rows;
        expect(columns.find((c) => c.name === 'ipv6_address')?.notnull).toBe(0);
        expect(columns.find((c) => c.name === 'pre_shared_key')?.notnull).toBe(
          0
        );
      } finally {
        await db.close();
        await fs.rm(root, { recursive: true, force: true });
      }
    }
  );
});
