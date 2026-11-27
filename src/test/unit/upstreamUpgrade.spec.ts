import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { describe, test, expect, vi } from 'vitest';
import { createNodeSqliteDatabase } from '#db/nodeSqlite';
import * as schema from '#db/schema';
import { InterfaceService } from '#db/repositories/interface/service';
import { InterfaceUpdateSchema } from '#db/repositories/interface/types';
import { publicInterface } from '#server/utils/publicInterface';
import { assertHeaderProtectionConfiguration } from '#server/utils/headerProtection';
import { HeaderProtectionKeySchema } from '#server/utils/types';
import { buildAwgLines } from '#server/utils/awg';
import type { InterfaceType } from '#db/repositories/interface/types';

vi.mock('#server/utils/config', () => ({
  WG_ENV: { WG_EXECUTABLE: 'awg', PORT: 51821 },
}));

const migrationsFolder = fileURLToPath(
  new URL('../../server/database/migrations', import.meta.url)
);
const interfaceFields = [
  'header_protection_key',
  'content_padding_addition',
  'rekey_after_time',
  'rekey_timeout',
  'reject_after_time',
  'keepalive_timeout',
  'max_handshake_attempts',
  'random_trailers',
  'disable_cookies',
];
const clientFields = interfaceFields.filter(
  (name) => !['header_protection_key', 'random_trailers'].includes(name)
);

describe('upstream 15.5 upgrade boundary', () => {
  test.each(Array.from({ length: 13 }, (_, i) => i))(
    'upgrades historical schema %s with null defaults and rerun preservation',
    async (index) => {
      const root = await fs.mkdtemp(
        path.join(os.tmpdir(), 'upstream-upgrade-')
      );
      const database = createNodeSqliteDatabase(
        path.join(root, 'test.db'),
        schema
      );
      try {
        const journal = JSON.parse(
          await fs.readFile(
            path.join(migrationsFolder, 'meta/_journal.json'),
            'utf8'
          )
        );
        const entries = journal.entries.filter(
          (entry: { idx: number }) => entry.idx <= index
        );
        const subset = path.join(root, 'subset');
        await fs.mkdir(path.join(subset, 'meta'), { recursive: true });
        for (const entry of entries)
          await fs.copyFile(
            path.join(migrationsFolder, entry.tag + '.sql'),
            path.join(subset, entry.tag + '.sql')
          );
        await fs.writeFile(
          path.join(subset, 'meta/_journal.json'),
          JSON.stringify({ ...journal, entries })
        );
        await database.migrate({ migrationsFolder: subset });
        const before = (
          await database.raw.execute('SELECT * FROM interfaces_table')
        ).rows;
        await database.migrate({ migrationsFolder });
        const after = (
          await database.raw.execute('SELECT * FROM interfaces_table')
        ).rows;
        expect(
          before.every((row, i) =>
            Object.entries(row).every(([k, v]) =>
              index === 2 && ['h1', 'h2', 'h3', 'h4'].includes(k)
                ? String(after[i]?.[k]) === String(v)
                : after[i]?.[k] === v
            )
          )
        ).toBe(true);
        expect(
          after.every((row) =>
            interfaceFields.every((field) => row[field] === null)
          )
        ).toBe(true);
        for (const [table, fields] of [
          ['interfaces_table', interfaceFields],
          ['clients_table', clientFields],
        ] as const) {
          const columns = (
            await database.raw.execute(`PRAGMA table_info(${table})`)
          ).rows.map((row) => row.name);
          expect(fields.every((field) => columns.includes(field))).toBe(true);
        }
        const count = (
          await database.raw.execute('SELECT * FROM __drizzle_migrations')
        ).rows.length;
        await database.migrate({ migrationsFolder });
        expect(
          (await database.raw.execute('SELECT * FROM __drizzle_migrations'))
            .rows
        ).toHaveLength(count);
        expect(
          (await database.raw.execute('PRAGMA foreign_key_check')).rows
        ).toEqual([]);
      } finally {
        await database.close();
        await fs.rm(root, { recursive: true, force: true });
      }
    }
  );

  test('refuses native upstream history before creating a migration journal', async () => {
    const database = createNodeSqliteDatabase(':memory:', schema);
    try {
      await database.raw.execute(
        'CREATE TABLE interfaces_table (header_protection_key TEXT)'
      );
      await database.raw.execute('CREATE TABLE general_table (id INTEGER)');
      await expect(database.migrate({ migrationsFolder })).rejects.toThrow(
        'Native upstream 15.5'
      );
      expect(
        (
          await database.raw.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
          )
        ).rows.map((row) => row.name)
      ).toEqual(['general_table', 'interfaces_table']);
    } finally {
      await database.close();
    }
  });

  test('rolls back all AWG columns and migration markers after a late failure', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'upstream-failure-'));
    const database = createNodeSqliteDatabase(
      path.join(root, 'test.db'),
      schema
    );
    try {
      const journal = JSON.parse(
        await fs.readFile(
          path.join(migrationsFolder, 'meta/_journal.json'),
          'utf8'
        )
      );
      const subset = path.join(root, 'subset');
      await fs.mkdir(path.join(subset, 'meta'), { recursive: true });
      for (const entry of journal.entries)
        await fs.copyFile(
          path.join(migrationsFolder, entry.tag + '.sql'),
          path.join(subset, entry.tag + '.sql')
        );
      await fs.writeFile(
        path.join(subset, 'meta/_journal.json'),
        JSON.stringify({ ...journal, entries: journal.entries.slice(0, -1) })
      );
      await database.migrate({ migrationsFolder: subset });
      const before = (
        await database.raw.execute('SELECT * FROM __drizzle_migrations')
      ).rows;
      await fs.appendFile(
        path.join(subset, journal.entries.at(-1).tag + '.sql'),
        '\n--> statement-breakpoint\nSELECT * FROM deliberate_missing_table;'
      );
      await fs.writeFile(
        path.join(subset, 'meta/_journal.json'),
        JSON.stringify(journal)
      );
      await expect(
        database.migrate({ migrationsFolder: subset })
      ).rejects.toThrow();
      for (const [table, fields] of [
        ['interfaces_table', interfaceFields],
        ['clients_table', clientFields],
      ] as const) {
        expect(
          (await database.raw.execute(`PRAGMA table_info(${table})`)).rows.some(
            (row) => fields.includes(String(row.name))
          )
        ).toBe(false);
      }
      expect(
        (await database.raw.execute('SELECT * FROM __drizzle_migrations')).rows
      ).toEqual(before);
      expect(
        (await database.raw.execute('PRAGMA foreign_key_check')).rows
      ).toEqual([]);
    } finally {
      await database.close();
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  test('validates stored secrets when optional updates are omitted or explicitly undefined', async () => {
    const database = createNodeSqliteDatabase(':memory:', schema);
    try {
      await database.migrate({ migrationsFolder });
      const key = randomBytes(32).toString('base64');
      await database.raw.execute({
        sql: "UPDATE interfaces_table SET header_protection_key=?,s1=12,s2=12,s3=12,s4=12,h1='5',h2='6',h3='7',h4='8',default_config_format='wireguard' WHERE name='wg0'",
        args: [key],
      });
      const service = new InterfaceService(database.db);
      const data = InterfaceUpdateSchema.parse(await service.getByName('wg0'));
      for (const headerProtectionKey of [undefined, '']) {
        await expect(
          service.update('wg0', { ...data, s4: 11, headerProtectionKey })
        ).rejects.toThrow();
        const unchanged = await service.getByName('wg0');
        expect(unchanged.s4).toBe(12);
        expect(unchanged.headerProtectionKey === key).toBe(true);
      }
      const { headerProtectionKey: _secret, ...omitted } = data;
      await expect(
        service.update('wg0', { ...omitted, s4: 11 })
      ).rejects.toThrow();
      await expect(
        service.update('wg0', { ...omitted, s4: 12.5 })
      ).rejects.toThrow();
      await service.update('wg0', { ...omitted, rekeyTimeout: '6' });
      expect((await service.getByName('wg0')).headerProtectionKey === key).toBe(
        true
      );
      await service.update('wg0', {
        ...data,
        headerProtectionKey: null,
        s4: 0,
      });
      expect((await service.getByName('wg0')).headerProtectionKey).toBeNull();
    } finally {
      await database.close();
    }
  });

  test('redacts the header key and checks complete persisted padding state', () => {
    const key = randomBytes(32).toString('base64');
    const value = {
      privateKey: key,
      headerProtectionKey: key,
      s1: 12,
      s2: 12,
      s3: 12,
      s4: 12,
    };
    expect(publicInterface(value as InterfaceType)).not.toHaveProperty(
      'headerProtectionKey'
    );
    expect(publicInterface(value as InterfaceType)).not.toHaveProperty(
      'privateKey'
    );
    expect(publicInterface(value as InterfaceType).hasHeaderProtectionKey).toBe(
      true
    );
    expect(() => assertHeaderProtectionConfiguration(value)).not.toThrow();
    expect(() =>
      assertHeaderProtectionConfiguration({ ...value, s4: 11 })
    ).toThrow();
    expect(
      HeaderProtectionKeySchema.safeParse(
        'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
      ).success
    ).toBe(false);
    expect(
      buildAwgLines({ ContentPaddingAddition: 0, RandomTrailers: false })
    ).toEqual(['ContentPaddingAddition = 0', 'RandomTrailers = off']);
  });
});
