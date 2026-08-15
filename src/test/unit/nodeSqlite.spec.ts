import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { integer, sqliteTable, text } from 'drizzle-orm/sqlite-core';
import { afterEach, describe, expect, test } from 'vitest';

import { createNodeSqliteDatabase } from '#db/nodeSqlite';

const item = sqliteTable('items', {
  id: integer().primaryKey({ autoIncrement: true }),
  value: text().notNull(),
});
const testSchema = { item };
const databases: Array<ReturnType<typeof createNodeSqliteDatabase>> = [];
const temporaryRoots: string[] = [];

afterEach(async () => {
  await Promise.all(databases.splice(0).map((database) => database.close()));
  await Promise.all(
    temporaryRoots
      .splice(0)
      .map((root) => fs.rm(root, { recursive: true, force: true }))
  );
});

async function createDatabase(
  options?: Parameters<typeof createNodeSqliteDatabase>[2]
) {
  const database = createNodeSqliteDatabase(':memory:', testSchema, options);
  databases.push(database);
  await database.execute(`
    CREATE TABLE items (
      id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
      value TEXT NOT NULL
    )
  `);
  return database;
}

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}

describe('Node SQLite async adapter', () => {
  test('holds the FIFO lock across an awaited transaction callback', async () => {
    const database = await createDatabase();
    const entered = deferred();
    const release = deferred();
    const events: string[] = [];

    const transaction = database.raw.transaction(async (tx) => {
      await tx.execute({
        sql: 'INSERT INTO items (value) VALUES (?)',
        args: ['transaction-first'],
      });
      events.push('transaction-waiting');
      entered.resolve();
      await release.promise;
      await tx.execute({
        sql: 'INSERT INTO items (value) VALUES (?)',
        args: ['transaction-second'],
      });
      events.push('transaction-committed');
    });

    await entered.promise;
    const standalone = database
      .execute({
        sql: 'INSERT INTO items (value) VALUES (?)',
        args: ['standalone'],
      })
      .then(() => events.push('standalone-finished'));
    await new Promise((resolve) => setImmediate(resolve));
    expect(events).toEqual(['transaction-waiting']);

    release.resolve();
    await Promise.all([transaction, standalone]);
    expect(events).toEqual([
      'transaction-waiting',
      'transaction-committed',
      'standalone-finished',
    ]);
    await expect(
      database.execute('SELECT value FROM items ORDER BY id')
    ).resolves.toMatchObject({
      rows: [
        { value: 'transaction-first' },
        { value: 'transaction-second' },
        { value: 'standalone' },
      ],
    });
  });

  test('rolls back async failures and supports nested Drizzle savepoints', async () => {
    const database = await createDatabase();

    await expect(
      database.raw.transaction(async (tx) => {
        await tx.execute({
          sql: 'INSERT INTO items (value) VALUES (?)',
          args: ['rolled-back'],
        });
        await new Promise((resolve) => setImmediate(resolve));
        throw new Error('injected transaction failure');
      })
    ).rejects.toThrow('injected transaction failure');

    await database.db.transaction(async (tx) => {
      await tx.insert(item).values({ value: 'outer-first' }).execute();
      await expect(
        tx.transaction(async (nested) => {
          await nested.insert(item).values({ value: 'nested' }).execute();
          throw new Error('injected savepoint failure');
        })
      ).rejects.toThrow('injected savepoint failure');
      await tx.insert(item).values({ value: 'outer-second' }).execute();
    });

    await expect(
      database.execute('SELECT value FROM items ORDER BY id')
    ).resolves.toMatchObject({
      rows: [{ value: 'outer-first' }, { value: 'outer-second' }],
    });
  });

  test('bounds and reuses the prepared-statement cache', async () => {
    const database = await createDatabase({ statementCacheSize: 3 });

    for (let index = 0; index < 20; index += 1) {
      await database.execute(`SELECT ${index} AS value`);
    }
    expect(database.cachedStatementCount).toBe(3);

    for (let index = 0; index < 100; index += 1) {
      await database.execute({
        sql: 'SELECT value FROM items WHERE id = ?',
        args: [index],
      });
    }
    expect(database.cachedStatementCount).toBe(3);
  });

  test('queues close behind active work and rejects new operations', async () => {
    const database = await createDatabase();
    const entered = deferred();
    const release = deferred();

    const transaction = database.raw.transaction(async (tx) => {
      entered.resolve();
      await release.promise;
      await tx.execute({
        sql: 'INSERT INTO items (value) VALUES (?)',
        args: ['completed-before-close'],
      });
    });
    await entered.promise;

    const closing = database.close();
    expect(database.isOpen).toBe(false);
    await expect(database.execute('SELECT 1')).rejects.toThrow(
      'SQLite database is closing or closed'
    );

    release.resolve();
    await Promise.all([transaction, closing]);
    expect(database.isOpen).toBe(false);
    await expect(database.close()).resolves.toBeUndefined();
  });

  test('rolls back a failed migration batch and leaves no applied marker', async () => {
    const root = await fs.mkdtemp(
      path.join(os.tmpdir(), 'wg-easy-node-sqlite-migration-')
    );
    temporaryRoots.push(root);
    const migrationsDirectory = path.join(root, 'migrations');
    await fs.mkdir(path.join(migrationsDirectory, 'meta'), { recursive: true });
    await fs.writeFile(
      path.join(migrationsDirectory, 'meta/_journal.json'),
      JSON.stringify({
        version: '7',
        dialect: 'sqlite',
        entries: [
          {
            idx: 0,
            version: '6',
            when: 1,
            tag: '0000_injected_failure',
            breakpoints: true,
          },
        ],
      })
    );
    await fs.writeFile(
      path.join(migrationsDirectory, '0000_injected_failure.sql'),
      [
        'PRAGMA foreign_keys=OFF;',
        '--> statement-breakpoint',
        'CREATE TABLE migration_should_rollback (id INTEGER PRIMARY KEY);',
        '--> statement-breakpoint',
        'INSERT INTO missing_table (id) VALUES (1);',
        '--> statement-breakpoint',
        'PRAGMA foreign_keys=ON;',
      ].join('\n')
    );

    const database = createNodeSqliteDatabase(
      path.join(root, 'migration.db'),
      testSchema
    );
    databases.push(database);
    await expect(
      database.migrate({ migrationsFolder: migrationsDirectory })
    ).rejects.toThrow();

    const table = await database.execute({
      sql: `SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`,
      args: ['migration_should_rollback'],
    });
    const marker = await database.execute(
      'SELECT COUNT(*) AS count FROM __drizzle_migrations'
    );
    const foreignKeys = await database.execute('PRAGMA foreign_keys');
    expect(table.rows).toEqual([]);
    expect(Number(marker.rows[0]?.count)).toBe(0);
    expect(Number(foreignKeys.rows[0]?.foreign_keys)).toBe(1);
  });
});
