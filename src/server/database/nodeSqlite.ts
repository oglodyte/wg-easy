import { AsyncLocalStorage } from 'node:async_hooks';
import { DatabaseSync, type StatementSync } from 'node:sqlite';

import type { MigrationConfig } from 'drizzle-orm/migrator';
import {
  drizzle,
  type AsyncBatchRemoteCallback,
  type AsyncRemoteCallback,
} from 'drizzle-orm/sqlite-proxy';
import { migrate as drizzleMigrate } from 'drizzle-orm/sqlite-proxy/migrator';

declare module 'drizzle-orm/sqlite-proxy' {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  interface SqliteRemoteResult<T = unknown> {
    rowsAffected: number;
    lastInsertRowid?: number | bigint;
  }
}

export type NodeSqliteStatement = {
  sql: string;
  args?: readonly unknown[];
};

export type NodeSqliteResult = {
  rows: Record<string, unknown>[];
  rowsAffected: number;
  lastInsertRowid?: number | bigint;
};

export interface NodeSqliteExecutor {
  execute(statement: string | NodeSqliteStatement): Promise<NodeSqliteResult>;
}

export interface NodeSqliteRawDatabase extends NodeSqliteExecutor {
  transaction<T>(
    callback: (transaction: NodeSqliteExecutor) => Promise<T>
  ): Promise<T>;
}

type SqliteInput = null | number | bigint | string | NodeJS.ArrayBufferView;
type ProxyMethod = Parameters<AsyncRemoteCallback>[2];
type StoreState = 'open' | 'closing' | 'closed';
type LockContext = { active: boolean };

const DEFAULT_BUSY_TIMEOUT_MS = 5_000;
const DEFAULT_STATEMENT_CACHE_SIZE = 512;

class AsyncMutex {
  #locked = false;
  readonly #waiters: Array<() => void> = [];

  async runExclusive<T>(callback: () => T | Promise<T>): Promise<T> {
    const release = await this.#acquire();
    try {
      return await callback();
    } finally {
      release();
    }
  }

  async #acquire(): Promise<() => void> {
    if (this.#locked) {
      await new Promise<void>((resolve) => this.#waiters.push(resolve));
    } else {
      this.#locked = true;
    }

    let released = false;
    return () => {
      if (released) {
        return;
      }
      released = true;
      const next = this.#waiters.shift();
      if (next) {
        next();
      } else {
        this.#locked = false;
      }
    };
  }
}

function normalizeParameter(value: unknown): SqliteInput {
  if (
    value === null ||
    typeof value === 'number' ||
    typeof value === 'bigint' ||
    typeof value === 'string' ||
    ArrayBuffer.isView(value)
  ) {
    return value as SqliteInput;
  }

  throw new TypeError(
    `Unsupported SQLite parameter type: ${
      value === undefined ? 'undefined' : typeof value
    }`
  );
}

function normalizeParameters(values: readonly unknown[]): SqliteInput[] {
  return values.map(normalizeParameter);
}

/**
 * Async Drizzle facade over Node's synchronous SQLite API.
 *
 * A single FIFO mutex prevents unrelated async operations from interleaving.
 * AsyncLocalStorage lets every query inside an awaited transaction reuse the
 * lock held by the outer transaction without deadlocking.
 */
export class NodeSqliteStore<
  TSchema extends Record<string, unknown> = Record<string, never>,
> {
  readonly db;
  readonly raw: NodeSqliteRawDatabase;

  readonly #database: DatabaseSync;
  readonly #mutex = new AsyncMutex();
  readonly #lockContext = new AsyncLocalStorage<LockContext>();
  readonly #statements = new Map<string, StatementSync>();
  readonly #statementCacheSize: number;
  #state: StoreState = 'open';

  constructor(
    databasePath: string,
    schema: TSchema,
    {
      busyTimeoutMs = DEFAULT_BUSY_TIMEOUT_MS,
      statementCacheSize = DEFAULT_STATEMENT_CACHE_SIZE,
    }: {
      busyTimeoutMs?: number;
      statementCacheSize?: number;
    } = {}
  ) {
    if (!Number.isSafeInteger(statementCacheSize) || statementCacheSize < 1) {
      throw new RangeError(
        'SQLite statement cache size must be a positive integer'
      );
    }

    this.#statementCacheSize = statementCacheSize;
    this.#database = new DatabaseSync(databasePath, {
      allowExtension: false,
      enableDoubleQuotedStringLiterals: false,
      enableForeignKeyConstraints: true,
      readBigInts: false,
      timeout: busyTimeoutMs,
    });

    const query: AsyncRemoteCallback = async (sql, params, method) =>
      this.#serialized(() => this.#executeProxy(sql, params, method));
    const batch: AsyncBatchRemoteCallback = async (queries) =>
      this.#serialized(() =>
        queries.map(({ sql, params, method }) =>
          this.#executeProxy(sql, params, method)
        )
      );

    const database = drizzle(query, batch, { schema });
    const transaction = database.transaction.bind(database);
    database.transaction = ((callback, config) =>
      this.#serialized(() =>
        transaction(callback, config)
      )) as typeof transaction;
    this.db = database;

    this.raw = {
      execute: (statement) => this.execute(statement),
      transaction: (callback) =>
        this.#serialized(async () => {
          this.#database.exec('BEGIN IMMEDIATE');
          try {
            const result = await callback(this.raw);
            this.#database.exec('COMMIT');
            return result;
          } catch (error) {
            if (this.#database.isTransaction) {
              this.#database.exec('ROLLBACK');
            }
            throw error;
          }
        }),
    };
  }

  get cachedStatementCount() {
    return this.#statements.size;
  }

  get isOpen() {
    return this.#state === 'open' && this.#database.isOpen;
  }

  async execute(
    statement: string | NodeSqliteStatement
  ): Promise<NodeSqliteResult> {
    const sql = typeof statement === 'string' ? statement : statement.sql;
    const args = typeof statement === 'string' ? [] : (statement.args ?? []);

    return this.#serialized(() => {
      const prepared = this.#prepare(sql);
      const parameters = normalizeParameters(args);
      prepared.setReturnArrays(false);
      if (prepared.columns().length > 0) {
        return {
          rows: prepared.all(...parameters) as Record<string, unknown>[],
          rowsAffected: 0,
        };
      }

      const result = prepared.run(...parameters);
      return {
        rows: [],
        rowsAffected: Number(result.changes),
        lastInsertRowid: result.lastInsertRowid,
      };
    });
  }

  async migrate(config: MigrationConfig): Promise<void> {
    await drizzleMigrate(
      this.db,
      async (queries) => {
        if (queries.length === 0) {
          return;
        }

        await this.#serialized(() => {
          const foreignKeysEnabled = this.#foreignKeysEnabled();
          try {
            this.#database.exec('PRAGMA foreign_keys=OFF');
            for (const query of queries) {
              if (/^\s*PRAGMA\s+journal_mode\s*=/i.test(query)) {
                this.#database.exec(query);
              }
            }

            this.#database.exec('BEGIN IMMEDIATE');
            try {
              for (const query of queries) {
                if (
                  /^\s*PRAGMA\s+(?:foreign_keys|journal_mode)\s*=/i.test(query)
                ) {
                  continue;
                }
                this.#database.exec(query);
              }
              this.#database.exec('COMMIT');
            } catch (error) {
              if (this.#database.isTransaction) {
                this.#database.exec('ROLLBACK');
              }
              throw error;
            }
          } finally {
            this.#database.exec(
              `PRAGMA foreign_keys=${foreignKeysEnabled ? 'ON' : 'OFF'}`
            );
            this.#statements.clear();
          }
        });
      },
      config
    );
  }

  async close(): Promise<void> {
    if (this.#state === 'closed') {
      return;
    }
    if (this.#state === 'closing') {
      await this.#mutex.runExclusive(() => undefined);
      return;
    }

    this.#state = 'closing';
    await this.#mutex.runExclusive(() => {
      if (this.#database.isTransaction) {
        this.#database.exec('ROLLBACK');
      }
      this.#statements.clear();
      if (this.#database.isOpen) {
        this.#database.close();
      }
      this.#state = 'closed';
    });
  }

  #assertOpen() {
    if (this.#state !== 'open' || !this.#database.isOpen) {
      throw new Error('SQLite database is closing or closed');
    }
  }

  async #serialized<T>(callback: () => T | Promise<T>): Promise<T> {
    if (this.#lockContext.getStore()?.active) {
      return callback();
    }

    this.#assertOpen();
    return this.#mutex.runExclusive(async () => {
      const context = { active: true };
      try {
        return await this.#lockContext.run(context, callback);
      } finally {
        context.active = false;
      }
    });
  }

  #prepare(sql: string): StatementSync {
    const cached = this.#statements.get(sql);
    if (cached) {
      this.#statements.delete(sql);
      this.#statements.set(sql, cached);
      return cached;
    }

    const statement = this.#database.prepare(sql);
    this.#statements.set(sql, statement);
    if (this.#statements.size > this.#statementCacheSize) {
      const oldest = this.#statements.keys().next().value;
      if (oldest !== undefined) {
        this.#statements.delete(oldest);
      }
    }
    return statement;
  }

  #executeProxy(sql: string, values: readonly unknown[], method: ProxyMethod) {
    const statement = this.#prepare(sql);
    const parameters = normalizeParameters(values);

    if (method === 'run') {
      const result = statement.run(...parameters);
      return {
        rows: [],
        rowsAffected: Number(result.changes),
        lastInsertRowid: result.lastInsertRowid,
      };
    }

    // Drizzle's proxy mapper consumes positional rows for selected fields and
    // relational queries. Raw callers use execute(), which returns named rows.
    statement.setReturnArrays(true);
    if (method === 'get') {
      return {
        rows: statement.get(...parameters) as never,
        rowsAffected: 0,
      };
    }
    return {
      rows: statement.all(...parameters) as never[],
      rowsAffected: 0,
    };
  }

  #foreignKeysEnabled() {
    const row = this.#database.prepare('PRAGMA foreign_keys').get();
    return Number(row?.foreign_keys) === 1;
  }
}

export function createNodeSqliteDatabase<
  TSchema extends Record<string, unknown>,
>(
  databasePath: string,
  schema: TSchema,
  options?: ConstructorParameters<typeof NodeSqliteStore<TSchema>>[2]
) {
  return new NodeSqliteStore(databasePath, schema, options);
}
