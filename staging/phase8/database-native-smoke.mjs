import { rmSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";

const databasePath = `/tmp/wg-easy-node-sqlite-smoke-${process.pid}.db`;

if (process.version !== "v24.19.0") {
  throw new Error(`Unexpected Node version ${process.version}`);
}

const database = new DatabaseSync(databasePath, {
  enableForeignKeyConstraints: true,
  timeout: 5_000,
});
const statements = new Map();

function prepare(sql) {
  const cached = statements.get(sql);
  if (cached) {
    return cached;
  }
  const statement = database.prepare(sql);
  statements.set(sql, statement);
  return statement;
}

try {
  database.exec(
    "CREATE TABLE smoke (id INTEGER PRIMARY KEY, value TEXT NOT NULL)",
  );

  for (let round = 0; round < 100; round += 1) {
    const expected = `value-${round}`;
    database.exec("BEGIN IMMEDIATE");
    try {
      prepare("INSERT INTO smoke (value) VALUES (?)").run(expected);
      const actual = prepare(
        "SELECT value FROM smoke WHERE id = last_insert_rowid()",
      ).get().value;
      if (actual !== expected) {
        throw new Error(`Unexpected SQLite value at round ${round}`);
      }
      database.exec("COMMIT");
    } catch (error) {
      if (database.isTransaction) {
        database.exec("ROLLBACK");
      }
      throw error;
    }

    if (round % 25 === 0) {
      globalThis.gc?.();
      await new Promise((resolve) => setImmediate(resolve));
    }
  }
} finally {
  statements.clear();
  database.close();
  for (let attempt = 0; attempt < 5; attempt += 1) {
    globalThis.gc?.();
    await new Promise((resolve) => setImmediate(resolve));
  }
  rmSync(databasePath, { force: true });
  rmSync(`${databasePath}-shm`, { force: true });
  rmSync(`${databasePath}-wal`, { force: true });
}
