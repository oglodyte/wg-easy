import { createRequire } from "node:module";
import { rmSync } from "node:fs";

const require = createRequire("/app/server/index.mjs");
const {
  version: libsqlVersion,
} = require("/app/server/node_modules/libsql/package.json");
const { Database } = require("/app/server/node_modules/libsql");
const databasePath = `/tmp/wg-easy-libsql-smoke-${process.pid}.db`;

if (process.version !== "v22.22.0") {
  throw new Error(`Unexpected Node version ${process.version}`);
}
if (libsqlVersion !== "0.5.29") {
  throw new Error(`Unexpected libSQL version ${libsqlVersion}`);
}

const database = new Database(databasePath);

try {
  database.exec(
    "CREATE TABLE smoke (id INTEGER PRIMARY KEY, value TEXT NOT NULL)",
  );

  const transaction = database.transaction((round) => {
    database
      .prepare("INSERT INTO smoke (value) VALUES (?)")
      .run(`value-${round}`);
    return database
      .prepare("SELECT value FROM smoke WHERE id = last_insert_rowid()")
      .get().value;
  });

  for (let round = 0; round < 100; round += 1) {
    const expected = `value-${round}`;
    if (transaction(round) !== expected) {
      throw new Error(`Unexpected libSQL value at round ${round}`);
    }

    if (round % 25 === 0) {
      globalThis.gc?.();
      await new Promise((resolve) => setImmediate(resolve));
    }
  }
} finally {
  database.close();
  for (let attempt = 0; attempt < 5; attempt += 1) {
    globalThis.gc?.();
    await new Promise((resolve) => setImmediate(resolve));
  }
  rmSync(databasePath, { force: true });
  rmSync(`${databasePath}-shm`, { force: true });
  rmSync(`${databasePath}-wal`, { force: true });
}

// libSQL can retain native bookkeeping after close. Finalizers have run above;
// do not let that bookkeeping turn this bounded architecture smoke into a hang.
process.exit(0);
