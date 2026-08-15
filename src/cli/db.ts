import * as schema from '#server/database/schema';
import { createNodeSqliteDatabase } from '#server/database/nodeSqlite';

const database = createNodeSqliteDatabase('/etc/wireguard/wg-easy.db', schema);
export const db = database.db;

export async function closeDatabase() {
  await database.close();
}

export { schema };
