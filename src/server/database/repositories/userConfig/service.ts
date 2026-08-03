import { eq, sql } from 'drizzle-orm';

import { userConfig } from './schema';
import type { UserConfigUpdateType } from './types';

import type { DBType } from '#db/sqlite';

function createPreparedStatement(db: DBType) {
  return {
    get: db.query.userConfig
      .findFirst({ where: eq(userConfig.id, sql.placeholder('interface')) })
      .prepare(),
  };
}

export class UserConfigService {
  #db: DBType;
  #statements: ReturnType<typeof createPreparedStatement>;

  constructor(db: DBType) {
    this.#db = db;
    this.#statements = createPreparedStatement(db);
  }

  async get(interfaceId: string) {
    const userConfig = await this.#statements.get.execute({
      interface: interfaceId,
    });

    if (!userConfig) {
      throw new Error('User config not found');
    }

    return userConfig;
  }

  // TODO: wrap ipv6 host in square brackets

  /**
   * sets host of user config
   *
   * The endpoint port is intentionally independent from the interface listen port.
   */
  updateHostPort(interfaceId: string, host: string, port: number) {
    return this.#db
      .update(userConfig)
      .set({ host, port })
      .where(eq(userConfig.id, interfaceId))
      .execute();
  }

  update(interfaceId: string, data: Partial<UserConfigUpdateType>) {
    return this.#db
      .update(userConfig)
      .set(data)
      .where(eq(userConfig.id, interfaceId))
      .execute();
  }
}
