import { randomBytes } from 'node:crypto';

import { eq, sql } from 'drizzle-orm';

import { oneTimeLink } from './schema';

import type { ID } from '#server/utils/types';
import { resolveClientConfigFormat } from '#server/utils/wgHelper';
import type { ConfigFormat } from '#shared/types/runtime';
import type { DBType } from '#db/sqlite';

function createPreparedStatement(db: DBType) {
  return {
    delete: db
      .delete(oneTimeLink)
      .where(eq(oneTimeLink.id, sql.placeholder('id')))
      .prepare(),
    create: db
      .insert(oneTimeLink)
      .values({
        id: sql.placeholder('id'),
        oneTimeLink: sql.placeholder('oneTimeLink'),
        expiresAt: sql.placeholder('expiresAt'),
        configFormat: sql.placeholder('configFormat'),
      })
      .onConflictDoUpdate({
        target: oneTimeLink.id,
        set: {
          expiresAt: sql.placeholder('expiresAt') as never as string,
          configFormat: sql.placeholder('configFormat') as never as
            'wireguard' | 'amneziawg',
        },
      })
      .prepare(),
    erase: db
      .update(oneTimeLink)
      .set({ expiresAt: sql.placeholder('expiresAt') as never as string })
      .where(eq(oneTimeLink.id, sql.placeholder('id')))
      .prepare(),
    findByOneTimeLink: db.query.oneTimeLink
      .findFirst({
        where: eq(oneTimeLink.oneTimeLink, sql.placeholder('oneTimeLink')),
      })
      .prepare(),
  };
}

export class OneTimeLinkService {
  #db: DBType;
  #statements: ReturnType<typeof createPreparedStatement>;

  constructor(db: DBType) {
    this.#db = db;
    this.#statements = createPreparedStatement(db);
  }

  delete(id: ID) {
    return this.#statements.delete.execute({ id });
  }

  getByOtl(oneTimeLink: string) {
    return this.#statements.findByOneTimeLink.execute({ oneTimeLink });
  }

  async generate(id: ID, requestedFormat: ConfigFormat = 'auto') {
    // The link is a bearer credential. Keep it independent from the client ID
    // and use enough CSPRNG entropy that the short validity window is defense
    // in depth rather than the primary protection against guessing.
    const oneTimeLink = randomBytes(32).toString('base64url');
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();

    const client = await this.#db.query.client.findFirst({
      where: (table, { eq }) => eq(table.id, id),
      with: { interface: true },
    });
    if (!client) {
      throw new Error('Client not found');
    }

    const configFormat = resolveClientConfigFormat(
      client.interface,
      client,
      requestedFormat
    );

    return this.#statements.create.execute({
      id,
      oneTimeLink,
      expiresAt,
      configFormat,
    });
  }

  erase(id: ID) {
    // SECURITY
    // This is known the extend the Window for brute force attacks
    // Reason: Set the expiresAt to 10 seconds in the future to allow a second request to get the otl
    // some browser apparently make two requests when downloading a file
    // cant find the bug report anymore, maybe this can be removed?
    const expiresAt = new Date(Date.now() + 10 * 1000).toISOString();
    return this.#statements.erase.execute({ id, expiresAt });
  }
}
