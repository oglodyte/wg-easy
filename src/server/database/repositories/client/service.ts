import { eq, sql, or, like, and } from 'drizzle-orm';
import { containsCidr, parseCidr } from 'cidr-tools';

import { client } from './schema';
import type {
  ClientCreateFromExistingType,
  ClientCreateType,
  ClientQueryType,
  UpdateClientType,
} from './types';

import { nextIP } from '#server/utils/ip';
import type { ID } from '#server/utils/types';
import { wg } from '#server/utils/wgHelper';
import { bumpDesiredRevision } from '#db/repositories/runtime/service';
import type { DBType } from '#db/sqlite';
import { wgInterface, userConfig } from '#db/schema';

export class InterfaceUnavailableForClientCreationError extends Error {}

function createPreparedStatement(db: DBType) {
  return {
    findAll: db.query.client
      .findMany({
        with: {
          oneTimeLink: true,
        },
      })
      .prepare(),
    findById: db.query.client
      .findFirst({ where: eq(client.id, sql.placeholder('id')) })
      .prepare(),
  };
}

export class ClientService {
  #db: DBType;
  #statements: ReturnType<typeof createPreparedStatement>;

  constructor(db: DBType) {
    this.#db = db;
    this.#statements = createPreparedStatement(db);
  }

  /**
   * Never return values directly from this function. Use {@link getAllPublic} instead.
   */
  async getAll() {
    const result = await this.#statements.findAll.execute();
    return result.map((row) => ({
      ...row,
      createdAt: new Date(row.createdAt),
      updatedAt: new Date(row.updatedAt),
    }));
  }

  async getAllForInterface(interfaceId: string) {
    const result = await this.#db.query.client
      .findMany({
        where: eq(client.interfaceId, interfaceId),
        with: { oneTimeLink: true },
      })
      .execute();
    return result.map((row) => ({
      ...row,
      createdAt: new Date(row.createdAt),
      updatedAt: new Date(row.updatedAt),
    }));
  }

  async getAllForInterfaces(interfaceIds: readonly string[]) {
    const clients = await Promise.all(
      [...new Set(interfaceIds)].map((interfaceId) =>
        this.getAllForInterface(interfaceId)
      )
    );
    return clients.flat();
  }

  /**
   * Returns all clients without sensitive data
   */
  async getAllPublic({ filter, sort, interfaceId }: ClientQueryType = {}) {
    const filters = [];

    if (filter?.trim()) {
      const filterPattern = `%${filter?.toLowerCase()}%`;
      filters.push(
        or(
          like(client.name, filterPattern),
          like(client.ipv4Address, filterPattern),
          like(client.ipv6Address, filterPattern)
        )
      );
    }
    if (interfaceId) filters.push(eq(client.interfaceId, interfaceId));

    const result = await this.#db.query.client
      .findMany({
        with: {
          oneTimeLink: true,
        },
        where: and(...filters),
        columns: {
          privateKey: false,
          preSharedKey: false,
        },
        orderBy: (t, { asc, desc }) => {
          if (sort === 'desc') {
            return desc(t.name);
          } else {
            // default to asc
            return asc(t.name);
          }
        },
      })
      .execute();

    return result.map((row) => ({
      ...row,
      createdAt: new Date(row.createdAt),
      updatedAt: new Date(row.updatedAt),
    }));
  }

  /**
   * Returns all clients without sensitive data belonging to user
   */
  async getAllForUser(
    userId: ID,
    { filter, sort, interfaceId }: ClientQueryType = {}
  ) {
    const filters = [];

    if (filter?.trim()) {
      const filterPattern = `%${filter?.toLowerCase()}%`;
      filters.push(
        or(
          like(client.name, filterPattern),
          like(client.ipv4Address, filterPattern),
          like(client.ipv6Address, filterPattern)
        )
      );
    }
    if (interfaceId) filters.push(eq(client.interfaceId, interfaceId));

    const result = await this.#db.query.client
      .findMany({
        where: and(eq(client.userId, userId), ...filters),
        with: { oneTimeLink: true },
        columns: {
          privateKey: false,
          preSharedKey: false,
        },
        orderBy: (t, { asc, desc }) => {
          if (sort === 'desc') {
            return desc(t.name);
          } else {
            // default to asc
            return asc(t.name);
          }
        },
      })
      .execute();

    return result.map((row) => ({
      ...row,
      createdAt: new Date(row.createdAt),
      updatedAt: new Date(row.updatedAt),
    }));
  }

  get(id: ID) {
    return this.#statements.findById.execute({ id });
  }

  async create({ name, expiresAt, interfaceId }: ClientCreateType) {
    const privateKey = await wg.generatePrivateKey();
    const publicKey = await wg.getPublicKey(privateKey);
    const preSharedKey = await wg.generatePreSharedKey();

    return this.#db.transaction(async (tx) => {
      const generalConfig = await tx.query.general
        .findFirst({ columns: { defaultInterfaceId: true } })
        .execute();
      if (!generalConfig) throw new Error('General Config not found');
      const selectedInterfaceId =
        interfaceId ?? generalConfig.defaultInterfaceId;
      const clients = await tx.query.client
        .findMany({ where: eq(client.interfaceId, selectedInterfaceId) })
        .execute();
      const clientInterface = await tx.query.wgInterface
        .findFirst({
          where: eq(wgInterface.name, selectedInterfaceId),
        })
        .execute();

      if (!clientInterface) {
        throw new Error('WireGuard interface not found');
      }
      if (clientInterface.pendingDelete) {
        throw new InterfaceUnavailableForClientCreationError(
          'WireGuard interface is pending deletion'
        );
      }

      const clientConfig = await tx.query.userConfig
        .findFirst({
          where: eq(userConfig.id, clientInterface.name),
        })
        .execute();

      if (!clientConfig) {
        throw new Error('WireGuard interface configuration not found');
      }

      const ipv4Cidr = parseCidr(clientInterface.ipv4Cidr);
      const ipv4Address = nextIP(4, ipv4Cidr, clients);
      const ipv6Cidr = parseCidr(clientInterface.ipv6Cidr);
      const ipv6Address = nextIP(6, ipv6Cidr, clients);

      const result = await tx
        .insert(client)
        .values({
          name,
          // TODO: properly assign user id
          userId: 1,
          interfaceId: selectedInterfaceId,
          expiresAt,
          privateKey,
          publicKey,
          preSharedKey,
          ipv4Address,
          ipv6Address,
          mtu: clientConfig.defaultMtu,
          jC: clientConfig.defaultJC,
          jMin: clientConfig.defaultJMin,
          jMax: clientConfig.defaultJMax,
          i1: clientConfig.defaultI1,
          i2: clientConfig.defaultI2,
          i3: clientConfig.defaultI3,
          i4: clientConfig.defaultI4,
          i5: clientConfig.defaultI5,
          persistentKeepalive: clientConfig.defaultPersistentKeepalive,
          serverAllowedIps: [],
          enabled: true,
        })
        .returning({ clientId: client.id })
        .execute();
      await bumpDesiredRevision(tx, [selectedInterfaceId]);
      return result;
    });
  }

  toggle(id: ID, enabled: boolean) {
    return this.#db.transaction(async (tx) => {
      const existing = await tx.query.client
        .findFirst({ where: eq(client.id, id) })
        .execute();
      if (!existing) throw new Error('Client not found');
      await tx
        .update(client)
        .set({ enabled })
        .where(eq(client.id, id))
        .execute();
      await bumpDesiredRevision(tx, [existing.interfaceId]);
    });
  }

  delete(id: ID) {
    return this.#db.transaction(async (tx) => {
      const existing = await tx.query.client
        .findFirst({ where: eq(client.id, id) })
        .execute();
      if (!existing) throw new Error('Client not found');
      await tx.delete(client).where(eq(client.id, id)).execute();
      await bumpDesiredRevision(tx, [existing.interfaceId]);
    });
  }

  update(id: ID, data: UpdateClientType) {
    return this.#db.transaction(async (tx) => {
      const existingClient = await tx.query.client
        .findFirst({ where: eq(client.id, id) })
        .execute();
      if (!existingClient) throw new Error('Client not found');
      const clientInterface = await tx.query.wgInterface
        .findFirst({
          where: eq(wgInterface.name, existingClient.interfaceId),
        })
        .execute();

      if (!clientInterface) {
        throw new Error('WireGuard interface not found');
      }

      if (!containsCidr(clientInterface.ipv4Cidr, data.ipv4Address)) {
        throw new Error('IPv4 address is not within the CIDR range');
      }

      if (!containsCidr(clientInterface.ipv6Cidr, data.ipv6Address)) {
        throw new Error('IPv6 address is not within the CIDR range');
      }

      await tx.update(client).set(data).where(eq(client.id, id)).execute();
      await bumpDesiredRevision(tx, [existingClient.interfaceId]);
    });
  }

  async createFromExisting({
    name,
    enabled,
    ipv4Address,
    ipv6Address,
    preSharedKey,
    privateKey,
    publicKey,
    interfaceId,
  }: ClientCreateFromExistingType) {
    const clientConfig = await this.#db.query.userConfig
      .findFirst({ where: eq(userConfig.id, interfaceId) })
      .execute();
    if (!clientConfig) {
      throw new Error('WireGuard interface configuration not found');
    }

    return this.#db.transaction(async (tx) => {
      const result = await tx
        .insert(client)
        .values({
          name,
          userId: 1,
          interfaceId,
          privateKey,
          publicKey,
          preSharedKey,
          ipv4Address,
          ipv6Address,
          mtu: clientConfig.defaultMtu,
          jC: clientConfig.defaultJC,
          jMin: clientConfig.defaultJMin,
          jMax: clientConfig.defaultJMax,
          i1: clientConfig.defaultI1,
          i2: clientConfig.defaultI2,
          i3: clientConfig.defaultI3,
          i4: clientConfig.defaultI4,
          allowedIps: clientConfig.defaultAllowedIps,
          dns: clientConfig.defaultDns,
          persistentKeepalive: clientConfig.defaultPersistentKeepalive,
          serverAllowedIps: [],
          enabled,
        })
        .execute();
      await bumpDesiredRevision(tx, [interfaceId]);
      return result;
    });
  }
}
