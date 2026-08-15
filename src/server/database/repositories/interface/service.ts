import { eq, ne, sql } from 'drizzle-orm';
import { containsCidr, parseCidr } from 'cidr-tools';

import { wgInterface } from './schema';
import type {
  InterfaceCidrUpdateType,
  InterfaceCreateInput,
  InterfaceUpdateType,
} from './types';

import { nextIPFromUsedAddresses } from '#server/utils/ip';
import { wg } from '#server/utils/wgHelper';
import { bumpDesiredRevision } from '#db/repositories/runtime/service';
import {
  client as clientSchema,
  general,
  hooks,
  interfaceRuntimeState,
  userConfig,
} from '#db/schema';
import type { DBType } from '#db/sqlite';

export class InterfaceDeletionBlockedError extends Error {}

export class InterfaceReservationConflictError extends Error {}

function createPreparedStatement(db: DBType) {
  return {
    get: db.query.wgInterface
      .findFirst({ where: eq(wgInterface.name, sql.placeholder('interface')) })
      .prepare(),
    updateKeyPair: db
      .update(wgInterface)
      .set({
        privateKey: sql.placeholder('privateKey') as never as string,
        publicKey: sql.placeholder('publicKey') as never as string,
      })
      .where(eq(wgInterface.name, sql.placeholder('interface')))
      .prepare(),
  };
}

export class InterfaceService {
  #db: DBType;
  #statements: ReturnType<typeof createPreparedStatement>;

  constructor(db: DBType) {
    this.#db = db;
    this.#statements = createPreparedStatement(db);
  }

  async getByName(interfaceId: string) {
    const wgInterface = await this.#statements.get.execute({
      interface: interfaceId,
    });
    if (!wgInterface) {
      throw new Error('Interface not found');
    }
    return wgInterface;
  }

  async getAll() {
    return this.#db.query.wgInterface
      .findMany({ orderBy: (table, { asc }) => asc(table.name) })
      .execute();
  }

  async getDefault() {
    const config = await this.#db.query.general
      .findFirst({
        columns: { defaultInterfaceId: true },
      })
      .execute();
    if (!config) throw new Error('General Config not found');
    return this.getByName(config.defaultInterfaceId);
  }

  async setDefault(interfaceId: string) {
    const wgInterface = await this.getByName(interfaceId);
    if (wgInterface.pendingDelete) {
      throw new Error('A pending-delete interface cannot be the default');
    }
    await this.#db
      .update(general)
      .set({ defaultInterfaceId: interfaceId })
      .execute();
    return wgInterface;
  }

  // Compatibility boundary for existing single-interface callers.
  get() {
    return this.getDefault();
  }

  updateKeyPair(interfaceId: string, privateKey: string, publicKey: string) {
    return this.#statements.updateKeyPair.execute({
      interface: interfaceId,
      privateKey,
      publicKey,
    });
  }

  updateAwgHeaders(
    interfaceId: string,
    headers: { h1: string; h2: string; h3: string; h4: string }
  ) {
    return this.#db
      .update(wgInterface)
      .set(headers)
      .where(eq(wgInterface.name, interfaceId))
      .execute();
  }

  async update(interfaceId: string, data: InterfaceUpdateType) {
    await this.assertCidrAndPortAvailable(data, interfaceId);
    return this.#db.transaction(async (tx) => {
      const result = await tx
        .update(wgInterface)
        .set(data)
        .where(eq(wgInterface.name, interfaceId))
        .execute();
      await bumpDesiredRevision(tx, [interfaceId]);
      return result;
    });
  }

  setFirewallEnabled(interfaceId: string, firewallEnabled: boolean) {
    return this.#db.transaction(async (tx) => {
      const result = await tx
        .update(wgInterface)
        .set({ firewallEnabled })
        .where(eq(wgInterface.name, interfaceId))
        .execute();
      await bumpDesiredRevision(tx, [interfaceId]);
      return result;
    });
  }

  async assertCidrAndPortAvailable(
    data: Pick<InterfaceCidrUpdateType, 'ipv4Cidr' | 'ipv6Cidr'> & {
      port?: number;
    },
    exceptInterfaceId?: string
  ) {
    const interfaces = await this.#db.query.wgInterface
      .findMany({
        where: exceptInterfaceId
          ? ne(wgInterface.name, exceptInterfaceId)
          : undefined,
      })
      .execute();
    for (const existing of interfaces) {
      if (
        containsCidr(existing.ipv4Cidr, data.ipv4Cidr) ||
        containsCidr(data.ipv4Cidr, existing.ipv4Cidr)
      ) {
        throw new InterfaceReservationConflictError(
          `IPv4 CIDR overlaps with interface ${existing.name}`
        );
      }
      if (
        containsCidr(existing.ipv6Cidr, data.ipv6Cidr) ||
        containsCidr(data.ipv6Cidr, existing.ipv6Cidr)
      ) {
        throw new InterfaceReservationConflictError(
          `IPv6 CIDR overlaps with interface ${existing.name}`
        );
      }
      if (data.port !== undefined && existing.port === data.port) {
        throw new InterfaceReservationConflictError(
          `Listen port is already used by interface ${existing.name}`
        );
      }
    }
  }

  async create(data: InterfaceCreateInput) {
    await this.assertCidrAndPortAvailable(data);
    const source = await this.getByName(
      data.cloneFromInterfaceId ?? (await this.getDefault()).name
    );
    const sourceHooks = await this.#db.query.hooks
      .findFirst({
        where: eq(hooks.id, source.name),
      })
      .execute();
    const sourceUserConfig = await this.#db.query.userConfig
      .findFirst({
        where: eq(userConfig.id, source.name),
      })
      .execute();
    if (!sourceHooks || !sourceUserConfig) {
      throw new Error('Source interface defaults are incomplete');
    }
    const privateKey = await wg.generatePrivateKey();
    const publicKey = await wg.getPublicKey(privateKey);

    await this.#db.transaction(async (tx) => {
      await tx
        .insert(wgInterface)
        .values({
          ...source,
          name: data.name,
          device: data.device,
          port: data.port,
          ipv4Cidr: data.ipv4Cidr,
          ipv6Cidr: data.ipv6Cidr,
          privateKey,
          publicKey,
          enabled: false,
          pendingDelete: false,
        })
        .execute();
      await tx
        .insert(hooks)
        .values({
          ...sourceHooks,
          id: data.name,
        })
        .execute();
      await tx
        .insert(userConfig)
        .values({
          ...sourceUserConfig,
          id: data.name,
        })
        .execute();
      await tx
        .insert(interfaceRuntimeState)
        .values({
          interfaceId: data.name,
          status: 'disabled',
          observedUp: false,
          restartRequired: false,
        })
        .execute();
      await bumpDesiredRevision(tx, [data.name]);
    });

    return this.getByName(data.name);
  }

  async updateCidr(interfaceId: string, data: InterfaceCidrUpdateType) {
    await this.assertCidrAndPortAvailable(data, interfaceId);
    return this.#db.transaction(async (tx) => {
      const oldCidr = await tx.query.wgInterface
        .findFirst({
          where: eq(wgInterface.name, interfaceId),
          columns: { ipv4Cidr: true, ipv6Cidr: true },
        })
        .execute();

      if (!oldCidr) {
        throw new Error('Interface not found');
      }

      await tx
        .update(wgInterface)
        .set(data)
        .where(eq(wgInterface.name, interfaceId))
        .execute();

      const clients = await tx.query.client
        .findMany({
          where: eq(clientSchema.interfaceId, interfaceId),
        })
        .execute();
      const ipv4Addresses = new Set(
        clients.map((client) => client.ipv4Address)
      );
      const ipv6Addresses = new Set(
        clients.map((client) => client.ipv6Address)
      );

      for (const client of clients) {
        // only calculate ip if cidr has changed

        let nextIpv4 = client.ipv4Address;
        if (data.ipv4Cidr !== oldCidr.ipv4Cidr) {
          nextIpv4 = nextIPFromUsedAddresses(
            4,
            parseCidr(data.ipv4Cidr),
            ipv4Addresses
          );
          ipv4Addresses.add(nextIpv4);
          ipv4Addresses.delete(client.ipv4Address);
        }

        let nextIpv6 = client.ipv6Address;
        if (data.ipv6Cidr !== oldCidr.ipv6Cidr) {
          nextIpv6 = nextIPFromUsedAddresses(
            6,
            parseCidr(data.ipv6Cidr),
            ipv6Addresses
          );
          ipv6Addresses.add(nextIpv6);
          ipv6Addresses.delete(client.ipv6Address);
        }

        await tx
          .update(clientSchema)
          .set({
            ipv4Address: nextIpv4,
            ipv6Address: nextIpv6,
          })
          .where(eq(clientSchema.id, client.id))
          .execute();
      }
      await bumpDesiredRevision(tx, [interfaceId]);
    });
  }

  async assertCanDelete(interfaceId: string) {
    const [generalConfig, existingClient] = await Promise.all([
      this.#db.query.general
        .findFirst({ columns: { defaultInterfaceId: true } })
        .execute(),
      this.#db.query.client
        .findFirst({
          where: eq(clientSchema.interfaceId, interfaceId),
          columns: { id: true },
        })
        .execute(),
    ]);
    if (!generalConfig) throw new Error('General Config not found');
    if (generalConfig.defaultInterfaceId === interfaceId) {
      throw new InterfaceDeletionBlockedError(
        'The default interface cannot be deleted'
      );
    }
    if (existingClient) {
      throw new InterfaceDeletionBlockedError(
        'Interface deletion is blocked while clients exist'
      );
    }
    return this.getByName(interfaceId);
  }

  async stageDelete(interfaceId: string) {
    return this.#db.transaction(async (tx) => {
      const [generalConfig, existingInterface, existingClient] =
        await Promise.all([
          tx.query.general
            .findFirst({ columns: { defaultInterfaceId: true } })
            .execute(),
          tx.query.wgInterface
            .findFirst({ where: eq(wgInterface.name, interfaceId) })
            .execute(),
          tx.query.client
            .findFirst({
              where: eq(clientSchema.interfaceId, interfaceId),
              columns: { id: true },
            })
            .execute(),
        ]);
      if (!generalConfig) throw new Error('General Config not found');
      if (!existingInterface) throw new Error('Interface not found');
      if (generalConfig.defaultInterfaceId === interfaceId) {
        throw new InterfaceDeletionBlockedError(
          'The default interface cannot be deleted'
        );
      }
      if (existingClient) {
        throw new InterfaceDeletionBlockedError(
          'Interface deletion is blocked while clients exist'
        );
      }
      await tx
        .update(wgInterface)
        .set({ enabled: false, pendingDelete: true })
        .where(eq(wgInterface.name, interfaceId))
        .execute();
      await bumpDesiredRevision(tx, [interfaceId]);
    });
  }

  finalizeDelete(interfaceId: string) {
    return this.#db
      .delete(wgInterface)
      .where(eq(wgInterface.name, interfaceId))
      .execute();
  }
}
