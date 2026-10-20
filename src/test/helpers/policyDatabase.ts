import { randomBytes } from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { eq } from 'drizzle-orm';

import { createNodeSqliteDatabase } from '#db/nodeSqlite';
import { ClientService } from '#db/repositories/client/service';
import { RoutingGroupService } from '#db/repositories/routingGroup/service';
import { InterfaceService } from '#db/repositories/interface/service';
import { GeneralService } from '#db/repositories/general/service';
import { HooksService } from '#db/repositories/hooks/service';
import { UserConfigService } from '#db/repositories/userConfig/service';
import * as schema from '#db/schema';
import { deriveClientPublicKey } from '#server/utils/clientCredentials';

export const syntheticKey = () => randomBytes(32).toString('base64');
export async function policyDatabase(version = 2) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'wge-policy-service-')),
    store = createNodeSqliteDatabase(path.join(root, 'test.db'), schema),
    db = store.db;
  await store.migrate({
    migrationsFolder: fileURLToPath(
      new URL('../../server/database/migrations', import.meta.url)
    ),
  });
  await db
    .insert(schema.user)
    .values({
      id: 1,
      username: 'admin',
      password: 'fixture',
      email: 'admin@example.test',
      name: 'Admin',
      role: 1,
      enabled: true,
      totpVerified: false,
    })
    .execute();
  const privateKey = syntheticKey();
  await db
    .update(schema.wgInterface)
    .set({
      privateKey,
      publicKey: deriveClientPublicKey(privateKey),
      ipv4Cidr: '10.8.0.0/24',
      ipv6Cidr: null,
      defaultConfigFormat: 'wireguard',
    })
    .execute();
  await db
    .update(schema.general)
    .set({ routingPolicyVersion: version })
    .execute();
  const clients = new ClientService(db);
  return {
    root,
    db,
    store,
    clients,
    groups: new RoutingGroupService(db),
    interfaces: new InterfaceService(db),
    general: new GeneralService(db),
    hooks: new HooksService(db),
    userConfigs: new UserConfigService(db),
    async addInterface(name: string, cidr: string, port = 62002) {
      const [iface, defaults, hooks] = await Promise.all([
          db.query.wgInterface.findFirst({
            where: eq(schema.wgInterface.name, 'wg0'),
          }),
          db.query.userConfig.findFirst({
            where: eq(schema.userConfig.id, 'wg0'),
          }),
          db.query.hooks.findFirst({ where: eq(schema.hooks.id, 'wg0') }),
        ]),
        privateKey = syntheticKey();
      await db.transaction(async (tx) => {
        await tx
          .insert(schema.wgInterface)
          .values({
            ...iface!,
            name,
            ipv4Cidr: cidr,
            ipv6Cidr: null,
            port,
            privateKey,
            publicKey: deriveClientPublicKey(privateKey),
          })
          .execute();
        await tx
          .insert(schema.userConfig)
          .values({ ...defaults!, id: name })
          .execute();
        await tx
          .insert(schema.hooks)
          .values({ ...hooks!, id: name })
          .execute();
        await tx
          .insert(schema.interfaceRuntimeState)
          .values({ interfaceId: name })
          .execute();
      });
    },
    async createClient(name: string, interfaceId = 'wg0', extra = {}) {
      const [created] = await clients.create({
        name,
        interfaceId,
        persistentKeepalive: 25,
        ...extra,
      });
      return (await clients.get(created!.clientId))!;
    },
    async close() {
      await store.close();
      await fs.rm(root, { recursive: true });
    },
  };
}
