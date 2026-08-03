import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { createClient } from '@libsql/client';
import { drizzle } from 'drizzle-orm/libsql';
import { migrate } from 'drizzle-orm/libsql/migrator';
import { afterEach, describe, expect, test, vi } from 'vitest';

import { ClientService } from '#db/repositories/client/service';
import { InterfaceService } from '#db/repositories/interface/service';
import { UserConfigService } from '#db/repositories/userConfig/service';
import * as schema from '#db/schema';
import type { DBType } from '#db/sqlite';

vi.mock('#server/utils/wgHelper', () => ({
  wg: {
    generatePrivateKey: vi.fn(async () => 'generated-private-key'),
    getPublicKey: vi.fn(async () => 'generated-public-key'),
    generatePreSharedKey: vi.fn(async () => 'generated-pre-shared-key'),
  },
}));

const migrationsDirectory = fileURLToPath(
  new URL('../../server/database/migrations', import.meta.url)
);
const temporaryRoots: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryRoots
      .splice(0)
      .map((root) => fs.rm(root, { recursive: true, force: true }))
  );
});

async function createServices() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'wg-easy-phase2-'));
  temporaryRoots.push(root);
  const client = createClient({ url: `file:${path.join(root, 'test.db')}` });
  const db = drizzle({ client, schema });
  await migrate(db, { migrationsFolder: migrationsDirectory });
  await client.execute({
    sql: `INSERT INTO users_table
      (id, username, password, email, name, role, totp_key, totp_verified, enabled)
      VALUES (1, 'admin', 'hash', 'admin@example.test', 'Admin', 1, NULL, 0, 1)`,
    args: [],
  });
  await client.execute({
    sql: `UPDATE interfaces_table
      SET private_key = 'wg0-private', public_key = 'wg0-public',
          ipv4_cidr = '10.251.0.0/24', ipv6_cidr = 'fd42:251::/64'
      WHERE name = 'wg0'`,
    args: [],
  });
  const typedDb = db as unknown as DBType;
  return {
    client,
    clients: new ClientService(typedDb),
    interfaces: new InterfaceService(typedDb),
    userConfigs: new UserConfigService(typedDb),
  };
}

describe('Phase 2 interface-scoped repositories', () => {
  test('creates a disabled cloned interface with independent port and endpoint', async () => {
    const { client, interfaces, userConfigs } = await createServices();
    const created = await interfaces.create({
      name: 'awg1',
      device: 'eth0',
      port: 51821,
      ipv4Cidr: '10.252.0.0/24',
      ipv6Cidr: 'fd42:252::/64',
    });

    expect(created).toMatchObject({
      name: 'awg1',
      enabled: false,
      privateKey: 'generated-private-key',
      publicKey: 'generated-public-key',
    });

    await userConfigs.updateHostPort('awg1', 'vpn.example.test', 51830);
    const endpoint = await userConfigs.get('awg1');
    const listenPort = await client.execute({
      sql: `SELECT port FROM interfaces_table WHERE name = 'awg1'`,
      args: [],
    });
    expect(endpoint).toMatchObject({ host: 'vpn.example.test', port: 51830 });
    expect(listenPort.rows[0]?.port).toBe(51821);
  });

  test('rejects CIDR and listen-port collisions', async () => {
    const { interfaces } = await createServices();
    await interfaces.create({
      name: 'awg1',
      device: 'eth0',
      port: 51821,
      ipv4Cidr: '10.252.0.0/24',
      ipv6Cidr: 'fd42:252::/64',
    });

    await expect(
      interfaces.create({
        name: 'awg2',
        device: 'eth1',
        port: 51822,
        ipv4Cidr: '10.252.0.7/24',
        ipv6Cidr: 'fd42:253::/64',
      })
    ).rejects.toThrow('IPv4 CIDR overlaps with interface awg1');

    await expect(
      interfaces.create({
        name: 'awg2',
        device: 'eth1',
        port: 51821,
        ipv4Cidr: '10.253.0.0/24',
        ipv6Cidr: 'fd42:253::/64',
      })
    ).rejects.toThrow('Listen port is already used by interface awg1');
  });

  test('allocates, filters, and validates clients against their assigned interface', async () => {
    const { clients, interfaces } = await createServices();
    await interfaces.create({
      name: 'awg1',
      device: 'eth0',
      port: 51821,
      ipv4Cidr: '10.252.0.0/24',
      ipv6Cidr: 'fd42:252::/64',
    });

    const created = await clients.create({
      name: 'on-awg1',
      expiresAt: null,
      interfaceId: 'awg1',
    });
    const clientId = created[0]!.clientId;
    const assigned = await clients.get(clientId);
    expect(assigned).toMatchObject({
      interfaceId: 'awg1',
      ipv4Address: '10.252.0.2',
      ipv6Address: 'fd42:252::2',
    });
    expect(await clients.getAllPublic({ interfaceId: 'awg1' })).toHaveLength(1);
    await expect(
      clients.update(clientId, {
        ...(assigned as NonNullable<typeof assigned>),
        ipv4Address: '10.251.0.2',
      })
    ).rejects.toThrow('IPv4 address is not within the CIDR range');
  });
});
