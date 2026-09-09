import { generateKeyPairSync, randomBytes } from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, describe, expect, test, vi } from 'vitest';

import {
  inspectLegacyBackup,
  prepareLegacyImport,
  validateImportReservations,
  LegacyImportError,
  parseImportJson,
} from '#server/utils/legacyImport';
import { InterfaceService } from '#db/repositories/interface/service';
import { wg } from '#server/utils/wgHelper';
import { LegacyInterfaceImportService } from '#db/repositories/interface/importService';
import { createNodeSqliteDatabase } from '#db/nodeSqlite';
import * as schema from '#db/schema';
import { legacyImportHttpError } from '#server/utils/legacyImportRequest';

vi.mock('#server/utils/config', () => ({
  WG_ENV: { WG_EXECUTABLE: 'awg', PORT: 51821 },
}));
const migrationsFolder = fileURLToPath(
  new URL('../../server/database/migrations', import.meta.url)
);
const databases: ReturnType<typeof createNodeSqliteDatabase>[] = [];
const directories: string[] = [];
afterEach(async () => {
  for (const db of databases.splice(0)) await db.close();
  for (const dir of directories.splice(0))
    await fs.rm(dir, { recursive: true, force: true });
});
function keys() {
  const pair = generateKeyPairSync('x25519');
  return {
    privateKey: pair.privateKey
      .export({ format: 'der', type: 'pkcs8' })
      .subarray(-32)
      .toString('base64'),
    publicKey: pair.publicKey
      .export({ format: 'der', type: 'spki' })
      .subarray(-32)
      .toString('base64'),
  };
}
function fixture(awg = false) {
  return {
    server: {
      ...keys(),
      address: '10.254.0.1',
      ...(awg
        ? {
            jc: 7,
            jmin: 10,
            jmax: 1000,
            s1: 128,
            s2: 56,
            h1: 111,
            h2: 222,
            h3: 333,
            h4: 444,
          }
        : {}),
    },
    clients: {
      first: {
        ...keys(),
        name: 'Phone',
        address: '10.254.0.2',
        preSharedKey: randomBytes(32).toString('base64'),
        enabled: true,
        createdAt: '2024-01-02T03:04:05Z',
        updatedAt: '2024-02-03T04:05:06Z',
        expiredAt: '2099-12-31T23:59:59Z',
      },
      second: {
        ...keys(),
        name: 'Disabled',
        address: '10.254.0.3',
        preSharedKey: '',
        enabled: false,
        createdAt: '2024-01-02T03:04:05Z',
        updatedAt: '2024-02-03T04:05:06Z',
        expiredAt: null,
      },
    },
  };
}
const settings = () => ({
  name: 'imported',
  device: 'eth0',
  listenPort: 51829,
  ipv6Cidr: 'fd42:254::/64',
  endpointHost: 'vpn.example.test',
  endpointPort: 51820,
  dns: ['1.1.1.1'],
  allowedIps: ['0.0.0.0/0'],
  mtu: 1420,
  persistentKeepalive: 25,
  hooks: { preUp: '', postUp: '', preDown: '', postDown: '' },
  hooksReviewed: true,
  mode: 'wireguard-compatible',
});
async function service() {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'legacy-import-'));
  directories.push(dir);
  const db = createNodeSqliteDatabase(path.join(dir, 'test.db'), schema);
  databases.push(db);
  await db.migrate({ migrationsFolder });
  await db.raw.execute(
    "INSERT INTO users_table (id,username,password,email,name,role,totp_key,totp_verified,enabled) VALUES (1,'admin','hash','admin@example.test','Admin',1,NULL,0,1)"
  );
  return { db, importer: new LegacyInterfaceImportService(db.db) };
}
async function state(db: ReturnType<typeof createNodeSqliteDatabase>) {
  const result: unknown[] = [];
  for (const table of [
    'interfaces_table',
    'clients_table',
    'hooks_table',
    'user_configs_table',
    'interface_runtime_state_table',
    'runtime_reconciliation_state_table',
    'one_time_links_table',
  ])
    result.push((await db.raw.execute(`SELECT * FROM ${table}`)).rows);
  return JSON.stringify(result);
}
function code(action: () => unknown) {
  try {
    action();
    return null;
  } catch (e) {
    return e instanceof LegacyImportError ? e.issues[0]?.code : 'unexpected';
  }
}
describe('legacy interface import', () => {
  test('ordinary interface creation rechecks reservations after asynchronous key generation', async () => {
    const { db, importer } = await service();
    let release!: () => void;
    let started!: () => void;
    const reached = new Promise<void>((resolve) => {
      started = resolve;
    });
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const pair = keys();
    const privateSpy = vi
      .spyOn(wg, 'generatePrivateKey')
      .mockImplementation(async () => {
        started();
        await gate;
        return pair.privateKey;
      });
    const publicSpy = vi
      .spyOn(wg, 'getPublicKey')
      .mockResolvedValue(pair.publicKey);
    try {
      const pending = new InterfaceService(db.db).create({
        name: 'ordinary',
        device: 'eth0',
        port: 51828,
        ipv4Cidr: '10.254.0.0/24',
        ipv6Cidr: 'fd42:253::/64',
      });
      await reached;
      await importer.create(JSON.stringify(fixture()), settings(), 1);
      release();
      await expect(pending).rejects.toThrow('IPv4 CIDR overlaps');
      expect(
        await db.db.query.wgInterface.findFirst({
          where: (table, { eq }) => eq(table.name, 'ordinary'),
        })
      ).toBeUndefined();
    } finally {
      release();
      privateSpy.mockRestore();
      publicSpy.mockRestore();
    }
  });

  test.each([false, true])(
    'preserves credentials with redacted preview (AWG=%s)',
    async (awg) => {
      const source = fixture(awg),
        raw = JSON.stringify(source);
      const { db, importer } = await service();
      const input = {
        ...settings(),
        mode: awg ? 'amneziawg' : 'wireguard-compatible',
      };
      const before = await state(db);
      const preview = await importer.preview(raw, input);
      expect(preview.blockers).toEqual([]);
      expect((await state(db)) === before).toBe(true);
      const secrets = [
        source.server.privateKey,
        ...Object.values(source.clients)
          .flatMap((c) => [c.privateKey, c.preSharedKey])
          .filter(Boolean),
      ];
      expect(
        secrets.some((secret) => JSON.stringify(preview).includes(secret))
      ).toBe(false);
      expect(await importer.create(raw, input, 1)).toMatchObject({
        enabled: false,
        importedClients: 2,
        interfaceId: 'imported',
        revision: 2,
      });
      const target = await db.db.query.wgInterface.findFirst({
        where: (table, { eq }) => eq(table.name, 'imported'),
      });
      const clients = await db.db.query.client.findMany();
      expect(
        target?.privateKey === source.server.privateKey &&
          target.publicKey === source.server.publicKey
      ).toBe(true);
      expect(
        clients.every(
          (c, i) =>
            c.privateKey === Object.values(source.clients)[i]!.privateKey &&
            c.publicKey === Object.values(source.clients)[i]!.publicKey
        )
      ).toBe(true);
      expect(
        clients.map((c) => [
          c.ipv4Address,
          c.ipv6Address,
          c.enabled,
          c.expiresAt,
        ])
      ).toEqual([
        ['10.254.0.2', 'fd42:254::2', true, '2099-12-31T23:59:59.000Z'],
        ['10.254.0.3', 'fd42:254::3', false, null],
      ]);
      expect(clients[1]?.preSharedKey === null).toBe(true);
      expect(target?.awgParametersEnabled).toBe(awg);
      expect(target?.jC).toBe(awg ? 7 : null);
      expect(
        (await db.raw.execute('PRAGMA foreign_key_check')).rows
      ).toHaveLength(0);
      const after = await state(db);
      await expect(importer.create(raw, input, 1)).rejects.toBeInstanceOf(
        LegacyImportError
      );
      expect((await state(db)) === after).toBe(true);
    }
  );
  test('incomplete preview returns safe prefills', async () => {
    const { importer } = await service();
    const result = await importer.preview(JSON.stringify(fixture(true)), {});
    expect(result.detectedMode).toBe('amneziawg');
    expect(result.awg.jc).toBe(7);
    expect(result.blockers.length).toBeGreaterThan(0);
  });
  test.each([
    'interfaces_table',
    'hooks_table',
    'user_configs_table',
    'interface_runtime_state_table',
    'clients_table',
    'runtime_reconciliation_state_table',
  ])('rolls back failure at %s including revisions', async (table) => {
    const { db, importer } = await service();
    const before = await state(db);
    const operation =
      table === 'runtime_reconciliation_state_table' ? 'UPDATE' : 'INSERT';
    await db.raw.execute(
      `CREATE TRIGGER reject_import BEFORE ${operation} ON ${table} BEGIN SELECT RAISE(ABORT, 'injected'); END`
    );
    const failed = await importer
      .create(JSON.stringify(fixture()), settings(), 1)
      .then(
        () => false,
        () => true
      );
    expect(failed).toBe(true);
    expect((await state(db)) === before).toBe(true);
  });
  test('serializes concurrent imports and rechecks changed reservations', async () => {
    const { db, importer } = await service();
    const raw = JSON.stringify(fixture());
    const results = await Promise.allSettled([
      importer.create(raw, settings(), 1),
      importer.create(raw, settings(), 1),
    ]);
    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
    expect((await db.db.query.client.findMany()).length).toBe(2);
    const other = fixture();
    other.server.address = '10.253.0.1';
    other.clients.first.address = '10.253.0.2';
    other.clients.second.address = '10.253.0.3';
    const input = {
      ...settings(),
      name: 'another',
      listenPort: 51828,
      ipv6Cidr: 'fd42:253::/64',
    };
    expect(
      (await importer.preview(JSON.stringify(other), input)).blockers
    ).toEqual([]);
    await db.raw.execute(
      "UPDATE interfaces_table SET port=51828 WHERE name='imported'"
    );
    const before = await state(db);
    await expect(
      importer.create(JSON.stringify(other), input, 1)
    ).rejects.toBeInstanceOf(LegacyImportError);
    expect((await state(db)) === before).toBe(true);
  });
  test('rejects malformed inputs without value-bearing errors', () => {
    expect(code(() => parseImportJson('{"__proto__":{}}'))).toBe(
      'invalid_file'
    );
    expect(
      code(() => parseImportJson('['.repeat(10) + '0' + ']'.repeat(10)))
    ).toBe('invalid_file');
    for (const address of [
      '10.254.0.0',
      '10.254.0.1',
      '10.254.0.255',
      '10.255.0.2',
    ]) {
      const f = fixture();
      f.clients.first.address = address;
      expect(code(() => inspectLegacyBackup(JSON.stringify(f)))).toBe(
        'client_address'
      );
    }
    const mismatch = fixture();
    mismatch.clients.first.publicKey = keys().publicKey;
    expect(code(() => inspectLegacyBackup(JSON.stringify(mismatch)))).toBe(
      'key_mismatch'
    );
    const duplicate = fixture();
    duplicate.clients.second.address = duplicate.clients.first.address;
    expect(code(() => inspectLegacyBackup(JSON.stringify(duplicate)))).toBe(
      'address_conflict'
    );
    expect(
      code(() =>
        inspectLegacyBackup(JSON.stringify({ ...fixture(), users: [] }))
      )
    ).toBe('invalid_file');
    const expiry = fixture();
    expiry.clients.first.expiredAt = 'bad';
    expect(code(() => inspectLegacyBackup(JSON.stringify(expiry)))).toBe(
      'invalid_expiry'
    );
  });
  test('checks capacity, AWG completeness, integer ports, and existing server identity', () => {
    const source = inspectLegacyBackup(JSON.stringify(fixture()));
    expect(
      code(() =>
        prepareLegacyImport(source, {
          ...settings(),
          ipv6Cidr: 'fd42:254::/126',
        })
      )
    ).toBe('ipv6_capacity');
    expect(
      code(() =>
        prepareLegacyImport(source, { ...settings(), mode: 'amneziawg' })
      )
    ).toBe('invalid_awg');
    expect(
      code(() =>
        prepareLegacyImport(source, { ...settings(), listenPort: 123.4 })
      )
    ).toBe('invalid_setting');
    const plan = prepareLegacyImport(source, settings());
    expect(
      code(() =>
        validateImportReservations(plan, {
          interfaces: [
            {
              name: 'other',
              port: 123,
              ipv4Cidr: '10.253.0.0/24',
              ipv6Cidr: 'fd42:253::/64',
              publicKey: source.backup.server.publicKey,
            },
          ],
          clients: [],
        })
      )
    ).toBe('credential_conflict');
    let exposed = '';
    try {
      legacyImportHttpError(new Error(source.backup.server.privateKey));
    } catch (e) {
      exposed = JSON.stringify(e);
    }
    expect(exposed.includes(source.backup.server.privateKey)).toBe(false);
  });
});
