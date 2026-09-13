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
import {
  ClientService,
  ClientConflictError,
} from '#db/repositories/client/service';
import { ClientUpdateSchema } from '#db/repositories/client/types';
import { legacyImportHooks } from '#shared/utils/importHooks';
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
  test('retains alternate credentials and requires disabling the active version before switching', async () => {
    const { db, importer } = await service();
    const source = fixture();
    source.clients.second.privateKey = source.clients.first.privateKey;
    source.clients.second.publicKey = source.clients.first.publicKey;
    source.clients.second.preSharedKey = source.clients.first.preSharedKey;
    // Distinct addresses ensure the credential guard itself is exercised.
    const raw = JSON.stringify(source);
    expect((await importer.preview(raw, settings())).blockers).toEqual([]);
    const reversed = {
      ...source,
      clients: { second: source.clients.second, first: source.clients.first },
    };
    expect(
      code(() => inspectLegacyBackup(JSON.stringify(reversed)))
    ).toBeNull();
    await importer.create(raw, settings(), 1);
    const rows = await db.db.query.client.findMany();
    const active = rows.find((c) => c.enabled)!;
    const alternate = rows.find((c) => !c.enabled)!;
    expect(rows).toHaveLength(2);
    expect(
      rows.every(
        (c) =>
          c.privateKey === source.clients.first.privateKey &&
          c.publicKey === source.clients.first.publicKey &&
          c.preSharedKey === source.clients.first.preSharedKey
      )
    ).toBe(true);
    const clients = new ClientService(db.db);
    const before = await state(db);
    await expect(clients.toggle(alternate.id, true)).rejects.toBeInstanceOf(
      ClientConflictError
    );
    await expect(
      clients.update(
        alternate.id,
        ClientUpdateSchema.parse({ ...alternate, enabled: true })
      )
    ).rejects.toBeInstanceOf(ClientConflictError);
    expect((await state(db)) === before).toBe(true);
    expect(
      await db.raw
        .execute({
          sql: 'UPDATE clients_table SET enabled=1 WHERE id=?',
          args: [alternate.id],
        })
        .then(
          () => false,
          () => true
        )
    ).toBe(true);
    await clients.toggle(active.id, false);
    await clients.toggle(alternate.id, true);
    await expect(clients.toggle(active.id, true)).rejects.toBeInstanceOf(
      ClientConflictError
    );
    await clients.toggle(alternate.id, false);
    const attempts = await Promise.allSettled([
      clients.toggle(active.id, true),
      clients.toggle(alternate.id, true),
    ]);
    expect(attempts.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
    expect(
      (await db.db.query.client.findMany()).filter((c) => c.enabled)
    ).toHaveLength(1);
    source.clients.second.enabled = true;
    expect(code(() => inspectLegacyBackup(JSON.stringify(source)))).toBe(
      'credential_conflict'
    );
    source.clients.second.enabled = false;
    source.clients.second.privateKey = source.server.privateKey;
    source.clients.second.publicKey = source.server.publicKey;
    expect(code(() => inspectLegacyBackup(JSON.stringify(source)))).toBe(
      'credential_conflict'
    );
  });
  test('requires explicit correction of stale server metadata without changing clients', async () => {
    const { db, importer } = await service();
    const source = fixture(true);
    source.server.address = source.clients.first.address;
    source.clients.second.address = source.clients.first.address;
    const raw = JSON.stringify(source);
    const input = { ...settings(), ipv6Cidr: '', mode: 'amneziawg' };
    const before = await state(db);
    const preview = await importer.preview(raw, input);
    expect(preview).toMatchObject({
      recordedServerAddress: '10.254.0.2',
      serverAddress: '10.254.0.1',
      serverAddressCorrectionRequired: true,
      blockers: [{ code: 'server_address', field: 'serverAddressConfirmed' }],
    });
    await expect(importer.create(raw, input, 1)).rejects.toBeInstanceOf(
      LegacyImportError
    );
    expect((await state(db)) === before).toBe(true);
    const confirmed = { ...input, serverAddressConfirmed: true };
    expect((await importer.preview(raw, confirmed)).blockers).toEqual([]);
    await importer.create(raw, confirmed, 1);
    const iface = (await db.db.query.wgInterface.findMany()).find(
      (i) => i.name === input.name
    )!;
    const hooks = (await db.db.query.hooks.findMany()).find(
      (h) => h.id === input.name
    )!;
    expect(
      wg
        .generateServerInterface(iface, hooks)
        .includes('Address = 10.254.0.1/24\n')
    ).toBe(true);
    const imported = await db.db.query.client.findMany();
    expect(
      imported.every(
        (c) => c.ipv4Address === '10.254.0.2' && c.ipv6Address === null
      )
    ).toBe(true);
    expect(
      imported.every(
        (c, i) => c.privateKey === Object.values(source.clients)[i]!.privateKey
      )
    ).toBe(true);
    // Confirmation never permits a client on the generated server address.
    source.clients.first.address = '10.254.0.1';
    expect(
      code(() =>
        prepareLegacyImport(
          inspectLegacyBackup(JSON.stringify(source)),
          confirmed
        )
      )
    ).toBe('client_address');
  });
  test('preserves disabled overlaps and prevents conflicting enables and edits atomically', async () => {
    const { db, importer } = await service();
    const source = fixture();
    source.clients.second.address = source.clients.first.address;
    const raw = JSON.stringify(source);
    expect((await importer.preview(raw, settings())).blockers).toEqual([]);
    await importer.create(raw, settings(), 1);
    const rows = await db.db.query.client.findMany();
    const active = rows.find((c) => c.enabled)!;
    const disabled = rows.find((c) => !c.enabled)!;
    const clients = new ClientService(db.db);
    // The enabled interface flag is false for this entire test: client intent
    // must still reserve the address before runtime activation.
    const before = await state(db);
    await expect(clients.toggle(disabled.id, true)).rejects.toBeInstanceOf(
      ClientConflictError
    );
    await expect(
      clients.update(
        disabled.id,
        ClientUpdateSchema.parse({ ...disabled, enabled: true })
      )
    ).rejects.toBeInstanceOf(ClientConflictError);
    expect((await state(db)) === before).toBe(true);
    // Database enforcement also covers other writers and concurrency.
    expect(
      await db.raw
        .execute({
          sql: 'UPDATE clients_table SET enabled=1 WHERE id=?',
          args: [disabled.id],
        })
        .then(
          () => false,
          () => true
        )
    ).toBe(true);
    await clients.toggle(active.id, false);
    await clients.update(
      disabled.id,
      ClientUpdateSchema.parse({ ...disabled, ipv6Address: active.ipv6Address })
    );
    const attempts = await Promise.allSettled([
      clients.toggle(active.id, true),
      clients.toggle(disabled.id, true),
    ]);
    expect(attempts.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
    expect(
      (await db.db.query.client.findMany()).filter((c) => c.enabled)
    ).toHaveLength(1);
    await clients.toggle(active.id, false);
    await clients.toggle(disabled.id, true);
    // Distinct IPv4 does not bypass a shared enabled IPv6 reservation.
    const updatedActive = ClientUpdateSchema.parse({
      ...active,
      ipv4Address: '10.254.0.4',
      enabled: true,
    });
    await expect(
      clients.update(active.id, updatedActive)
    ).rejects.toBeInstanceOf(ClientConflictError);
    expect(
      await db.raw
        .execute({
          sql: 'UPDATE clients_table SET enabled=1, ipv4_address=? WHERE id=?',
          args: ['10.254.0.4', active.id],
        })
        .then(
          () => false,
          () => true
        )
    ).toBe(true);
    expect((await db.raw.execute('PRAGMA foreign_key_check')).rows).toEqual([]);
  });
  test('imports comma-separated legacy routes as tunnel hosts with warnings', () => {
    const source = fixture(true);
    source.clients.first.address = '192.0.2.0/24, 10.254.0.2';
    source.clients.second.address = '0.0.0.0/1, 128.0.0.0/1, 10.254.0.3/32';
    const inspected = inspectLegacyBackup(JSON.stringify(source));
    expect(inspected.clients.map((c) => c.address)).toEqual([
      '10.254.0.2',
      '10.254.0.3',
    ]);
    expect(inspected.warnings).toEqual([
      { code: 'routes_omitted', client: 1 },
      { code: 'routes_omitted', client: 2 },
    ]);
    expect(inspected.detectedMode).toBe('amneziawg');
    for (const address of [
      '10.254.0.2, 10.254.0.4',
      '192.0.2.0/24',
      'bad, 10.254.0.2',
      '10.254.0.2,',
      '::/0, 10.254.0.2',
    ]) {
      source.clients.first.address = address;
      expect(code(() => inspectLegacyBackup(JSON.stringify(source)))).toBe(
        'client_address'
      );
    }
  });

  test.each(['', null, undefined])(
    'IPv4-only import persists and remains editable (%s)',
    async (ipv6Cidr) => {
      const { db, importer } = await service();
      const input = {
        ...settings(),
        ipv6Cidr,
        hooks: legacyImportHooks(false),
      };
      const raw = JSON.stringify(fixture());
      expect((await importer.preview(raw, input)).blockers).toEqual([]);
      await importer.create(raw, input, 1);
      const iface = (await db.db.query.wgInterface.findMany()).find(
        (i) => i.name === input.name
      )!;
      const hooks = (await db.db.query.hooks.findMany()).find(
        (h) => h.id === input.name
      )!;
      const defaults = (await db.db.query.userConfig.findMany()).find(
        (c) => c.id === input.name
      )!;
      const clients = await db.db.query.client.findMany();
      expect(iface.ipv6Cidr).toBeNull();
      expect(clients.every((c) => c.ipv6Address === null)).toBe(true);
      const server = wg.generateServerInterface(iface, hooks);
      expect(server.includes('Address = 10.254.0.1/24\n')).toBe(true);
      expect(server.includes('ip6tables')).toBe(false);
      expect(server.includes('-i imported')).toBe(true);
      expect(server.includes('ip -4 route show default')).toBe(true);
      for (const c of clients) {
        const config = wg.generateClientConfig(iface, defaults, {
          ...c,
          allowedIps: ['0.0.0.0/0', '::/0'],
        });
        expect(config.includes(`Address = ${c.ipv4Address}/32\n`)).toBe(true);
        expect(config.includes('::/0')).toBe(false);
        expect(wg.generateServerPeer(c).includes('/128')).toBe(false);
      }
      const clientService = new ClientService(db.db);
      const first = clients[0]!;
      await clientService.update(first.id, ClientUpdateSchema.parse(first));
      const pair = keys();
      const spies = [
        vi.spyOn(wg, 'generatePrivateKey').mockResolvedValue(pair.privateKey),
        vi.spyOn(wg, 'getPublicKey').mockResolvedValue(pair.publicKey),
        vi
          .spyOn(wg, 'generatePreSharedKey')
          .mockResolvedValue(randomBytes(32).toString('base64')),
      ];
      try {
        await clientService.create({
          name: 'New',
          interfaceId: input.name,
          expiresAt: null,
        });
      } finally {
        spies.forEach((spy) => spy.mockRestore());
      }
      expect(
        (await db.db.query.client.findMany()).every(
          (c) => c.ipv6Address === null
        )
      ).toBe(true);
      const interfaces = new InterfaceService(db.db);
      await interfaces.updateCidr(input.name, {
        ipv4Cidr: iface.ipv4Cidr,
        ipv6Cidr: 'fd42:254::/64',
      });
      expect(
        (await db.db.query.client.findMany()).every((c) => !!c.ipv6Address)
      ).toBe(true);
      await interfaces.updateCidr(input.name, {
        ipv4Cidr: iface.ipv4Cidr,
        ipv6Cidr: null,
      });
      expect(
        (await db.db.query.client.findMany()).every(
          (c) => c.ipv6Address === null
        )
      ).toBe(true);
    }
  );
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
    // The actual upload form sends empty fields, not an empty settings object.
    const result = await importer.preview(JSON.stringify(fixture(true)), {
      ...settings(),
      name: '',
      ipv6Cidr: '',
      endpointHost: '',
      hooksReviewed: false,
    });
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
    duplicate.clients.second.enabled = true;
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
