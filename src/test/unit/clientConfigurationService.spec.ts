import { eq } from 'drizzle-orm';
import { afterEach, describe, expect, test, vi } from 'vitest';

import { policyDatabase, syntheticKey } from '../helpers/policyDatabase';

import { ClientUpdateSchema } from '#db/repositories/client/types';
import * as schema from '#db/schema';
import { deriveClientPublicKey } from '#server/utils/clientCredentials';

vi.mock('#server/utils/config', () => ({
  WG_ENV: { WG_EXECUTABLE: 'awg', PORT: 51821 },
}));

const databases: Awaited<ReturnType<typeof policyDatabase>>[] = [];
afterEach(async () => {
  for (const db of databases.splice(0)) await db.close();
});
async function fixture(version = 2) {
  const f = await policyDatabase(version);
  databases.push(f);
  return f;
}
const fields = {
  name: 'full profile',
  enabled: false,
  expiresAt: '2030-01-01T00:00:00.000Z',
  ipv4Address: '10.8.0.25',
  ipv6Address: null,
  preUp: ': custom client up',
  postUp: ': custom client ready',
  preDown: ': custom client stop',
  postDown: ': custom client down',
  allowedIps: ['198.51.100.0/24'],
  firewallIps: ['198.51.100.2:443/tcp'],
  serverAllowedIps: ['192.0.2.7/24'],
  persistentKeepalive: 25,
  mtu: 1350,
  jC: 3,
  jMin: 10,
  jMax: 20,
  i1: null,
  i2: null,
  i3: null,
  i4: null,
  i5: null,
  dns: ['192.0.2.53'],
  serverEndpoint: 'router.example.test:62001',
  preferredConfigFormat: 'amneziawg' as const,
};
describe('complete client configuration transactions', () => {
  test('automatic creation and explicit addresses retain the assigned interface IPv6 policy', async () => {
    const f = await fixture();
    await f.db
      .update(schema.wgInterface)
      .set({ ipv6Cidr: 'fd42:8::/64' })
      .execute();
    const [created] = await f.clients.create({ name: 'automatic addresses' });
    const row = (await f.clients.get(created!.clientId))!;
    expect(row.ipv6Address).toBe('fd42:8::2');
    const before = JSON.stringify(await f.db.query.client.findMany()),
      revision = (await f.db.query.runtimeReconciliationState.findFirst())!
        .desiredRevision;
    await expect(
      f.clients.create({ name: 'unsupported opt-out', ipv6Address: null })
    ).rejects.toMatchObject({ code: 'invalid_address', field: 'ipv6Address' });
    await expect(
      f.clients.update(row.id, {
        ...ClientUpdateSchema.parse(row),
        ipv6Address: null,
      })
    ).rejects.toMatchObject({ code: 'invalid_address', field: 'ipv6Address' });
    expect(JSON.stringify(await f.db.query.client.findMany()) === before).toBe(
      true
    );
    expect(
      (await f.db.query.runtimeReconciliationState.findFirst())?.desiredRevision
    ).toBe(revision);
  });
  test('creates with an independently generated private key and every supported override, preserving explicit nulls', async () => {
    const f = await fixture(),
      privateKey = syntheticKey(),
      publicKey = deriveClientPublicKey(privateKey);
    const [created] = await f.clients.create({
      ...fields,
      privateKey,
      publicKey,
      preSharedKey: null,
    });
    const row = (await f.clients.get(created!.clientId))!;
    for (const [name, value] of Object.entries(fields))
      expect(
        JSON.stringify(row[name as keyof typeof row]) ===
          JSON.stringify(name === 'serverAllowedIps' ? ['192.0.2.0/24'] : value)
      ).toBe(true);
    expect(row.privateKey === privateKey && row.publicKey === publicKey).toBe(
      true
    );
    expect(row.preSharedKey === null).toBe(true);
    expect(
      (await f.db.query.runtimeReconciliationState.findFirst())?.desiredRevision
    ).toBe(2);
    const publicRows = await f.clients.getAllPublic();
    expect(
      publicRows.every(
        (c) =>
          !Object.hasOwn(c, 'privateKey') && !Object.hasOwn(c, 'preSharedKey')
      )
    ).toBe(true);
  });
  test('omitted creation keys generate a valid pair/PSK and omitted edit secrets preserve the exact accepted values', async () => {
    const f = await fixture(),
      row = await f.createClient('generated');
    expect(deriveClientPublicKey(row.privateKey) === row.publicKey).toBe(true);
    expect(row.preSharedKey !== null).toBe(true);
    await f.clients.update(row.id, {
      ...ClientUpdateSchema.parse(row),
      name: 'renamed',
    });
    const next = (await f.clients.get(row.id))!;
    expect(
      next.privateKey === row.privateKey &&
        next.publicKey === row.publicKey &&
        next.preSharedKey === row.preSharedKey
    ).toBe(true);
  });
  test('replaces identity and clears/replaces PSK atomically while preserving IDs, owner, interface, links and routing references', async () => {
    const f = await fixture(),
      row = await f.createClient('member'),
      exit = await f.createClient('exit');
    await f.db
      .insert(schema.oneTimeLink)
      .values({
        id: row.id,
        oneTimeLink: 'stable-fixture-link',
        expiresAt: '2030-01-01T00:00:00.000Z',
      })
      .execute();
    const group = await f.groups.createAggregate({
      name: 'LAN',
      enabled: true,
      natEnabled: false,
      allExitsDownPolicy: 'block',
      routedIpv4Prefixes: ['192.168.1.0/24'],
      memberClientIds: [row.id],
      exits: [{ clientId: exit.id, priority: 0, enabled: true }],
    });
    const privateKey = syntheticKey();
    await f.clients.update(row.id, {
      ...ClientUpdateSchema.parse(row),
      privateKey,
      preSharedKey: null,
    });
    const next = (await f.clients.get(row.id))!;
    expect(
      next.privateKey === privateKey &&
        next.publicKey === deriveClientPublicKey(privateKey)
    ).toBe(true);
    expect(next.preSharedKey === null).toBe(true);
    expect([next.id, next.userId, next.interfaceId]).toEqual([
      row.id,
      row.userId,
      row.interfaceId,
    ]);
    expect(
      (await f.db.query.oneTimeLink.findFirst())?.oneTimeLink ===
        'stable-fixture-link'
    ).toBe(true);
    expect(
      (await f.groups.get(group.group.id)).members.map((m) => m.clientId)
    ).toEqual([row.id]);
    const psk = syntheticKey();
    await f.clients.update(row.id, {
      ...ClientUpdateSchema.parse(next),
      preSharedKey: psk,
    });
    expect((await f.clients.get(row.id))!.preSharedKey === psk).toBe(true);
  });
  test('retains disabled same-interface credential/address alternatives, but rejects simultaneous enable and cross-interface/server reuse', async () => {
    const f = await fixture(),
      first = await f.createClient('active');
    const [created] = await f.clients.create({
      name: 'alternate',
      privateKey: first.privateKey,
      ipv4Address: first.ipv4Address,
      enabled: false,
    });
    const alternate = (await f.clients.get(created!.clientId))!;
    await expect(f.clients.toggle(alternate.id, true)).rejects.toThrow();
    await f.clients.toggle(first.id, false);
    await f.clients.toggle(alternate.id, true);
    await f.addInterface('awg1', '10.9.0.0/24');
    await expect(
      f.clients.create({
        name: 'cross reuse',
        interfaceId: 'awg1',
        privateKey: first.privateKey,
        enabled: false,
      })
    ).rejects.toThrow('credentials cannot be reused');
    const server = (await f.db.query.wgInterface.findFirst({
      where: eq(schema.wgInterface.name, 'wg0'),
    }))!;
    await expect(
      f.clients.create({
        name: 'server reuse',
        privateKey: server.privateKey,
        enabled: false,
      })
    ).rejects.toThrow('credentials cannot be reused');
  });
  test('invalid keys, addresses, compatibility and AWG overrides preserve all rows and revisions without echoing secrets', async () => {
    const f = await fixture(),
      row = await f.createClient('stable'),
      before = JSON.stringify(await f.clients.get(row.id)),
      revision = await f.db.query.runtimeReconciliationState.findFirst();
    const privateKey = syntheticKey(),
      other = deriveClientPublicKey(syntheticKey());
    for (const change of [
      { privateKey, publicKey: other },
      { privateKey: '********' },
      { privateKey: null },
      { ipv4Address: '10.8.0.0' },
      { ipv4Address: '10.8.0.1' },
      { ipv4Address: '10.8.0.255' },
      { jMin: -1 },
      { jMin: 50, jMax: 10 },
      { mtu: 1400.5 },
    ]) {
      let caught: unknown;
      try {
        await f.clients.update(row.id, {
          ...ClientUpdateSchema.parse(row),
          ...change,
        } as never);
      } catch (error) {
        caught = error;
      }
      expect(caught instanceof Error).toBe(true);
      expect(String(caught).includes(privateKey)).toBe(false);
      expect(JSON.stringify(await f.clients.get(row.id)) === before).toBe(true);
      expect(
        (await f.db.query.runtimeReconciliationState.findFirst())
          ?.desiredRevision
      ).toBe(revision!.desiredRevision);
    }
    await f.db
      .update(schema.wgInterface)
      .set({ awgParametersEnabled: true, defaultConfigFormat: 'amneziawg' })
      .execute();
    await expect(
      f.clients.update(row.id, {
        ...ClientUpdateSchema.parse(row),
        preferredConfigFormat: 'wireguard',
      })
    ).rejects.toThrow('format_unavailable');
  });
  test('redacts private SQL binds even when a failure occurs after the credential write', async () => {
    const f = await fixture(),
      row = await f.createClient('stable'),
      privateKey = syntheticKey();
    await f.store.raw.execute(
      "CREATE TRIGGER fail_client_revision BEFORE UPDATE ON runtime_reconciliation_state_table BEGIN SELECT RAISE(ABORT, 'private-database-bind-fixture'); END"
    );
    let caught: unknown;
    try {
      await f.clients.update(row.id, {
        ...ClientUpdateSchema.parse(row),
        privateKey,
      });
    } catch (error) {
      caught = error;
    }
    expect(caught).toMatchObject({ code: 'write_failed' });
    expect(
      String(caught).includes(privateKey) ||
        String(caught).includes('private-database-bind-fixture')
    ).toBe(false);
    expect(Object.hasOwn(caught as object, 'cause')).toBe(false);
    expect((await f.clients.get(row.id))!.privateKey === row.privateKey).toBe(
      true
    );
  });
  test('version 1 keeps old requests and defaults working while refusing new credential replacement until guarded activation', async () => {
    const f = await fixture(1),
      [created] = await f.clients.create({ name: 'legacy', expiresAt: null }),
      row = (await f.clients.get(created!.clientId))!;
    await f.clients.update(row.id, {
      ...ClientUpdateSchema.parse(row),
      name: 'legacy renamed',
    });
    await expect(
      f.clients.update(row.id, {
        ...ClientUpdateSchema.parse(row),
        privateKey: syntheticKey(),
      })
    ).rejects.toThrow('policy_version_required');
    expect((await f.clients.get(row.id))!.privateKey === row.privateKey).toBe(
      true
    );
  });
});
