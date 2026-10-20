import { randomBytes } from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, describe, expect, test, vi } from 'vitest';

import { hookFirewall } from '../helpers/hookFirewall';

import { createNodeSqliteDatabase } from '#db/nodeSqlite';
import { RoutingPolicyRuntimeService } from '#db/repositories/runtime/policyService';
import * as schema from '#db/schema';
import { deriveClientPublicKey } from '#server/utils/clientCredentials';
import { parseManagedInterfaceConfig } from '#server/utils/managedInterfaceState';
import type { ManagedInterfaceDevices } from '#server/utils/managedInterfaceTransition';
import { ManagedServerHookEffects } from '#server/utils/managedServerHooks';
import { policyPeerId } from '#server/utils/routingPolicy';
import { RoutingPolicyBackups } from '#server/utils/routingPolicyBackups';
import {
  rebasePendingRoutingNamespace,
  cancelPendingBootstrapInNewNamespace,
} from '#server/utils/routingPolicyColdStart';
import { buildPolicyBootstrapBaseline } from '#server/utils/routingPolicyBootstrap';
import { RoutingExecutor } from '#server/utils/routingExecutor';
import { RoutingGuard } from '#server/utils/routingGuard';
import { RoutingPolicyFirewall } from '#server/utils/routingPolicyFirewall';
import { routingPolicyRuntimeFingerprint } from '#server/utils/routingPolicyRuntime';
import type { RoutingPolicyJournal } from '#shared/types/routingPolicy';

const roots: string[] = [],
  stores: ReturnType<typeof createNodeSqliteDatabase>[] = [];
afterEach(async () => {
  await Promise.all(stores.splice(0).map((s) => s.close()));
  await Promise.all(roots.splice(0).map((r) => fs.rm(r, { recursive: true })));
});
const oldNamespace = '11111111-1111-4111-8111-111111111111:4:4026531001',
  newNamespace = '11111111-1111-4111-8111-111111111111:4:4026531002';
async function fixture() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'wge-cold-policy-'));
  roots.push(root);
  const store = createNodeSqliteDatabase(path.join(root, 'test.db'), schema);
  stores.push(store);
  await store.migrate({
    migrationsFolder: fileURLToPath(
      new URL('../../server/database/migrations', import.meta.url)
    ),
  });
  const serverKey = randomBytes(32).toString('base64'),
    peerKey = deriveClientPublicKey(randomBytes(32).toString('base64')),
    oldConfig = `[Interface]\nPrivateKey = ${serverKey}\nListenPort = 62001\nAddress = 10.8.0.1/24\nMTU = 1420\nTable = off\nPreUp = \nPostUp = iptables -A FORWARD -i wg0 -j ACCEPT;\nPreDown = \nPostDown = iptables -D FORWARD -i wg0 -j ACCEPT;\n[Peer]\nPublicKey = ${peerKey}\nAllowedIPs = 10.8.0.2/32\n`,
    candidate = oldConfig.replace('62001', '62002');
  const plan: RoutingPolicyJournal['plan'] = {
      version: 2,
      namespaceId: oldNamespace,
      interfaces: [
        {
          interfaceId: 'wg0',
          ipv4Cidr: '10.8.0.0/24',
          enabled: true,
          observedUp: true,
          hooksApplied: true,
        },
      ],
      peers: [
        {
          clientId: 1,
          interfaceId: 'wg0',
          peerId: policyPeerId({ interfaceId: 'wg0', publicKey: peerKey }),
          prefixes: ['10.8.0.2/32'],
        },
      ],
      bypassPrefixes: ['10.8.0.0/24'],
      siteRoutes: [],
      programs: [],
      groups: [],
      clientFirewall: { enableIpv6: false, interfaces: [], entries: [] },
    },
    previous = {
      revision: 1,
      plan,
      fingerprint: routingPolicyRuntimeFingerprint(plan),
    },
    target = { ...previous, revision: 2 };
  await store.db
    .update(schema.general)
    .set({ routingPolicyVersion: 2 })
    .execute();
  await store.db
    .update(schema.runtimeReconciliationState)
    .set({ desiredRevision: 2, appliedRevision: 1 })
    .execute();
  await store.db
    .update(schema.routingPolicyRuntime)
    .set({ applied: previous })
    .execute();
  await fs.writeFile(path.join(root, 'wg0.conf'), oldConfig, { mode: 0o600 });
  const backups = new RoutingPolicyBackups(root),
    reference = await backups.create(['wg0'], {
      candidateConfigurations: new Map([['wg0', candidate]]),
    });
  const journal = new RoutingPolicyRuntimeService(store.db),
    pending = await journal.prepare(
      {
        ...target,
        stage: 'prepared',
        guardScopes: [],
        backupBasenames: [reference],
        errorCode: null,
      },
      previous
    );
  await fs.writeFile(path.join(root, 'wg0.conf'), candidate);
  const devices: ManagedInterfaceDevices = {
      observe: vi.fn(async () => null),
      validate: vi.fn(async (id, config) => {
        parseManagedInterfaceConfig(id, config);
      }),
      up: vi.fn(async () => {
        throw new Error('must never start');
      }),
      down: vi.fn(async () => {
        throw new Error('must never stop');
      }),
      sync: vi.fn(async () => {
        throw new Error('must never sync');
      }),
      verifyRecoverable: vi.fn(async () => {}),
    },
    executor = new RoutingExecutor(async () => ''),
    guard = new RoutingGuard(async () => ''),
    firewall = new RoutingPolicyFirewall(async () => ''),
    kernel = hookFirewall([]);
  vi.spyOn(executor, 'observe').mockResolvedValue({
    chains: [],
    routes: [],
    policyRules: [],
    markUses: [],
  });
  vi.spyOn(executor, 'prepare').mockResolvedValue(undefined);
  vi.spyOn(guard, 'ensure').mockResolvedValue(undefined);
  vi.spyOn(guard, 'verify').mockResolvedValue(undefined);
  vi.spyOn(guard, 'prepare').mockResolvedValue(null);
  vi.spyOn(guard, 'remove').mockResolvedValue(undefined);
  vi.spyOn(firewall, 'verifyAbsent').mockResolvedValue(undefined);
  const deps = {
    journal,
    backups,
    executor,
    guard,
    firewall,
    devices,
    hooks: new ManagedServerHookEffects(kernel.run),
    configDirectory: root,
    protectedPaths: [],
  };
  return { root, store, deps, previous, pending, oldConfig, candidate, kernel };
}
describe('cold namespace pending rebase', () => {
  test.each([false, true])(
    'an interrupted first promotion cancels only after empty-namespace verification; failed publication=%s',
    async (failed) => {
      const f = await fixture(),
        target = { ...f.previous, revision: 2 },
        publicKey = parseManagedInterfaceConfig(
          'wg0',
          f.oldConfig
        ).peers[0]!.get('publickey')!,
        bootstrap = buildPolicyBootstrapBaseline(
          {
            interfaces: [{ interfaceId: 'wg0', ipv4Cidr: '10.8.0.0/24' }],
            clients: [
              {
                id: 1,
                name: '',
                interfaceId: 'wg0',
                publicKey,
                ipv4Address: '10.8.0.2',
                enabled: true,
                serverAllowedIps: [],
              },
            ],
            groups: [],
          },
          target
        ),
        pending = { ...f.pending, ...target, bootstrap };
      await f.store.db
        .update(schema.general)
        .set({ routingPolicyVersion: 1 })
        .execute();
      await f.store.db
        .update(schema.runtimeReconciliationState)
        .set({ appliedRevision: 2 })
        .execute();
      await f.store.db
        .update(schema.routingPolicyRuntime)
        .set({ applied: null, pending })
        .execute();
      const publish = vi.fn(async () => {
        if (failed) throw new Error('private failure');
      });
      await expect(
        cancelPendingBootstrapInNewNamespace(f.deps, oldNamespace, publish)
      ).rejects.toThrow('bootstrap_cancellation_unavailable');
      expect(publish).not.toHaveBeenCalled();
      if (failed) {
        await expect(
          cancelPendingBootstrapInNewNamespace(f.deps, newNamespace, publish)
        ).rejects.toThrow('final_verification_failed');
        expect(await f.deps.journal.get()).toMatchObject({
          version: 1,
          applied: null,
          pending,
          runtime: { appliedRevision: 2 },
        });
        expect(f.deps.guard.ensure).toHaveBeenCalledTimes(2);
      } else {
        await cancelPendingBootstrapInNewNamespace(
          f.deps,
          newNamespace,
          publish
        );
        expect(await f.deps.journal.get()).toMatchObject({
          version: 1,
          applied: null,
          pending: null,
          runtime: {
            desiredRevision: 2,
            appliedRevision: 2,
            status: 'pending',
            lastError: 'bootstrap_namespace_reset',
          },
        });
      }
      expect(f.deps.devices.up).not.toHaveBeenCalled();
      expect(f.kernel.writes).toEqual([]);
      expect(await fs.readFile(path.join(f.root, 'wg0.conf'), 'utf8')).toBe(
        f.oldConfig
      );
    }
  );

  test('restores durable old bytes and CAS-replaces one Pending with a private down baseline, without inheriting hook ownership', async () => {
    const f = await fixture(),
      next = await rebasePendingRoutingNamespace(f.deps, newNamespace);
    expect(next).toMatchObject({
      revision: 1,
      withdrawal: { unavailableInterfaceIds: ['wg0'], resetNamespace: true },
      supersededGuardScopes: [],
    });
    expect(next.plan.interfaces[0]).toMatchObject({
      observedUp: false,
      hooksApplied: false,
    });
    expect(await fs.readFile(path.join(f.root, 'wg0.conf'), 'utf8')).toBe(
      f.oldConfig
    );
    expect(next.backupBasenames).not.toEqual(f.pending.backupBasenames);
    expect(
      await f.deps.backups.readPrivateLifecycleIntent(next.backupBasenames[0]!)
    ).toMatchObject({
      interfaces: [
        {
          previousUp: false,
          targetUp: false,
          previousHooksApplied: false,
          targetHooksApplied: false,
        },
      ],
      hooks: [],
    });
    expect((await f.deps.journal.get()).applied).toEqual(f.previous);
    expect(f.deps.devices.up).not.toHaveBeenCalled();
    expect(f.kernel.writes).toEqual([]);
    // A crash after CAS is recognized; do not create another backup/history.
    expect(await rebasePendingRoutingNamespace(f.deps, newNamespace)).toEqual(
      next
    );
  });
  test.each(['device', 'routing', 'private bytes'])(
    'refuses unknown %s before changing Pending or restoring old files',
    async (kind) => {
      const f = await fixture();
      if (kind === 'device')
        vi.mocked(f.deps.devices.observe).mockResolvedValue({
          showconf: '',
          addresses: '',
        });
      if (kind === 'routing')
        vi.mocked(f.deps.executor.observe).mockResolvedValue({
          routes: [],
          policyRules: [],
          markUses: [],
          chains: [
            { table: 'mangle', name: 'WG_ROUTE_MARK', owner: 'wg-easy' },
          ],
        });
      if (kind === 'private bytes')
        await fs.writeFile(path.join(f.root, 'wg0.conf'), '# foreign');
      await expect(
        rebasePendingRoutingNamespace(f.deps, newNamespace)
      ).rejects.toThrow(/cold_namespace_|unknown_configuration/);
      expect((await f.deps.journal.get()).pending).toEqual(f.pending);
      expect(await fs.readFile(path.join(f.root, 'wg0.conf'), 'utf8')).toBe(
        kind === 'private bytes' ? '# foreign' : f.candidate
      );
      expect(f.deps.devices.up).not.toHaveBeenCalled();
    }
  );
  test('a failed CAS leaves old Pending recoverable and discards only the new unreferenced backup', async () => {
    const f = await fixture();
    vi.spyOn(f.deps.journal, 'rebasePendingToWithdrawal').mockRejectedValue(
      new Error('injected writer race')
    );
    await expect(
      rebasePendingRoutingNamespace(f.deps, newNamespace)
    ).rejects.toThrow('injected writer race');
    expect((await f.deps.journal.get()).pending).toEqual(f.pending);
    expect(
      (await fs.readdir(f.deps.backups.directory)).filter((name) =>
        name.endsWith('.json')
      )
    ).toEqual(f.pending.backupBasenames);
    expect(await fs.readFile(path.join(f.root, 'wg0.conf'), 'utf8')).toBe(
      f.oldConfig
    );
  });
});
