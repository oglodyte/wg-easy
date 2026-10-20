import { randomBytes } from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, test } from 'vitest';

import { hookFirewall } from '../helpers/hookFirewall';

import {
  ManagedInterfaceTransition,
  type ManagedInterfaceDevices,
} from '#server/utils/managedInterfaceTransition';
import { deriveClientPublicKey } from '#server/utils/clientCredentials';
import { parseManagedInterfaceConfig } from '#server/utils/managedInterfaceState';
import {
  ManagedServerHookEffects,
  admitManagedServerHooks,
  resolveManagedServerHooks,
} from '#server/utils/managedServerHooks';
import { RoutingPolicyBackups } from '#server/utils/routingPolicyBackups';
import { policyPeerId } from '#server/utils/routingPolicy';
import type { AppliedRoutingPolicyPlan } from '#shared/types/routingPolicy';

const roots: string[] = [];
afterEach(async () => {
  for (const root of roots.splice(0))
    await fs.rm(root, { recursive: true, force: true });
});
function config(
  interfaceId: string,
  serverKey: string,
  peerKey: string,
  index: number,
  port = 62001,
  psk: string | null = null
) {
  const up = `iptables -A INPUT -p udp -m udp --dport ${port} -j ACCEPT; iptables -A FORWARD -i ${interfaceId} -j ACCEPT;`;
  return `[Interface]\nPrivateKey = ${serverKey}\nListenPort = ${port}\nAddress = 10.24.${index}.1/24\nMTU = 1420\nTable = off\nPreUp = : safe-marker\nPostUp = ${up}\nPreDown = \nPostDown = ${up.replaceAll(' -A ', ' -D ')}\n[Peer]\nPublicKey = ${peerKey}\n${psk ? `PresharedKey = ${psk}\n` : ''}AllowedIPs = 10.24.${index}.2/32\n`;
}
function observed(interfaceId: string, config: string) {
  const parsed = parseManagedInterfaceConfig(interfaceId, config),
    showconf = `[Interface]\n${[...parsed.fields]
      .filter(
        ([name]) =>
          ![
            'address',
            'mtu',
            'table',
            'preup',
            'postup',
            'predown',
            'postdown',
          ].includes(name)
      )
      .map(([name, value]) => `${name} = ${value}`)
      .join(
        '\n'
      )}\n${parsed.peers.map((p) => '[Peer]\n' + [...p].map(([name, value]) => `${name} = ${value}`).join('\n')).join('\n')}`,
    [local, prefix] = parsed.fields.get('address')!.split('/');
  return {
    showconf,
    addresses: JSON.stringify([
      {
        ifname: interfaceId,
        flags: ['UP'],
        mtu: 1420,
        addr_info: [
          { family: 'inet', local, prefixlen: Number(prefix), scope: 'global' },
        ],
      },
    ]),
  };
}
function plan(
  configs: Map<string, string | null>,
  upIds: string[]
): AppliedRoutingPolicyPlan {
  return {
    version: 2,
    interfaces: [...configs].map(([interfaceId, contents], i) => ({
      interfaceId,
      ipv4Cidr: contents
        ? parseManagedInterfaceConfig(interfaceId, contents)
            .fields.get('address')!
            .replace(/\.1\//, '.0/')
        : `10.24.${i + 1}.0/24`,
      enabled: upIds.includes(interfaceId),
      observedUp: upIds.includes(interfaceId),
    })),
    bypassPrefixes: [],
    programs: [],
    groups: [],
    siteRoutes: [],
    clientFirewall: { enableIpv6: false, interfaces: [], entries: [] },
    peers: [...configs].flatMap(([interfaceId, contents], i) =>
      contents && upIds.includes(interfaceId)
        ? parseManagedInterfaceConfig(interfaceId, contents).peers.map((p) => ({
            clientId: i + 1,
            interfaceId,
            peerId: policyPeerId({
              interfaceId,
              publicKey: p.get('publickey')!,
            }),
            prefixes: p
              .get('allowedips')!
              .split(',')
              .map((v) => v.trim()),
          }))
        : []
    ),
  };
}
async function fixture(
  mode: 'restart' | 'credentials' | 'identical' = 'restart'
) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'wge-lifecycle-'));
  roots.push(root);
  const serverKey = randomBytes(32).toString('base64'),
    peerKey = deriveClientPublicKey(randomBytes(32).toString('base64')),
    oldPsk = randomBytes(32).toString('base64'),
    previous = new Map([
      ['wg0', config('wg0', serverKey, peerKey, 1, 62001, oldPsk)],
      [
        'other0',
        config(
          'other0',
          randomBytes(32).toString('base64'),
          deriveClientPublicKey(randomBytes(32).toString('base64')),
          2,
          62009
        ),
      ],
    ]),
    target = new Map(previous);
  if (mode !== 'identical')
    target.set(
      'wg0',
      config('wg0', serverKey, peerKey, 1, mode === 'restart' ? 62002 : 62001)
    );
  for (const [id, contents] of previous)
    await fs.writeFile(path.join(root, `${id}.conf`), contents, {
      mode: 0o600,
    });
  const previousPlan = plan(previous, ['wg0', 'other0']),
    targetPlan = plan(target, ['wg0', 'other0']),
    runtime = new Map(previous),
    rules = [...previous].flatMap(([id, contents]) =>
      resolveManagedServerHooks(
        admitManagedServerHooks(
          id,
          parseManagedInterfaceConfig(id, contents).fields
        )
      )
    ),
    firewall = hookFirewall(rules),
    hooks = new ManagedServerHookEffects(firewall.run),
    backups = new RoutingPolicyBackups(root),
    events: string[] = [];
  let boundary = 0,
    injected = -1;
  const guard = async () => {
      events.push('guard');
    },
    point = (when: string) => {
      events.push(when);
      if (++boundary === injected)
        throw new Error('injected lifecycle failure');
    };
  const devices: ManagedInterfaceDevices = {
    observe: async (id) =>
      runtime.has(id) ? observed(id, runtime.get(id)!) : null,
    validate: async (id, c) => {
      parseManagedInterfaceConfig(id, c);
    },
    down: async (id, c) => {
      expect(await fs.readFile(path.join(root, `${id}.conf`), 'utf8')).toBe(c);
      point(`before-down-${id}`);
      runtime.delete(id);
      point(`after-down-${id}`);
    },
    up: async (id, c) => {
      expect(await fs.readFile(path.join(root, `${id}.conf`), 'utf8')).toBe(c);
      expect(runtime.has(id)).toBe(false);
      point(`before-up-${id}`);
      runtime.set(id, c);
      point(`after-up-${id}`);
    },
    sync: async (id, c) => {
      expect(runtime.has(id)).toBe(true);
      point(`before-sync-${id}`);
      runtime.set(id, c);
      point(`after-sync-${id}`);
    },
    verifyRecoverable: async (id, configs) => {
      if (runtime.has(id) && !configs.includes(runtime.get(id)!))
        throw new Error('unknown device');
    },
  };
  const deps = { configDirectory: root, backups, devices, hooks };
  return {
    root,
    previous,
    target,
    previousPlan,
    targetPlan,
    runtime,
    firewall,
    hooks,
    backups,
    events,
    guard,
    devices,
    deps,
    peerKey,
    failAt: (at: number) => {
      boundary = 0;
      injected = at;
    },
    prepare: () =>
      ManagedInterfaceTransition.prepare(
        deps,
        previousPlan,
        targetPlan,
        target,
        {
          restartInterfaceIds:
            mode === 'identical' ? new Set(['wg0']) : new Set(),
        }
      ),
  };
}

describe('private guarded interface lifecycle orchestration', () => {
  test('a failed bring-up restores the down-device baseline and its retained hooks without restarting the failed device', async () => {
    const f = await fixture();
    f.runtime.delete('wg0');
    const down = structuredClone(f.previousPlan);
    down.interfaces.find((i) => i.interfaceId === 'wg0')!.observedUp = false;
    down.interfaces.find((i) => i.interfaceId === 'wg0')!.hooksApplied = true;
    down.peers = down.peers.filter((p) => p.interfaceId !== 'wg0');
    const transition = await ManagedInterfaceTransition.prepare(
        f.deps,
        down,
        f.targetPlan,
        f.target
      ),
      reference = await f.backups.create([...f.target.keys()], {
        candidateConfigurations: transition.candidateConfigurations,
        expectedPreviousConfigurations: transition.previousConfigurations,
        lifecycleIntent: transition.intent,
      });
    f.failAt(1);
    await expect(transition.apply(f.guard)).rejects.toThrow(
      'injected lifecycle failure'
    );
    f.failAt(-1);
    const reopened = await ManagedInterfaceTransition.reopen(
      f.deps,
      reference,
      down,
      f.targetPlan
    );
    await reopened.beforeRestore(f.guard);
    await f.backups.restore(reference);
    await reopened.restorePrevious(f.guard);
    expect(f.runtime.has('wg0')).toBe(false);
    expect(f.events.filter((e) => e === 'before-up-wg0')).toHaveLength(1);
    expect(f.events.some((e) => e.includes('other0'))).toBe(false);
    await reopened.verify('previous');
  });

  test('preserves inactive unsupported hook text while allowing a safe start, then restores it without execution', async () => {
    const f = await fixture();
    f.runtime.delete('wg0');
    const old = f.previous
      .get('wg0')!
      .replace('PreUp = : safe-marker', 'PreUp = opaque preserved script');
    await fs.writeFile(path.join(f.root, 'wg0.conf'), old);
    const down = structuredClone(f.previousPlan);
    down.interfaces.find((i) => i.interfaceId === 'wg0')!.observedUp = false;
    down.interfaces.find((i) => i.interfaceId === 'wg0')!.hooksApplied = false;
    down.peers = down.peers.filter((p) => p.interfaceId !== 'wg0');
    // No old effect exists in this namespace. Equal unrelated rules, if any,
    // are preserved as baseline by the typed effect capture.
    const previous = f.firewall.entries.filter(
      (l) => l.includes('wg0') || l.includes('--dport 62001')
    );
    for (const line of previous)
      f.firewall.entries.splice(f.firewall.entries.indexOf(line), 1);
    const transition = await ManagedInterfaceTransition.prepare(
        f.deps,
        down,
        f.targetPlan,
        f.target
      ),
      reference = await f.backups.create([...f.target.keys()], {
        candidateConfigurations: transition.candidateConfigurations,
        lifecycleIntent: transition.intent,
      });
    await transition.apply(f.guard);
    const reopened = await ManagedInterfaceTransition.reopen(
      f.deps,
      reference,
      down,
      f.targetPlan
    );
    await reopened.beforeRestore(f.guard);
    await f.backups.restore(reference);
    await reopened.restorePrevious(f.guard);
    expect(f.runtime.has('wg0')).toBe(false);
    expect(
      (await fs.readFile(path.join(f.root, 'wg0.conf'), 'utf8')).includes(
        'opaque preserved script'
      )
    ).toBe(true);
    await reopened.verify('previous');
  });

  test('refuses a newly present interface when neither side of a file-only transition owns a device', async () => {
    const f = await fixture();
    f.runtime.delete('wg0');
    const down = structuredClone(f.previousPlan);
    down.interfaces.find((i) => i.interfaceId === 'wg0')!.observedUp = false;
    down.interfaces.find((i) => i.interfaceId === 'wg0')!.hooksApplied = false;
    down.peers = down.peers.filter((p) => p.interfaceId !== 'wg0');
    const target = structuredClone(down);
    const transition = await ManagedInterfaceTransition.prepare(
        f.deps,
        down,
        target,
        f.target
      ),
      reference = await f.backups.create([...f.target.keys()], {
        candidateConfigurations: transition.candidateConfigurations,
        lifecycleIntent: transition.intent,
      });
    f.runtime.set('wg0', f.previous.get('wg0')!);
    const before = [...f.events],
      reopened = await ManagedInterfaceTransition.reopen(
        f.deps,
        reference,
        down,
        target
      );
    await expect(reopened.beforeRestore(f.guard)).rejects.toThrow(
      'unknown_device'
    );
    expect(f.events).toEqual(before);
  });
  test('keeps an applied dynamic egress binding during peer sync and refreshes it only on a requested restart', async () => {
    const f = await fixture('credentials'),
      prefix =
        'OUT_IF=$(ip -4 route show default | awk "NR == 1 {print \\$5}"); test -n "$OUT_IF" || exit 1;',
      old =
        f.previous
          .get('wg0')!
          .replace('PostUp = ', 'PostUp = ' + prefix)
          .replace('PostDown = ', 'PostDown = ' + prefix) +
        '# wg-easy managed hook egress: ethOld\n',
      desired = old
        .replace(/^PresharedKey = .*\n/m, '')
        .replace(/^# wg-easy managed hook egress: .*\n/m, '');
    f.previous.set('wg0', old);
    f.runtime.set('wg0', old);
    f.target.set('wg0', desired);
    await fs.writeFile(path.join(f.root, 'wg0.conf'), old);
    let lookups = 0;
    f.deps.hooks = new ManagedServerHookEffects(
      async (binary, args, options) => {
        if (binary === 'ip') {
          lookups++;
          return JSON.stringify([{ dev: 'ethNew' }]);
        }
        return f.firewall.run(binary, args, options);
      }
    );
    const transition = await f.prepare();
    expect(lookups).toBe(0);
    expect(
      transition.intent.interfaces.find((i) => i.interfaceId === 'wg0')
    ).toMatchObject({
      restart: false,
      previousDefaultEgress: 'ethOld',
      targetDefaultEgress: 'ethOld',
    });
    await transition.apply(f.guard);
    expect(f.events.filter((e) => e !== 'guard')).toEqual([
      'before-sync-wg0',
      'after-sync-wg0',
    ]);
    const restarted = await ManagedInterfaceTransition.prepare(
      f.deps,
      f.targetPlan,
      f.targetPlan,
      f.target,
      { restartInterfaceIds: new Set(['wg0']) }
    );
    expect(lookups).toBe(1);
    expect(
      restarted.intent.interfaces.find((i) => i.interfaceId === 'wg0')
    ).toMatchObject({
      restart: true,
      previousDefaultEgress: 'ethOld',
      targetDefaultEgress: 'ethNew',
    });
    expect(restarted.candidateConfigurations.get('wg0')).toContain(
      '# wg-easy managed hook egress: ethNew\n'
    );
  });

  test('stops with old bytes, writes candidate before start, and preserves an unrelated healthy interface', async () => {
    const f = await fixture(),
      transition = await f.prepare(),
      reference = await f.backups.create([...f.target.keys()], {
        candidateConfigurations: transition.candidateConfigurations,
        lifecycleIntent: transition.intent,
      });
    await transition.apply(f.guard);
    expect(f.events.filter((e) => e !== 'guard')).toEqual([
      'before-down-wg0',
      'after-down-wg0',
      'before-up-wg0',
      'after-up-wg0',
    ]);
    expect(f.runtime.get('wg0')).toBe(f.target.get('wg0'));
    expect(f.runtime.get('other0')).toBe(f.previous.get('other0'));
    expect(transition.forcePeerIds).toContain(
      policyPeerId({ interfaceId: 'wg0', publicKey: f.peerKey })
    );
    const reopened = await ManagedInterfaceTransition.reopen(
      f.deps,
      reference,
      f.previousPlan,
      f.targetPlan
    );
    await reopened.beforeRestore(f.guard);
    await f.backups.restore(reference);
    await reopened.restorePrevious(f.guard);
    expect(f.runtime).toEqual(f.previous);
    expect(f.events.some((e) => e.includes('other0'))).toBe(false);
  });

  test.each([1, 2, 3, 4])(
    'recovers a process boundary %s from private old/candidate data without desired credentials',
    async (boundary) => {
      const f = await fixture(),
        transition = await f.prepare(),
        reference = await f.backups.create([...f.target.keys()], {
          candidateConfigurations: transition.candidateConfigurations,
          lifecycleIntent: transition.intent,
        });
      f.failAt(boundary);
      await expect(transition.apply(f.guard)).rejects.toThrow(
        'injected lifecycle failure'
      );
      f.failAt(-1);
      const reopened = await ManagedInterfaceTransition.reopen(
        f.deps,
        reference,
        f.previousPlan,
        f.targetPlan
      );
      await reopened.beforeRestore(f.guard);
      await f.backups.restore(reference);
      await reopened.restorePrevious(f.guard);
      await reopened.verify('previous');
      expect(f.runtime).toEqual(f.previous);
      expect(f.events.some((e) => e.includes('other0'))).toBe(false);
    }
  );

  test('retains identical-byte explicit restart through a failure after starting and repairs partial PostUp', async () => {
    const f = await fixture('identical'),
      transition = await f.prepare(),
      reference = await f.backups.create([...f.target.keys()], {
        candidateConfigurations: transition.candidateConfigurations,
        lifecycleIntent: transition.intent,
      });
    // Down hook effects are two writes; fail on the first PostUp write.
    f.firewall.setFailure(3);
    await expect(transition.apply(f.guard)).rejects.toThrow(
      'effect_repair_failed'
    );
    expect(f.runtime.get('wg0')).toBe(f.previous.get('wg0'));
    f.firewall.setFailure(-1);
    const reopened = await ManagedInterfaceTransition.reopen(
      f.deps,
      reference,
      f.previousPlan,
      f.targetPlan
    );
    expect(
      reopened.intent.interfaces.find((i) => i.interfaceId === 'wg0')?.restart
    ).toBe(true);
    await reopened.beforeRestore(f.guard);
    await f.backups.restore(reference);
    await reopened.restorePrevious(f.guard);
    await reopened.verify('previous');
    expect(f.events.filter((e) => e === 'after-down-wg0')).toHaveLength(2);
    expect(f.runtime).toEqual(f.previous);
  });

  test('synchronizes credential-only changes under a forced peer guard without restarting other interfaces', async () => {
    const f = await fixture('credentials'),
      transition = await f.prepare();
    expect(transition.intent.interfaces.every((i) => !i.restart)).toBe(true);
    expect([...transition.forcePeerIds]).toEqual([
      policyPeerId({ interfaceId: 'wg0', publicKey: f.peerKey }),
    ]);
    await transition.apply(f.guard);
    expect(f.events.filter((e) => e !== 'guard')).toEqual([
      'before-sync-wg0',
      'after-sync-wg0',
    ]);
    expect(f.runtime.get('wg0')).toBe(f.target.get('wg0'));
  });

  test('preflights every file and device before restoration mutates the first interface', async () => {
    const f = await fixture(),
      transition = await f.prepare(),
      reference = await f.backups.create([...f.target.keys()], {
        candidateConfigurations: transition.candidateConfigurations,
        lifecycleIntent: transition.intent,
      });
    await transition.apply(f.guard);
    await fs.writeFile(
      path.join(f.root, 'other0.conf'),
      'private unknown bytes'
    );
    const before = [...f.events],
      reopened = await ManagedInterfaceTransition.reopen(
        f.deps,
        reference,
        f.previousPlan,
        f.targetPlan
      );
    await expect(reopened.beforeRestore(f.guard)).rejects.toThrow(
      'unknown_configuration'
    );
    expect(f.events).toEqual(before);
    await fs.writeFile(
      path.join(f.root, 'other0.conf'),
      f.previous.get('other0')!
    );
    f.runtime.set(
      'other0',
      f.previous.get('other0')!.replace('62009', '62010')
    );
    await expect(reopened.beforeRestore(f.guard)).rejects.toThrow(
      'unknown device'
    );
    expect(f.events).toEqual(before);
  });

  test('refuses unknown hook multiplicity before stopping any device during restoration', async () => {
    const f = await fixture(),
      transition = await f.prepare(),
      reference = await f.backups.create([...f.target.keys()], {
        candidateConfigurations: transition.candidateConfigurations,
        lifecycleIntent: transition.intent,
      });
    await transition.apply(f.guard);
    const known = f.firewall.entries.find((line) =>
      line.startsWith('4:filter -A FORWARD -i wg0')
    )!;
    f.firewall.entries.push(known);
    const before = [...f.events],
      reopened = await ManagedInterfaceTransition.reopen(
        f.deps,
        reference,
        f.previousPlan,
        f.targetPlan
      );
    await expect(reopened.beforeRestore(f.guard)).rejects.toThrow(
      'unknown_effects'
    );
    expect(f.events).toEqual(before);
    expect(f.runtime.get('wg0')).toBe(f.target.get('wg0'));
  });

  test('rejects opaque hooks and unverified old state before any device write', async () => {
    const f = await fixture();
    f.target.set(
      'other0',
      f.target
        .get('other0')!
        .replace('PreUp = : safe-marker', 'PreUp = echo private opaque script')
    );
    await expect(f.prepare()).rejects.toThrow('unsupported_script');
    expect(f.events).toHaveLength(0);
    f.target.set('other0', f.previous.get('other0')!);
    f.runtime.delete('other0');
    await expect(f.prepare()).rejects.toThrow('previous_device_missing');
    expect(f.events).toHaveLength(0);
  });
});
