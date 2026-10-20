import fs from 'node:fs/promises';
import path from 'node:path';

import { describe, expect, test } from 'vitest';

import { hookFirewall as firewall } from '../helpers/hookFirewall';

import {
  admitManagedServerHooks,
  ManagedServerHookEffects,
  parseManagedHookCounts,
  resolveManagedServerHooks,
  type ManagedHookRule,
} from '#server/utils/managedServerHooks';
import { parseManagedLifecycleIntent } from '#server/utils/managedLifecycleIntent';

const dynamic =
  'OUT_IF=$(ip -4 route show default | awk "NR == 1 {print \\$5}"); test -n "$OUT_IF" || exit 1;';
const up =
  'iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE; iptables -A INPUT -p udp -m udp --dport 51820 -j ACCEPT; iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; ip6tables -t nat -A POSTROUTING -s fd41:1::/64 -o eth0 -j MASQUERADE; ip6tables -A INPUT -p udp -m udp --dport 51820 -j ACCEPT; ip6tables -A FORWARD -i wg0 -j ACCEPT; ip6tables -A FORWARD -o wg0 -j ACCEPT;';
function fields(script = up) {
  return new Map([
    ['preup', ': phase0-baseline'],
    ['postup', script],
    ['predown', ''],
    ['postdown', script.replaceAll(' -A ', ' -D ')],
  ]);
}
function rules(script = up) {
  return resolveManagedServerHooks(
    admitManagedServerHooks('wg0', fields(script))
  );
}
function ruleId(rule: ManagedHookRule) {
  return `${rule.family}:${rule.table} -A ${rule.chain} ${rule.args.join(' ')}`;
}

describe('closed guarded server-hook contract', () => {
  test('admits the exact default and recorded dynamic NAT hooks without changing saved text', async () => {
    expect(rules()).toHaveLength(8);
    const script = dynamic + up.replaceAll('-o eth0', '-o "$OUT_IF"'),
      hooks = fields(script),
      original = [...hooks],
      admitted = admitManagedServerHooks('wg0', hooks);
    expect(admitted.dynamic).toBe(true);
    expect(() => resolveManagedServerHooks(admitted)).toThrow(
      'default_egress_unavailable'
    );
    const fake = firewall([]),
      effects = new ManagedServerHookEffects(fake.run),
      resolved = resolveManagedServerHooks(
        admitted,
        await effects.defaultEgress()
      );
    expect(
      resolved.filter((r) => r.table === 'nat').map((r) => r.args[3])
    ).toEqual(['ens160', 'ens160']);
    expect([...hooks]).toEqual(original);
    const seed = await fs.readFile(
      path.resolve('../staging/phase0/scripts/seed-baseline.sh'),
      'utf8'
    );
    const recorded = seed
      .match(/^phase0_dynamic_post_up='(.*)'$/m)![1]!
      .replaceAll('{{ipv4Cidr}}', '10.8.0.0/24')
      .replaceAll('{{ipv6Cidr}}', 'fd41:1::/64')
      .replaceAll('{{port}}', '51820');
    expect(
      resolveManagedServerHooks(
        admitManagedServerHooks('wg0', fields(recorded)),
        'ens160'
      )
    ).toEqual(resolved);
  });

  test.each([
    'iptables -F FORWARD',
    'iptables -I FORWARD 1 -j ACCEPT',
    'iptables -R FORWARD 1 -j ACCEPT',
    'iptables -P FORWARD ACCEPT',
    'iptables -D FORWARD 1',
    'iptables -A FORWARD -j WG_ROUTE_GUARD',
    'iptables -A WG_CLIENTS -i wg0 -j ACCEPT',
    'iptables -t nat -A PREROUTING -j DNAT --to 10.8.0.2',
    'iptables -A FORWARD -i $(touch /tmp/opaque) -j ACCEPT',
    'iptables -A FORWARD -i `opaque` -j ACCEPT',
    'iptables -A FORWARD -i wg0 -j ACCEPT > /tmp/out',
    'iptables -A FORWARD -i wg0 -j ACCEPT && opaque',
    'iptables -A FORWARD -i wg0 -j ACCEPT | opaque',
    'iptables -A FORWARD -i wg+ -j ACCEPT',
    '/sbin/iptables -A FORWARD -i wg0 -j ACCEPT',
    'eval "$SCRIPT"',
    ': $(opaque)',
    '# comment; opaque',
    'iptables -t nat -A POSTROUTING -s 0.0.0.0/0 -o eth0 -j MASQUERADE',
  ])(
    'rejects unverifiable script %s before execution with a safe scoped error',
    (script) => {
      try {
        admitManagedServerHooks('wg0', fields(script));
        throw new Error('unexpected admission');
      } catch (error) {
        expect(error).toMatchObject({
          interfaceId: 'wg0',
          code: 'unsupported_script',
        });
        expect(String(error)).not.toContain(script);
      }
    }
  );

  test('requires inverse multisets, including multiplicity and startup/shutdown phases', () => {
    const hooks = fields();
    hooks.set('predown', hooks.get('postdown')!);
    hooks.set('postdown', '');
    hooks.set('preup', hooks.get('postup')!);
    hooks.set('postup', '');
    expect(
      resolveManagedServerHooks(admitManagedServerHooks('wg0', hooks))
    ).toEqual(rules());
    hooks.set('postup', up);
    expect(() => admitManagedServerHooks('wg0', hooks)).toThrow(
      'non_reversible_script'
    );
  });

  test('bounds script size, statement count and frozen recovery shapes', () => {
    expect(() =>
      admitManagedServerHooks('wg0', fields(': x;'.repeat(130)))
    ).toThrow('rule_budget_exceeded');
    expect(() =>
      admitManagedServerHooks('wg0', fields('x'.repeat(8193)))
    ).toThrow('unsupported_script');
    const manifest = [{ rule: rules()[0]!, base: 0, previous: 1, target: 1 }];
    for (const altered of [
      [...manifest, ...manifest],
      [{ ...manifest[0], command: 'opaque' }],
      [{ ...manifest[0], base: 2 }],
      [{ ...manifest[0], target: 5000 }],
      [
        {
          ...manifest[0],
          rule: { ...manifest[0]!.rule, args: ['-j', 'WG_ROUTE_GUARD'] },
        },
      ],
    ])
      expect(() => parseManagedHookCounts(altered)).toThrow(
        'invalid_recovery_manifest'
      );
    expect(parseManagedHookCounts(manifest)).toEqual(manifest);
    const intent = {
      interfaces: [
        { interfaceId: 'wg0', previousUp: true, targetUp: true, restart: true },
      ],
      hooks: manifest,
    };
    expect(parseManagedLifecycleIntent(intent)).toEqual(intent);
    expect(() =>
      parseManagedLifecycleIntent({
        ...intent,
        interfaces: [
          { ...intent.interfaces[0], targetUp: false, restart: false },
        ],
      })
    ).toThrow('invalid_lifecycle_manifest');
    expect(() =>
      parseManagedLifecycleIntent({
        ...intent,
        interfaces: [...intent.interfaces, ...intent.interfaces],
      })
    ).toThrow('invalid_lifecycle_manifest');
  });
});

describe('guarded reversible lifecycle effects', () => {
  test('restores all partial up/down effects after each failed write, preserving equal foreign rules', async () => {
    const old = rules(),
      target = rules(
        up.replaceAll('eth0', 'ens160').replaceAll('51820', '51821')
      );
    for (let boundary = 1; boundary <= 16; boundary++) {
      const fake = firewall(old, 2),
        baseline = [...fake.entries].sort(),
        effects = new ManagedServerHookEffects(fake.run),
        manifest = await effects.capture(old, target);
      let guards = 0;
      const verifyGuard = async () => {
        guards++;
      };
      fake.setFailure(boundary);
      try {
        await effects.reconcile(manifest, 'base', verifyGuard);
        await effects.reconcile(manifest, 'target', verifyGuard);
      } catch {
        /* A process may die immediately after the kernel commits. */
      }
      fake.setFailure(-1);
      const reopened = new ManagedServerHookEffects(fake.run);
      await reopened.reconcile(
        JSON.parse(JSON.stringify(manifest)),
        'previous',
        verifyGuard
      );
      await reopened.verify(manifest, 'previous');
      expect([...fake.entries].sort()).toEqual(baseline);
      expect(fake.entries).toContain(fake.foreign);
      const forward = fake.entries.filter((l) =>
        l.startsWith('4:filter -A FORWARD')
      );
      expect(forward.indexOf(ruleId(old[2]!))).toBeLessThan(
        forward.indexOf(fake.foreign)
      );
      expect(guards).toBeGreaterThan(0);
      const writes = fake.writes.length;
      await reopened.reconcile(manifest, 'previous', verifyGuard);
      expect(fake.writes).toHaveLength(writes);
    }
  });

  test('preserves the order of identical baseline rules around unrelated rules', async () => {
    const only = rules('iptables -A FORWARD -i wg0 -j ACCEPT;'),
      fake = firewall(only),
      first = ruleId(only[0]!);
    fake.entries.push(first);
    const effects = new ManagedServerHookEffects(fake.run),
      manifest = await effects.capture(only, []);
    await effects.reconcile(manifest, 'target', async () => {});
    expect(fake.entries).toEqual([first, fake.foreign]);
    await effects.reconcile(manifest, 'previous', async () => {});
    expect(fake.entries).toEqual([first, fake.foreign, first]);
  });

  test('checks every rule before repair and refuses unknown counts without any write', async () => {
    const old = rules(),
      fake = firewall(old),
      effects = new ManagedServerHookEffects(fake.run),
      manifest = await effects.capture(old, old);
    fake.entries.push(ruleId(old[old.length - 1]!));
    await expect(
      effects.reconcile(manifest, 'base', async () => {})
    ).rejects.toThrow('unknown_effects');
    expect(fake.writes).toHaveLength(0);
    const missing = firewall([]);
    await expect(
      new ManagedServerHookEffects(missing.run).capture(old, old)
    ).rejects.toThrow('previous_effects_unverified');
  });

  test('refuses a lost guard before a write and detects intervening rule changes', async () => {
    const old = rules(),
      fake = firewall(old),
      effects = new ManagedServerHookEffects(fake.run),
      manifest = await effects.capture(old, []);
    await expect(
      effects.reconcile(manifest, 'base', async () => {
        throw new Error('guard gone');
      })
    ).rejects.toThrow('guard gone');
    expect(fake.writes).toHaveLength(0);
    await expect(
      effects.reconcile(manifest, 'base', async () => {
        fake.entries.push(ruleId(manifest[0]!.rule));
      })
    ).rejects.toThrow('effects_changed');
    expect(fake.writes).toHaveLength(0);
  });

  test('does not leak command stderr or malformed route data', async () => {
    const secret = 'private command diagnostic',
      effects = new ManagedServerHookEffects(async () => {
        throw new Error(secret);
      });
    await expect(effects.defaultEgress()).rejects.toThrow(
      'default_egress_unavailable'
    );
    await expect(effects.capture(rules(), [])).rejects.not.toThrow(secret);
    for (const value of ['null', '{}', '[{"dev":"$(opaque)"}]', '[]']) {
      await expect(
        new ManagedServerHookEffects(async () => value).defaultEgress()
      ).rejects.toThrow('default_egress_unavailable');
    }
  });
});
