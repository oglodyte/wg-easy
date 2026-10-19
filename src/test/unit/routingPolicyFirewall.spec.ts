import { describe, expect, test } from 'vitest';

import {
  canonicalClientFirewallRule,
  validateClientFirewallPolicy,
} from '#server/utils/clientFirewallPolicy';
import type { execFile } from '#server/utils/cmd';
import {
  buildClientFirewallManifest,
  buildPolicyClientFirewall,
} from '#server/utils/firewall';
import {
  assertRoutingGuardState,
  buildRoutingGuard,
  routingGuardRestoreDocument,
} from '#server/utils/routingGuard';
import { RoutingPolicyFirewall } from '#server/utils/routingPolicyFirewall';
import type { PolicyClientFirewall } from '#shared/types/routingPolicy';

function fixture(): PolicyClientFirewall {
  return {
    enableIpv6: true,
    interfaces: [{ interfaceId: 'wg0', ipv6: true }],
    entries: [
      {
        interfaceId: 'wg0',
        clientId: 1,
        clientName: 'client 1: member',
        family: 4,
        source: '10.8.0.2',
        destination: '0.0.0.0/0',
      },
      {
        interfaceId: 'wg0',
        clientId: 1,
        clientName: 'client 1: member',
        family: 6,
        source: 'fd08::2',
        destination: '::/0',
        port: 443,
        proto: 'tcp',
      },
    ],
  };
}
const guard = buildRoutingGuard(
  [
    {
      direction: 'forward',
      inputInterface: 'wg0',
      source: '10.8.0.2/32',
      destination: '0.0.0.0/0',
    },
  ],
  { protectedPaths: [] }
);
const foreign = '-A FOREIGN -j RETURN';
function kernel(plan = fixture()) {
  const tables = new Map<4 | 6, { chains: string[]; rules: string[] }>();
  for (const family of [4, 6] as const) {
    const manifest = buildClientFirewallManifest(plan, family);
    tables.set(family, {
      chains: ['INPUT', 'FORWARD', 'OUTPUT', 'WG_CLIENTS', 'FOREIGN'],
      rules: [...manifest.body, ...manifest.jumps, foreign],
    });
  }
  const save = (family: 4 | 6) =>
    [
      '*filter',
      ...tables.get(family)!.chains.map((c) => `:${c} - [0:0]`),
      ...tables.get(family)!.rules,
      'COMMIT',
      '',
    ].join('\n');
  function apply(family: 4 | 6, document: string) {
    const table = tables.get(family)!;
    for (const line of document.split('\n')) {
      if (line.startsWith(':')) {
        const name = line.split(' ')[0]!.slice(1);
        if (!table.chains.includes(name)) table.chains.push(name);
      } else if (line.startsWith('-F '))
        table.rules = table.rules.filter(
          (r) => !r.startsWith(`-A ${line.slice(3)} `)
        );
      else if (line.startsWith('-D ')) {
        const index = table.rules.indexOf(line.replace(/^-D /, '-A '));
        expect(index).toBeGreaterThanOrEqual(0);
        table.rules.splice(index, 1);
      } else if (line.startsWith('-I '))
        table.rules.unshift(line.replace(/^-I (\S+) 1 /, '-A $1 '));
      else if (line.startsWith('-A ')) table.rules.push(line);
    }
  }
  const calls: { binary: string; args: readonly string[] }[] = [];
  let fail = '';
  const run: typeof execFile = async (binary, args = [], options = {}) => {
    calls.push({ binary, args });
    const family = binary.startsWith('ip6') ? 6 : 4;
    if (binary.endsWith('-save')) return save(family);
    if (fail === `${family}-${args.includes('--test') ? 'test' : 'write'}`)
      throw new Error('fixture failure');
    if (!args.includes('--test')) apply(family, options.input!);
    return '';
  };
  const empty =
    '*filter\n:INPUT - [0:0]\n:FORWARD - [0:0]\n:OUTPUT - [0:0]\nCOMMIT\n';
  apply(4, routingGuardRestoreDocument(empty, guard, null)!);
  return {
    run,
    save,
    apply,
    tables,
    calls,
    setFail: (value: string) => {
      fail = value;
    },
  };
}

describe('strict guarded client firewall recovery', () => {
  test('normalizes the existing effective-field precedence and retains only active semantic entries', () => {
    const states = [
      {
        wgInterface: {
          name: 'wg0',
          enabled: true,
          firewallEnabled: true,
          ipv6Cidr: 'fd08::/64',
        },
        observedUp: true,
        userConfig: { defaultAllowedIps: ['0.0.0.0/0'] },
        clients: [
          {
            id: 1,
            name: 'one " -s suspicious',
            enabled: true,
            ipv4Address: '10.8.0.2',
            ipv6Address: 'fd08::2',
            allowedIps: ['192.0.2.0/24'],
            firewallIps: ['198.51.100.0/24:443/tcp', '[2001:db8::/64]:53/udp'],
          },
        ],
      },
    ];
    const policy = buildPolicyClientFirewall(states, true);
    expect(policy.entries.map((e) => [e.destination, e.port, e.proto])).toEqual(
      [
        ['198.51.100.0/24', 443, 'tcp'],
        ['2001:db8::/64', 53, 'udp'],
      ]
    );
    expect(policy.entries[0]!.clientName).toBe('client 1: one  -s suspicious');
    states[0]!.clients[0]!.firewallIps = [];
    expect(
      buildPolicyClientFirewall(states, false).entries[0]!.destination
    ).toBe('192.0.2.0/24');
    states[0]!.observedUp = false;
    expect(buildPolicyClientFirewall(states, true).entries).toEqual([]);
  });
  test('kernel canonicalization treats quoted comments as opaque', () => {
    const before =
      '-A WG_CLIENTS -s 10.8.0.2 -d 0.0.0.0/0 -p tcp --dport 443 -m comment --comment "client 1: text -s anything -j WG_CLIENTS" -j ACCEPT';
    const after = before
      .replace('-s 10.8.0.2 -d 0.0.0.0/0', '-s 10.8.0.2/32')
      .replace('-p tcp', '-p tcp -m tcp');
    expect(canonicalClientFirewallRule(before)).toBe(
      canonicalClientFirewallRule(after)
    );
    expect(
      canonicalClientFirewallRule(before.replace('-p tcp', '-p tcp -m udp'))
    ).not.toBe(canonicalClientFirewallRule(after));
  });
  test('rejects invalid semantic entries and secret/command-shaped persisted fields with generic errors', () => {
    for (const patch of [
      { destination: '198.51.100.2; touch private' },
      { source: '0.0.0.0/0' },
      { port: 0, proto: 'tcp' },
      { proto: 'udp' },
      { clientName: 'unsafe " comment' },
      { interfaceId: 'missing0' },
      { privateKey: 'private-fixture' },
    ])
      expect(() =>
        validateClientFirewallPolicy({
          ...fixture(),
          entries: [{ ...fixture().entries[0], ...patch }],
        })
      ).toThrow('Client firewall policy is invalid');
  });
  test('preflights both families before writing either table', async () => {
    const k = kernel();
    const target = fixture();
    target.entries[0]!.destination = '198.51.100.0/24';
    k.setFail('6-test');
    await expect(
      new RoutingPolicyFirewall(k.run).apply(target, [fixture()], guard)
    ).rejects.toThrow('application_failed');
    expect(
      k.calls
        .filter((c) => c.binary.endsWith('-restore'))
        .map((c) => [c.binary, c.args])
    ).toEqual([
      ['iptables-restore', ['--test', '--noflush']],
      ['ip6tables-restore', ['--test', '--noflush']],
    ]);
    assertRoutingGuardState(k.save(4), guard);
  });
  test('atomically preserves the guard ahead of client accepts, keeps foreign state, and restores from recorded policy', async () => {
    const k = kernel(),
      previous = fixture(),
      target = fixture();
    target.entries[0]!.destination = '198.51.100.0/24';
    k.setFail('6-write');
    await expect(
      new RoutingPolicyFirewall(k.run).apply(target, [previous], guard)
    ).rejects.toThrow('application_failed');
    assertRoutingGuardState(k.save(4), guard);
    k.setFail('');
    await new RoutingPolicyFirewall(k.run).apply(previous, [target], guard);
    await new RoutingPolicyFirewall(k.run).verify(previous, guard);
    expect(k.save(4)).toContain(foreign);
    expect(k.save(6)).toContain(foreign);
    expect(k.save(4)).not.toContain('198.51.100.0/24');
  });
  test.each([
    'body',
    'foreign reference',
    'duplicate reference',
    'owner forgery',
  ])('unknown %s aborts before any filter test/write', async (kind) => {
    const k = kernel(),
      table = k.tables.get(4)!;
    if (kind === 'body') table.rules.push('-A WG_CLIENTS -j ACCEPT');
    else if (kind === 'foreign reference')
      table.rules.push('-A INPUT -j WG_CLIENTS');
    else if (kind === 'duplicate reference')
      table.rules.push(buildClientFirewallManifest(fixture(), 4).jumps[0]!);
    else
      table.rules = table.rules.filter(
        (r) => !r.startsWith('-A WG_CLIENTS -s ')
      );
    await expect(
      new RoutingPolicyFirewall(k.run).prepare(fixture(), [], guard)
    ).rejects.toThrow('ownership_unknown');
    expect(k.calls.some((c) => c.binary.endsWith('-restore'))).toBe(false);
  });
  test('an earlier foreign ACCEPT cannot masquerade as verified client filtering', async () => {
    const k = kernel();
    // Keep the guard first, but insert a bypass before the known client jump.
    const rules = k.tables.get(4)!.rules;
    rules.splice(
      rules.findIndex((r) => r.startsWith('-A FORWARD -i wg0')),
      0,
      '-A FORWARD -j ACCEPT'
    );
    await expect(
      new RoutingPolicyFirewall(k.run).verify(fixture(), guard)
    ).rejects.toThrow('filter_hook_unverified');
  });
  test('an unknown IPv6 guard is never exempted from filter hook ordering', async () => {
    const k = kernel();
    k.tables.get(6)!.chains.push('WG_ROUTE_GUARD');
    k.tables.get(6)!.rules.unshift('-A FORWARD -j WG_ROUTE_GUARD');
    await expect(
      new RoutingPolicyFirewall(k.run).verify(fixture(), guard)
    ).rejects.toThrow('filter_hook_unverified');
  });
});
