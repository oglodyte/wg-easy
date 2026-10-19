import { parseCidr } from 'cidr-tools';
import { describe, expect, test } from 'vitest';

import { buildRoutingPolicyTransition } from '#server/utils/routingPolicyTransition';
import type { AppliedRoutingPolicyPlan } from '#shared/types/routingPolicy';

function fixture(): AppliedRoutingPolicyPlan {
  return {
    version: 2,
    clientFirewall: { enableIpv6: false, interfaces: [], entries: [] },
    interfaces: [
      {
        interfaceId: 'wg0',
        ipv4Cidr: '10.8.0.0/24',
        enabled: true,
        observedUp: true,
      },
      {
        interfaceId: 'awg1',
        ipv4Cidr: '10.9.0.0/24',
        enabled: true,
        observedUp: true,
      },
      {
        interfaceId: 'awg2',
        ipv4Cidr: '10.10.0.0/24',
        enabled: true,
        observedUp: true,
      },
    ],
    siteRoutes: [],
    bypassPrefixes: ['10.8.0.0/24', '10.9.0.0/24', '10.10.0.0/24'],
    programs: [
      {
        sources: [{ clientId: 1, interfaceId: 'wg0', ipv4Address: '10.8.0.2' }],
        branches: [
          { prefix: '203.0.113.0/24', groupId: 1, action: 'exit' },
          { prefix: '192.168.0.0/16', groupId: 2, action: 'exit' },
        ],
      },
    ],
    groups: [
      {
        id: 1,
        routingSlot: 1,
        enabled: true,
        natEnabled: true,
        allExitsDownPolicy: 'block',
        selectedExitClientId: 4,
        exitInterfaceId: 'awg2',
        serverIpv4Address: '10.10.0.1',
        effectivePrefixes: ['203.0.113.0/24'],
      },
      {
        id: 2,
        routingSlot: 2,
        enabled: true,
        natEnabled: true,
        allExitsDownPolicy: 'block',
        selectedExitClientId: 2,
        exitInterfaceId: 'awg1',
        serverIpv4Address: '10.9.0.1',
        effectivePrefixes: ['192.168.0.0/16'],
      },
    ],
    peers: [
      {
        clientId: 1,
        interfaceId: 'wg0',
        peerId: 'member',
        prefixes: ['10.8.0.2/32'],
      },
      {
        clientId: 2,
        interfaceId: 'awg1',
        peerId: 'lan-primary',
        prefixes: ['10.9.0.2/32', '192.168.0.0/16'],
      },
      {
        clientId: 3,
        interfaceId: 'awg1',
        peerId: 'lan-backup',
        prefixes: ['10.9.0.3/32'],
      },
      {
        clientId: 4,
        interfaceId: 'awg2',
        peerId: 'internet',
        prefixes: ['10.10.0.2/32', '203.0.113.0/24'],
      },
    ],
  };
}
const options = { protectedPaths: [] };
function contains(prefix: string, address: string) {
  const p = parseCidr(prefix),
    a = parseCidr(`${address}/32`);
  return p.start <= a.start && a.end <= p.end;
}

describe('inactive whole-policy transition closure', () => {
  test('credential-only replacement guards IPv6 identity paths while leaving another same-interface peer alone', () => {
    const plan = fixture();
    plan.peers[0]!.prefixes.push('fd08::2/128');
    plan.peers.push({
      clientId: 5,
      interfaceId: 'wg0',
      peerId: 'unrelated',
      prefixes: ['10.8.0.3/32', 'fd08::3/128'],
    });
    const guard = buildRoutingPolicyTransition(plan, plan, {
      ...options,
      forcePeerIds: new Set(['member']),
    });
    expect(
      guard.scopes.filter(
        (s) => s.source.includes(':') || s.destination.includes(':')
      )
    ).toHaveLength(4);
    expect(guard.scopes).toContainEqual({
      direction: 'input',
      inputInterface: 'wg0',
      source: 'fd08::2/128',
      destination: '::/0',
    });
    expect(
      guard.scopes.some(
        (s) => s.source === 'fd08::3/128' || s.destination === 'fd08::3/128'
      )
    ).toBe(false);
  });
  test('IPv6 LPM closure preserves unchanged more-specific peers and unsigned high addresses', () => {
    const before = fixture(),
      after = fixture();
    before.peers[1]!.prefixes.push('8000::/1');
    after.peers[2]!.prefixes.push('8000::/1');
    for (const plan of [before, after])
      plan.peers.push({
        clientId: 5,
        interfaceId: 'awg1',
        peerId: 'unrelated6',
        prefixes: ['8000:1234::/32'],
      });
    const guard = buildRoutingPolicyTransition(before, after, options);
    const outbound = guard.scopes.filter(
      (s) => s.direction === 'output' && s.destination.includes(':')
    );
    const covered = (ip: string) =>
      outbound.some((s) => {
        const p = parseCidr(s.destination),
          a = parseCidr(ip);
        return p.start <= a.start && p.end >= a.end;
      });
    expect(covered('8000:1234::1')).toBe(false);
    expect(covered('8000:1235::1')).toBe(true);
    expect(covered('ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')).toBe(true);
    expect(covered('7fff:ffff::1')).toBe(false);
  });
  test('IPv6 legacy route withdrawal has prefix-only local and forwarded protection even if peers do not change', () => {
    const before = fixture(),
      after = fixture();
    before.siteRoutes = [
      { interfaceId: 'awg1', prefixes: ['2001:db8:44::/64'] },
    ];
    const guard = buildRoutingPolicyTransition(before, after, options);
    expect(guard.scopes).toHaveLength(4);
    expect(guard.scopes).toContainEqual({
      direction: 'output',
      source: '::/0',
      destination: '2001:db8:44::/64',
    });
    expect(guard.scopes).toContainEqual({
      direction: 'input',
      source: '2001:db8:44::/64',
      destination: '::/0',
    });
  });
  test('does nothing for identical state without credential impacts', () => {
    const plan = fixture();
    expect(buildRoutingPolicyTransition(plan, plan, options).scopes).toEqual(
      []
    );
  });
  test('NAT-only edits protect member traffic and both tracked/unmatched returns', () => {
    const before = fixture(),
      after = fixture();
    after.groups[1]!.natEnabled = false;
    const guard = buildRoutingPolicyTransition(before, after, options);
    expect(guard.scopes).toContainEqual({
      direction: 'forward',
      inputInterface: 'wg0',
      source: '10.8.0.2/32',
      destination: '192.168.0.0/16',
    });
    expect(guard.scopes).toContainEqual({
      direction: 'forward',
      outputInterface: 'wg0',
      source: '192.168.0.0/16',
      destination: '10.8.0.2/32',
    });
    expect(guard.scopes).toContainEqual({
      direction: 'input',
      inputInterface: 'awg1',
      source: '192.168.0.0/16',
      destination: '10.9.0.1/32',
    });
    expect(
      guard.scopes.some(
        (s) => s.inputInterface === 'awg2' || s.outputInterface === 'awg2'
      )
    ).toBe(false);
    expect(
      guard.scopes.some(
        (s) =>
          s.destination === '203.0.113.0/24' || s.source === '203.0.113.0/24'
      )
    ).toBe(false);
  });
  test('effective client-filter edits guard only that peer on a shared interface', () => {
    const before = fixture(),
      after = fixture();
    for (const plan of [before, after]) {
      plan.peers.push({
        clientId: 5,
        interfaceId: 'wg0',
        peerId: 'unrelated-member',
        prefixes: ['10.8.0.3/32'],
      });
      plan.clientFirewall = {
        enableIpv6: false,
        interfaces: [{ interfaceId: 'wg0', ipv6: false }],
        entries: [
          {
            interfaceId: 'wg0',
            clientId: 1,
            clientName: 'client 1: member',
            family: 4,
            source: '10.8.0.2',
            destination: '0.0.0.0/0',
          },
        ],
      };
    }
    after.clientFirewall.entries[0]!.destination = '198.51.100.0/24';
    const guard = buildRoutingPolicyTransition(before, after, options);
    expect(guard.scopes).toContainEqual({
      direction: 'forward',
      inputInterface: 'wg0',
      source: '10.8.0.2/32',
      destination: '0.0.0.0/0',
    });
    expect(
      guard.scopes.some(
        (s) =>
          s.inputInterface === 'awg1' ||
          s.outputInterface === 'awg1' ||
          s.inputInterface === 'awg2' ||
          s.outputInterface === 'awg2'
      )
    ).toBe(false);
    expect(
      guard.scopes.some(
        (s) => s.source === '10.8.0.3/32' || s.destination === '10.8.0.3/32'
      )
    ).toBe(false);
  });
  test('peer ownership moves include local/unmarked paths and leave healthy internet alone', () => {
    const before = fixture(),
      after = fixture();
    after.groups[1]!.selectedExitClientId = 3;
    after.peers[1]!.prefixes = ['10.9.0.2/32'];
    after.peers[2]!.prefixes.push('192.168.0.0/16');
    const guard = buildRoutingPolicyTransition(before, after, options);
    expect(guard.scopes).toContainEqual({
      direction: 'output',
      outputInterface: 'awg1',
      source: '0.0.0.0/0',
      destination: '192.168.0.0/16',
    });
    expect(guard.scopes).toContainEqual({
      direction: 'input',
      inputInterface: 'awg1',
      source: '192.168.0.0/16',
      destination: '0.0.0.0/0',
    });
    expect(
      guard.scopes.some(
        (s) => s.inputInterface === 'awg2' || s.outputInterface === 'awg2'
      )
    ).toBe(false);
  });
  test('credential-only replacement forces protection from historical peer identity', () => {
    const before = fixture(),
      after = fixture();
    const guard = buildRoutingPolicyTransition(before, after, {
      ...options,
      forcePeerIds: new Set(['lan-primary']),
    });
    expect(
      guard.scopes.some(
        (s) => s.direction === 'output' && s.destination === '192.168.0.0/16'
      )
    ).toBe(true);
    expect(
      guard.scopes.some(
        (s) => s.direction === 'input' && s.source === '10.9.0.2/32'
      )
    ).toBe(true);
    after.peers = after.peers.filter((p) => p.clientId !== 2);
    expect(
      buildRoutingPolicyTransition(before, after, options).scopes.some(
        (s) => s.inputInterface === 'awg1' && contains(s.source, '192.168.1.1')
      )
    ).toBe(true);
  });
  test('prefix rewrites guard the touched peer while excluding an unchanged more-specific owner', () => {
    const before = fixture(),
      after = fixture();
    before.programs = [];
    after.programs = [];
    before.peers[1]!.prefixes = ['0.0.0.0/0'];
    after.peers[1]!.prefixes = ['0.0.0.0/1', '128.0.0.0/1'];
    const guard = buildRoutingPolicyTransition(before, after, options);
    const outward = guard.scopes.filter(
      (s) => s.direction === 'output' && s.outputInterface === 'awg1'
    );
    expect(
      outward.some((s) => contains(s.destination, '255.255.255.255'))
    ).toBe(true);
    expect(outward.some((s) => contains(s.destination, '10.9.0.3'))).toBe(
      false
    );
  });
  test('guards legacy route withdrawal even when selected group ownership keeps the peer map unchanged', () => {
    const before = fixture(),
      after = fixture();
    before.siteRoutes = [{ interfaceId: 'awg1', prefixes: ['192.168.0.0/16'] }];
    const guard = buildRoutingPolicyTransition(before, after, options);
    expect(guard.scopes).toContainEqual({
      direction: 'output',
      source: '0.0.0.0/0',
      destination: '192.168.0.0/16',
    });
    expect(guard.scopes).toContainEqual({
      direction: 'input',
      source: '192.168.0.0/16',
      destination: '0.0.0.0/0',
    });
    expect(() =>
      buildRoutingPolicyTransition(before, after, {
        protectedPaths: [
          {
            direction: 'output',
            outputInterface: 'eth0',
            source: '192.0.2.1/32',
            destination: '192.168.1.1/32',
          },
        ],
      })
    ).toThrow('management_collision');
  });
  test('refuses a closure that intersects the actual protected management path', () => {
    const before = fixture(),
      after = fixture();
    after.groups[1]!.natEnabled = false;
    expect(() =>
      buildRoutingPolicyTransition(before, after, {
        protectedPaths: [
          {
            direction: 'forward',
            inputInterface: 'wg0',
            source: '10.8.0.2/32',
            destination: '192.168.1.1/32',
          },
        ],
      })
    ).toThrow('management_collision');
  });
});
