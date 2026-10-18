import { describe, expect, test } from 'vitest';

import {
  specializeRoutingPolicy,
  verifyRoutingPolicyPeerMap,
} from '#server/utils/routingPolicyRuntime';
import type { PolicySnapshot } from '#shared/types/routingPolicy';

function fixture(): PolicySnapshot {
  return {
    interfaces: [
      { interfaceId: 'wg0', ipv4Cidr: '10.8.0.0/24' },
      { interfaceId: 'awg1', ipv4Cidr: '10.9.0.0/24' },
    ],
    clients: [
      {
        id: 1,
        name: 'member',
        interfaceId: 'wg0',
        publicKey: 'member-public',
        ipv4Address: '10.8.0.2',
        ipv6Address: 'fd08::2',
        enabled: true,
        serverAllowedIps: [],
      },
      {
        id: 2,
        name: 'internet',
        interfaceId: 'awg1',
        publicKey: 'internet-public',
        ipv4Address: '10.9.0.2',
        ipv6Address: 'fd09::2',
        enabled: true,
        serverAllowedIps: [],
      },
      {
        id: 3,
        name: 'LAN',
        interfaceId: 'awg1',
        publicKey: 'lan-public',
        ipv4Address: '10.9.0.3',
        ipv6Address: 'fd09::3',
        enabled: true,
        serverAllowedIps: ['2001:db8:44::/64'],
      },
      {
        id: 4,
        name: 'disabled alternative',
        interfaceId: 'awg1',
        publicKey: 'lan-public',
        ipv4Address: '10.9.0.3',
        enabled: false,
        serverAllowedIps: [],
      },
    ],
    groups: [
      {
        id: 1,
        name: 'default',
        routingSlot: 1,
        enabled: true,
        natEnabled: true,
        allExitsDownPolicy: 'block',
        routedIpv4Prefixes: ['0.0.0.0/0'],
        excludedIpv4Prefixes: ['192.168.0.0/16'],
        memberClientIds: [1],
        exits: [{ clientId: 2, priority: 0, enabled: true }],
      },
      {
        id: 2,
        name: 'LAN',
        routingSlot: 2,
        enabled: true,
        natEnabled: false,
        allExitsDownPolicy: 'block',
        routedIpv4Prefixes: ['192.168.0.0/16'],
        memberClientIds: [1],
        exits: [{ clientId: 3, priority: 0, enabled: true }],
      },
    ],
  };
}
const enabledInterfaceIds = new Set(['wg0', 'awg1']);
function specialize(
  snapshot = fixture(),
  selectedExitClientIds = new Map<number, number | null>([
    [1, 2],
    [2, 3],
  ]),
  enableIpv6 = true
) {
  return specializeRoutingPolicy(snapshot, {
    selectedExitClientIds,
    enabledInterfaceIds,
    upInterfaceIds: enabledInterfaceIds,
    enableIpv6,
  });
}
function observed(state: ReturnType<typeof specialize>) {
  const snapshot = fixture();
  return state.plan.peers.map((peer) => ({
    interfaceId: peer.interfaceId,
    publicKey: snapshot.clients.find((c) => c.id === peer.clientId)!.publicKey,
    allowedIps: peer.prefixes,
  }));
}

describe('inactive complete runtime policy specialization', () => {
  test('uses one winner partition and complete enabled peer maps', () => {
    const result = specialize();
    expect(result.plan.peers.map((p) => p.clientId)).toEqual([1, 2, 3]);
    expect(result.plan.peers[0]!.prefixes).toEqual([
      '10.8.0.2/32',
      'fd08::2/128',
    ]);
    expect(result.plan.peers[2]!.prefixes).toEqual([
      '10.9.0.3/32',
      '192.168.0.0/16',
      '2001:db8:44::/64',
      'fd09::3/128',
    ]);
    expect(result.plan.groups[1]).toMatchObject({
      selectedExitClientId: 3,
      exitInterfaceId: 'awg1',
      serverIpv4Address: '10.9.0.1',
      effectivePrefixes: ['192.168.0.0/16'],
    });
    expect(
      result.plan.programs[0]!.branches.find((b) => b.groupId === 2)
    ).toEqual({ prefix: '192.168.0.0/16', groupId: 2, action: 'exit' });
    expect(() =>
      verifyRoutingPolicyPeerMap(result.plan, observed(result))
    ).not.toThrow();
  });
  test('all-down block/host stays terminal and never broadens default ownership', () => {
    for (const fallback of ['block', 'host'] as const) {
      const snapshot = fixture();
      snapshot.groups[1]!.allExitsDownPolicy = fallback;
      const result = specialize(
        snapshot,
        new Map([
          [1, 2],
          [2, null],
        ])
      );
      expect(
        result.plan.programs[0]!.branches.find((b) => b.groupId === 2)!.action
      ).toBe(fallback);
      expect(result.plan.peers[2]!.prefixes).not.toContain('192.168.0.0/16');
      expect(result.plan.groups[1]!.effectivePrefixes).toEqual([
        '192.168.0.0/16',
      ]);
      expect(result.plan.peers[1]!.prefixes).toEqual(
        specialize().plan.peers[1]!.prefixes
      );
    }
  });
  test('retains normalized legacy routes and IPv6 legacy declarations independently of own IPv6 export', () => {
    const result = specialize(
      fixture(),
      new Map([
        [1, 2],
        [2, 3],
      ]),
      false
    );
    expect(result.plan.peers[2]!.prefixes).toContain('2001:db8:44::/64');
    expect(result.plan.peers[2]!.prefixes).not.toContain('fd09::3/128');
    expect(result.plan.siteRoutes).toEqual([
      { interfaceId: 'awg1', prefixes: ['2001:db8:44::/64'] },
    ]);
    expect(JSON.stringify(result.plan)).not.toContain('lan-public');
  });
  test('rejects missing/stale/extra peers and stale more-specific prefixes', () => {
    const result = specialize(),
      actual = observed(result);
    expect(() =>
      verifyRoutingPolicyPeerMap(result.plan, actual.slice(1))
    ).toThrow('peer_missing');
    expect(() =>
      verifyRoutingPolicyPeerMap(result.plan, [
        ...actual,
        {
          interfaceId: 'awg1',
          publicKey: 'stale-public',
          allowedIps: ['192.0.2.0/24'],
        },
      ])
    ).toThrow('peer_map_mismatch');
    expect(() =>
      verifyRoutingPolicyPeerMap(
        result.plan,
        actual.map((p, i) =>
          i === 1
            ? { ...p, allowedIps: [...p.allowedIps, '192.168.8.0/24'] }
            : p
        )
      )
    ).toThrow('peer_map_mismatch');
    expect(() =>
      verifyRoutingPolicyPeerMap(result.plan, [...actual, actual[0]!])
    ).toThrow('duplicate_observed_peer');
    expect(() =>
      verifyRoutingPolicyPeerMap(result.plan, [
        ...actual,
        {
          interfaceId: 'foreign0',
          publicKey: 'foreign',
          allowedIps: ['0.0.0.0/0'],
        },
      ])
    ).not.toThrow();
  });
  test('key replacement changes runtime identity while retaining stable profile references', () => {
    const before = specialize(),
      snapshot = fixture();
    snapshot.clients[2]!.publicKey = 'replacement-public';
    const after = specialize(snapshot);
    expect(after.plan.peers[2]!.clientId).toBe(before.plan.peers[2]!.clientId);
    expect(after.plan.peers[2]!.peerId).not.toBe(before.plan.peers[2]!.peerId);
    expect(after.fingerprint).not.toBe(before.fingerprint);
    expect(() =>
      verifyRoutingPolicyPeerMap(after.plan, observed(before))
    ).toThrow('peer_map_mismatch');
  });
  test('rejects a selected exit absent from its enabled candidate rows or available interface', () => {
    expect(() => specialize(fixture(), new Map([[999, 2]]))).toThrow(
      'selection_group_unavailable'
    );
    expect(() =>
      specialize(
        fixture(),
        new Map([
          [1, 3],
          [2, 3],
        ])
      )
    ).toThrow('selected_exit_unavailable');
    expect(() =>
      specializeRoutingPolicy(fixture(), {
        selectedExitClientIds: new Map([
          [1, 2],
          [2, 3],
        ]),
        enabledInterfaceIds,
        upInterfaceIds: new Set(['wg0']),
        enableIpv6: true,
      })
    ).toThrow('selected_exit_unavailable');
  });
  test('is deterministic across row ordering and changes identity for policy/NAT edits', () => {
    const snapshot = fixture();
    snapshot.clients = [...snapshot.clients].reverse();
    snapshot.interfaces = [...snapshot.interfaces].reverse();
    snapshot.groups = [...snapshot.groups].reverse();
    expect(specialize(snapshot).fingerprint).toBe(specialize().fingerprint);
    snapshot.groups[0]!.natEnabled = true;
    expect(specialize(snapshot).fingerprint).not.toBe(specialize().fingerprint);
  });
});
