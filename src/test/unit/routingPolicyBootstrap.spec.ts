import { describe, expect, test } from 'vitest';

import { buildRoutingPlan } from '#server/utils/routing';
import { buildPolicyBootstrapBaseline } from '#server/utils/routingPolicyBootstrap';
import { parsePolicyBootstrapBaseline } from '#server/utils/routingPolicyJournal';
import { specializeRoutingPolicy } from '#server/utils/routingPolicyRuntime';
import { buildRoutingPolicyTransition } from '#server/utils/routingPolicyTransition';
import type { PolicySnapshot } from '#shared/types/routingPolicy';

function fixture() {
  const snapshot: PolicySnapshot = {
    interfaces: [
      { interfaceId: 'wg0', ipv4Cidr: '10.8.0.0/24' },
      { interfaceId: 'awg1', ipv4Cidr: '10.9.0.0/24' },
    ],
    clients: [
      {
        id: 1,
        name: 'member',
        interfaceId: 'wg0',
        ipv4Address: '10.8.0.2',
        ipv6Address: 'fd08::2',
        enabled: true,
        publicKey: 'member',
        serverAllowedIps: [],
      },
      {
        id: 2,
        name: 'exit',
        interfaceId: 'awg1',
        ipv4Address: '10.9.0.2',
        ipv6Address: 'fd09::2',
        enabled: true,
        publicKey: 'exit',
        serverAllowedIps: ['2001:db8:210::/64'],
      },
      {
        id: 3,
        name: 'disabled alternate',
        interfaceId: 'awg1',
        ipv4Address: '10.9.0.2',
        ipv6Address: 'fd09::2',
        enabled: false,
        publicKey: 'exit',
        serverAllowedIps: [],
      },
    ],
    groups: [
      {
        id: 1,
        name: 'default',
        enabled: true,
        routingSlot: 1,
        natEnabled: true,
        allExitsDownPolicy: 'block',
        routedIpv4Prefixes: ['0.0.0.0/0'],
        memberClientIds: [1],
        exits: [{ clientId: 2, priority: 0, enabled: true }],
      },
    ],
  };
  const { plan, fingerprint } = specializeRoutingPolicy(snapshot, {
    selectedExitClientIds: new Map([[1, 2]]),
    enabledInterfaceIds: new Set(['wg0', 'awg1']),
    upInterfaceIds: new Set(['wg0', 'awg1']),
    enableIpv6: true,
    clientFirewall: { enableIpv6: true, interfaces: [], entries: [] },
  });
  const target = { revision: 7, fingerprint, plan };
  return { snapshot, target };
}

describe('one-generation version 1 activation baseline', () => {
  test('retains the actual broad legacy peer claim instead of fabricating effective v2 claims', () => {
    const { snapshot, target } = fixture();
    const baseline = buildPolicyBootstrapBaseline(snapshot, target);
    expect(baseline.peers.find((p) => p.clientId === 2)?.prefixes).toContain(
      '0.0.0.0/0'
    );
    expect(
      target.plan.peers.find((p) => p.clientId === 2)?.prefixes
    ).not.toContain('0.0.0.0/0');
    expect(baseline.peers.map((p) => p.clientId)).toEqual([1, 2]);
    expect(baseline.clients.find((c) => c.id === 3)?.enabled).toBe(false);
    expect(baseline.peers.find((p) => p.clientId === 2)?.prefixes).toContain(
      '2001:db8:210::/64'
    );
    expect(
      parsePolicyBootstrapBaseline(JSON.parse(JSON.stringify(baseline)), target)
    ).toEqual(baseline);
    const legacy = buildRoutingPlan(baseline);
    expect(legacy.classifier).toBeUndefined();
    expect(legacy.peerAllowedIps).toEqual([
      { clientId: 2, prefixes: ['0.0.0.0/0'] },
    ]);
    const closure = buildRoutingPolicyTransition(
      { ...target.plan, peers: baseline.peers },
      target.plan,
      { protectedPaths: [] }
    );
    expect(closure.scopes.some((s) => s.outputInterface === 'awg1')).toBe(true);
    expect(closure.scopes.some((s) => s.inputInterface === 'wg0')).toBe(false);
    expect(JSON.stringify(baseline)).not.toMatch(
      /privateKey|presharedKey|publicKey|command|executable/
    );
  });

  test('refuses advanced memberships or exclusions as a legacy baseline', () => {
    const { snapshot, target } = fixture();
    const excluded = structuredClone(snapshot);
    excluded.groups[0] = {
      ...excluded.groups[0]!,
      excludedIpv4Prefixes: ['192.168.0.0/16'],
    };
    expect(() => buildPolicyBootstrapBaseline(excluded, target)).toThrow(
      'invalid_bootstrap_baseline'
    );
    const multiple = structuredClone(snapshot);
    multiple.groups = [
      ...multiple.groups,
      { ...multiple.groups[0]!, id: 2, routingSlot: 2, enabled: false },
    ];
    expect(() => buildPolicyBootstrapBaseline(multiple, target)).toThrow(
      'invalid_bootstrap_baseline'
    );
  });

  test('rejects substituted legacy identities, peer claims or changed generations', () => {
    const { snapshot, target } = fixture();
    const baseline = buildPolicyBootstrapBaseline(snapshot, target);
    const changed = structuredClone(baseline);
    changed.peers[1]!.peerId = 'f'.repeat(64);
    expect(() => parsePolicyBootstrapBaseline(changed, target)).toThrow(
      'invalid_bootstrap_baseline'
    );
    changed.peers = target.plan.peers;
    expect(() => parsePolicyBootstrapBaseline(changed, target)).toThrow(
      'invalid_bootstrap_baseline'
    );
    const next = structuredClone(baseline);
    next.groups[0]!.natEnabled = false;
    expect(() => parsePolicyBootstrapBaseline(next, target)).toThrow(
      'invalid_bootstrap_baseline'
    );
  });
});
