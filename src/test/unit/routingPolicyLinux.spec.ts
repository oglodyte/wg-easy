import { parseCidr } from 'cidr-tools';
import { describe, expect, test } from 'vitest';

import {
  FWMARK_MASK,
  routingMarkForSlot,
  SITE_TO_SITE_TABLE_ID,
} from '#server/utils/routing';
import { RoutingExecutor } from '#server/utils/routingExecutor';
import { renderRoutingPolicyLinux } from '#server/utils/routingPolicyLinux';
import { specializeRoutingPolicy } from '#server/utils/routingPolicyRuntime';
import type { PolicySnapshot } from '#shared/types/routingPolicy';

function fixture(): PolicySnapshot {
  return {
    interfaces: [
      { interfaceId: 'wg0', ipv4Cidr: '10.8.0.0/24' },
      { interfaceId: 'awg1', ipv4Cidr: '10.9.0.0/24' },
      { interfaceId: 'awg2', ipv4Cidr: '10.10.0.0/24' },
    ],
    clients: [
      { id: 1, interfaceId: 'wg0', ipv4Address: '10.8.0.2' },
      { id: 4, interfaceId: 'wg0', ipv4Address: '10.8.0.3' },
      { id: 2, interfaceId: 'awg1', ipv4Address: '10.9.0.2' },
      { id: 3, interfaceId: 'awg2', ipv4Address: '10.10.0.2' },
      { id: 5, interfaceId: 'awg1', ipv4Address: '10.9.0.3' },
    ].map((c) => ({
      ...c,
      name: `profile ${c.id}`,
      publicKey: `public ${c.id}`,
      enabled: true,
      serverAllowedIps: [],
    })),
    groups: [
      {
        id: 1,
        name: 'Internet',
        routingSlot: 1,
        enabled: true,
        natEnabled: true,
        allExitsDownPolicy: 'block',
        routedIpv4Prefixes: ['0.0.0.0/0'],
        memberClientIds: [1, 4],
        exits: [{ clientId: 2, priority: 0, enabled: true }],
      },
      {
        id: 2,
        name: 'LAN',
        routingSlot: 2,
        enabled: true,
        natEnabled: false,
        allExitsDownPolicy: 'block',
        routedIpv4Prefixes: ['10.20.0.0/16'],
        memberClientIds: [1, 4],
        exits: [
          { clientId: 3, priority: 0, enabled: true },
          { clientId: 5, priority: 1, enabled: true },
        ],
      },
    ],
  };
}
function specialize(snapshot: PolicySnapshot, lanExit: number | null = 3) {
  return specializeRoutingPolicy(snapshot, {
    selectedExitClientIds: new Map([
      [1, 2],
      [2, lanExit],
    ]),
    enabledInterfaceIds: new Set(['wg0', 'awg1', 'awg2']),
    upInterfaceIds: new Set(['wg0', 'awg1', 'awg2']),
    enableIpv6: true,
    clientFirewall: { enableIpv6: true, interfaces: [], entries: [] },
  }).plan;
}
function contains(prefix: string, ip: string) {
  const network = parseCidr(prefix),
    address = parseCidr(`${ip}/32`).start;
  return network.start <= address && address <= network.end;
}
/** Small instruction interpreter independent of the compiler/winner helpers. */
function classify(
  linux: ReturnType<typeof renderRoutingPolicyLinux>,
  source = '10.8.0.2',
  destination = '10.20.1.3',
  inputInterface = 'wg0',
  initialMark = 0xa0551234
) {
  let mark = initialMark >>> 0;
  function run(rules: string[][]) {
    for (const rule of rules) {
      const value = (flag: string) => {
        const index = rule.indexOf(flag);
        return index < 0 ? undefined : rule[index + 1];
      };
      if (value('-i') && value('-i') !== inputInterface) continue;
      if (value('-s') && !contains(value('-s')!, source)) continue;
      if (value('-d') && !contains(value('-d')!, destination)) continue;
      const target = value('--goto');
      if (target) {
        run(linux.classifier!.children.find((c) => c.name === target)!.rules);
        return;
      }
      if (value('-j') === 'RETURN') return;
      if (value('-j') === 'MARK') {
        const [bits, mask] = value('--set-xmark')!.split('/').map(Number);
        mark = ((mark & ~mask!) ^ bits!) >>> 0;
      }
    }
  }
  run(linux.markChainRules);
  return mark;
}

describe('inactive shared Linux policy rendering', () => {
  test('uses one shared terminal program for two sources, effective routes and per-group NAT', () => {
    const plan = specialize(fixture()),
      linux = renderRoutingPolicyLinux(plan);
    expect(linux.classifier!.children).toHaveLength(1);
    expect(
      linux.markChainRules.filter((r) => r.includes('--goto'))
    ).toHaveLength(2);
    expect(classify(linux)).toBe((routingMarkForSlot(2) | 0x1234) >>> 0);
    expect(classify(linux, '10.8.0.3', '8.8.8.8')).toBe(
      (routingMarkForSlot(1) | 0x1234) >>> 0
    );
    expect(linux.routes).toContainEqual(
      expect.objectContaining({
        table: 52002,
        prefix: '10.20.0.0/16',
        device: 'awg2',
      })
    );
    expect(linux.natChainRules).toHaveLength(1);
    expect(linux.natChainRules[0]).toContain('10.9.0.1');
    expect(linux.peerAllowedIps).toEqual(
      plan.peers.map((p) => ({ clientId: p.clientId, prefixes: p.prefixes }))
    );
    for (const iface of plan.interfaces)
      expect(classify(linux, '10.8.0.2', iface.ipv4Cidr.split('/')[0]!)).toBe(
        0x1234
      );
    expect(classify(linux, '10.8.0.77')).toBe(0x1234);
    expect(classify(linux, '10.8.0.2', '10.20.1.3', 'awg1')).toBe(0x1234);
    expect(linux.parentMarkJumps.map((j) => j.interfaceId)).toEqual([
      'awg1',
      'awg2',
      'wg0',
    ]);
  });
  test('all-down block and host remain terminal despite a healthy internet policy', () => {
    const snapshot = fixture();
    const block = renderRoutingPolicyLinux(specialize(snapshot, null));
    expect(classify(block) & FWMARK_MASK).toBe(routingMarkForSlot(2));
    expect(block.routes).toContainEqual(
      expect.objectContaining({
        prefix: '10.20.0.0/16',
        table: 52002,
        type: 'unreachable',
      })
    );
    snapshot.groups = snapshot.groups.map((g) =>
      g.id === 2 ? { ...g, allExitsDownPolicy: 'host' } : g
    );
    const host = renderRoutingPolicyLinux(specialize(snapshot, null));
    expect(classify(host)).toBe(0x1234);
    expect(host.policyRules.some((r) => r.table === 52002)).toBe(false);
    expect(classify(host, '10.8.0.2', '8.8.8.8') & FWMARK_MASK).toBe(
      routingMarkForSlot(1)
    );
  });
  test('same-output-interface backup keeps independent effective ownership and NAT', () => {
    const linux = renderRoutingPolicyLinux(specialize(fixture(), 5));
    expect(
      linux.routes
        .filter((r) => r.table === 52002)
        .every((r) => r.device === 'awg1')
    ).toBe(true);
    expect(classify(linux) & FWMARK_MASK).toBe(routingMarkForSlot(2));
    expect(classify(linux, '10.8.0.3', '8.8.4.4') & FWMARK_MASK).toBe(
      routingMarkForSlot(1)
    );
    expect(linux.classifier!.children).toHaveLength(1);
  });
  test('preserves unmarked legacy IPv4 and IPv6 routes plus deterministic child identities', () => {
    const snapshot = fixture();
    snapshot.groups = snapshot.groups.map((g) =>
      g.id === 1 ? { ...g, excludedIpv4Prefixes: ['192.168.0.0/16'] } : g
    );
    snapshot.clients = snapshot.clients.map((c) =>
      c.id === 3
        ? { ...c, serverAllowedIps: ['192.168.0.0/16', 'fd99::/64'] }
        : c
    );
    const plan = specialize(snapshot),
      linux = renderRoutingPolicyLinux(plan);
    expect(classify(linux, '10.8.0.2', '192.168.1.1')).toBe(0x1234);
    expect(
      linux.routes
        .filter((r) => r.table === SITE_TO_SITE_TABLE_ID)
        .map((r) => [r.family, r.prefix, r.device])
    ).toEqual([
      [4, '192.168.0.0/16', 'awg2'],
      [6, 'fd99::/64', 'awg2'],
    ]);
    expect(
      linux.policyRules.filter((r) => r.table === SITE_TO_SITE_TABLE_ID)
    ).toHaveLength(2);
    expect(renderRoutingPolicyLinux(structuredClone(plan))).toEqual(linux);
    const child = linux.classifier!.children[0]!;
    expect(child.name).toBe(`WG_RP_${child.fingerprint.slice(0, 16)}`);
    expect(child.rules[0]!.join(' ')).toContain(child.fingerprint);
  });
  test('refuses to hand a child program to the existing executor before guarded integration', async () => {
    const linux = renderRoutingPolicyLinux(specialize(fixture()));
    let calls = 0;
    const executor = new RoutingExecutor(async () => {
      calls++;
      return '';
    });
    await expect(executor.apply(linux)).rejects.toThrow(
      'execution is unavailable'
    );
    expect(calls).toBe(0);
  });
});
