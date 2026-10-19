import { describe, expect, test } from 'vitest';

import type { RoutingPlan } from '#server/utils/routing';
import { routingExecutorTestExports } from '#server/utils/routingExecutor';
import { renderRoutingPolicyLinux } from '#server/utils/routingPolicyLinux';
import {
  assertRoutingPolicyChains,
  canonicalRoutingRule,
} from '#server/utils/routingPolicyOwnership';
import type { AppliedRoutingPolicyPlan } from '#shared/types/routingPolicy';

function plan(action: 'host' | 'block' = 'block') {
  const value: AppliedRoutingPolicyPlan = {
    version: 2,
    clientFirewall: { enableIpv6: false, interfaces: [], entries: [] },
    interfaces: [
      {
        interfaceId: 'wg0',
        ipv4Cidr: '10.8.0.0/24',
        enabled: true,
        observedUp: true,
      },
    ],
    bypassPrefixes: ['10.8.0.0/24'],
    siteRoutes: [],
    peers: [
      {
        clientId: 1,
        interfaceId: 'wg0',
        peerId: 'a'.repeat(64),
        prefixes: ['10.8.0.2/32'],
      },
    ],
    groups: [
      {
        id: 7,
        routingSlot: 7,
        enabled: true,
        natEnabled: true,
        allExitsDownPolicy: action,
        selectedExitClientId: null,
        exitInterfaceId: null,
        serverIpv4Address: null,
        effectivePrefixes: ['192.168.0.0/16'],
      },
    ],
    programs: [
      {
        sources: [{ clientId: 1, interfaceId: 'wg0', ipv4Address: '10.8.0.2' }],
        branches: [{ prefix: '192.168.0.0/16', groupId: 7, action }],
      },
    ],
  };
  return renderRoutingPolicyLinux(value);
}
function saved(p: RoutingPlan) {
  function table(name: 'mangle' | 'nat') {
    return routingExecutorTestExports
      .renderRestoreDocument({
        table: name,
        chain: name === 'mangle' ? 'WG_ROUTE_MARK' : 'WG_ROUTE_NAT',
        rules: name === 'mangle' ? p.markChainRules : p.natChainRules,
        jumps:
          name === 'mangle'
            ? p.parentMarkJumps.map((j) => j.args)
            : p.parentNatJump
              ? [p.parentNatJump]
              : [],
        children: name === 'mangle' ? p.classifier?.children : [],
        observed: { policyRules: [], routes: [], chains: [], markUses: [] },
      })
      .split('\n')
      .filter(
        (l) => l.startsWith(':') || l.startsWith('-A ') || l.startsWith('-I ')
      )
      .map((l) => canonicalRoutingRule(l.replace(/^-I (\S+) 1 /, '-A $1 ')))
      .join('\n');
  }
  return { mangle: table('mangle'), nat: table('nat') };
}

describe('strict routing classifier ownership manifests', () => {
  test('accepts complete known manifests and kernel canonical mark/goto spelling', () => {
    const p = plan(),
      tables = saved(p);
    expect(tables.mangle).toContain('--set-xmark 0x0/0xffff0000');
    expect(tables.mangle).toContain(' -g WG_RP_');
    expect(() =>
      assertRoutingPolicyChains(tables, [p], { final: true })
    ).not.toThrow();
    expect(() =>
      assertRoutingPolicyChains({ mangle: '', nat: '' }, [p])
    ).not.toThrow();
    expect(() =>
      assertRoutingPolicyChains({ mangle: '', nat: '' }, [p], { final: true })
    ).toThrow('ownership is unknown');
  });
  test('rejects unknown bodies, duplicates, missing owner and prefix collisions without echoing rules', () => {
    const p = plan(),
      tables = saved(p),
      child = p.classifier!.children[0]!.name;
    for (const mangle of [
      `${tables.mangle}\n-A ${child} -j ACCEPT`,
      `${tables.mangle}\n${tables.mangle.split('\n').find((l) => l.startsWith(`-A ${child} `))}`,
      tables.mangle.replace(
        / -m comment --comment "wg-easy common routing owner"/,
        ''
      ),
      `${tables.mangle}\n:WG_RP_foreign - [0:0]\n-A WG_RP_foreign -m comment --comment "sensitive test input" -j ACCEPT`,
    ])
      expect(() =>
        assertRoutingPolicyChains({ ...tables, mangle }, [p])
      ).toThrow('Routing policy chain ownership is unknown');
  });
  test('rejects every foreign reference even with an owner-looking comment', () => {
    const p = plan(),
      tables = saved(p),
      child = p.classifier!.children[0]!.name;
    for (const line of [
      `-A PREROUTING -j ${child}`,
      `-A OUTPUT -g ${child}`,
      '-A PREROUTING -m comment --comment "wg-easy common routing" -j WG_ROUTE_MARK',
      '-A WG_FOREIGN -j WG_ROUTE_NAT',
    ])
      expect(() =>
        assertRoutingPolicyChains(
          { ...tables, mangle: `${tables.mangle}\n${line}` },
          [p]
        )
      ).toThrow('ownership is unknown');
    expect(() =>
      assertRoutingPolicyChains(
        { ...tables, nat: `${tables.nat}\n:${child} - [0:0]` },
        [p]
      )
    ).toThrow('ownership is unknown');
  });
  test('allows only known stale children before cleanup and requires their removal at final verification', () => {
    const previous = plan(),
      next = plan('host'),
      tables = saved(next),
      old = saved(previous);
    const child = previous.classifier!.children[0]!.name;
    const stale = old.mangle
      .split('\n')
      .filter(
        (l) => l.startsWith(`:${child} `) || l.startsWith(`-A ${child} `)
      );
    const mixed = {
      ...tables,
      mangle: [...tables.mangle.split('\n'), ...stale].join('\n'),
    };
    expect(() =>
      assertRoutingPolicyChains(mixed, [next, previous])
    ).not.toThrow();
    expect(() =>
      assertRoutingPolicyChains(mixed, [next], { final: true })
    ).toThrow('ownership is unknown');
    expect(() =>
      assertRoutingPolicyChains(tables, [next], { final: true })
    ).not.toThrow();
    const missing = {
      ...tables,
      mangle: tables.mangle
        .split('\n')
        .filter((l) => !l.startsWith(':WG_RP_'))
        .join('\n'),
    };
    expect(() => assertRoutingPolicyChains(missing, [next])).toThrow(
      'ownership is unknown'
    );
  });
});
