import { describe, expect, test } from 'vitest';

import {
  FWMARK_MASK,
  ROUTING_MARK_CHAIN,
  RoutingValidationError,
  buildRoutingPlan,
  canonicalizeServerAllowedIps,
  findRoutingPrefixConflicts,
  findServerAllowedIpConflicts,
  formatMark,
  preflightRoutingOwnership,
  routingMarkForSlot,
  selectActiveExit,
} from '#server/utils/routing';

const interfaces = [
  {
    interfaceId: 'wg0',
    ipv4Cidr: '10.8.0.0/24',
    enabled: true,
    observedUp: true,
  },
  {
    interfaceId: 'awg1',
    ipv4Cidr: '10.10.0.0/24',
    enabled: true,
    observedUp: true,
  },
];

const clients = [
  {
    id: 1,
    interfaceId: 'wg0',
    ipv4Address: '10.8.0.2',
    enabled: true,
    serverAllowedIps: [],
  },
  {
    id: 2,
    interfaceId: 'awg1',
    ipv4Address: '10.10.0.2',
    enabled: true,
    serverAllowedIps: [],
  },
];

function group(
  overrides: Partial<
    Parameters<typeof buildRoutingPlan>[0]['groups'][number]
  > = {}
) {
  return {
    id: 17,
    routingSlot: 17,
    enabled: true,
    natEnabled: true,
    allExitsDownPolicy: 'block' as const,
    routedIpv4Prefixes: ['0.0.0.0/0'],
    memberClientIds: [1],
    selectedExitClientId: 2,
    ...overrides,
  };
}

describe('Phase 5 pure routing planner', () => {
  test('builds deterministic masked-mark, route, NAT, and peer intents', () => {
    const first = buildRoutingPlan({ interfaces, clients, groups: [group()] });
    const second = buildRoutingPlan({ interfaces, clients, groups: [group()] });

    expect(first).toEqual(second);
    expect(first.executionAvailable).toBe(true);
    expect(first.preflight.status).toBe('not_evaluated');
    expect(first.groups).toEqual([
      expect.objectContaining({
        groupId: 17,
        routingSlot: 17,
        outcome: 'selected_exit',
        table: 52017,
        priority: 22017,
        fwmark: 0x54110000,
      }),
    ]);
    expect(first.routes).toContainEqual(
      expect.objectContaining({
        prefix: '0.0.0.0/0',
        device: 'awg1',
        table: 52017,
        protocol: 186,
      })
    );
    expect(first.policyRules).toContainEqual(
      expect.objectContaining({
        priority: 22017,
        table: 52017,
        fwmark: 0x54110000,
        mask: FWMARK_MASK,
      })
    );
    expect(first.markChainRules).toContainEqual([
      '-A',
      ROUTING_MARK_CHAIN,
      '-s',
      '10.8.0.2/32',
      '-d',
      '0.0.0.0/0',
      '-m',
      'comment',
      '--comment',
      'wg-easy common routing group 17',
      '-j',
      'MARK',
      '--set-xmark',
      '0x54110000/0xffff0000',
    ]);
    expect(first.natChainRules).toContainEqual(
      expect.arrayContaining([
        '--mark',
        '0x54110000/0xffff0000',
        '-o',
        'awg1',
        '--to-source',
        '10.10.0.1',
      ])
    );
    expect(first.peerAllowedIps).toEqual([
      { clientId: 2, prefixes: ['0.0.0.0/0'] },
    ]);
  });

  test('plans NAT-off, block, and host policies without mutating the host', () => {
    const natOff = buildRoutingPlan({
      interfaces,
      clients,
      groups: [group({ natEnabled: false })],
    });
    expect(natOff.natChainRules).toEqual([]);

    const blocked = buildRoutingPlan({
      interfaces,
      clients,
      groups: [group({ selectedExitClientId: null })],
    });
    expect(blocked.groups[0]?.outcome).toBe('block');
    expect(blocked.routes).toContainEqual(
      expect.objectContaining({
        type: 'unreachable',
        prefix: '0.0.0.0/0',
      })
    );
    expect(blocked.policyRules).toHaveLength(1);

    const host = buildRoutingPlan({
      interfaces,
      clients,
      groups: [
        group({ selectedExitClientId: null, allExitsDownPolicy: 'host' }),
      ],
    });
    expect(host.groups[0]?.outcome).toBe('host');
    expect(host.routes).toEqual([]);
    expect(host.policyRules).toEqual([]);
    expect(host.markChainRules.every((rule) => !rule.includes('MARK'))).toBe(
      true
    );
  });

  test('plans explicit site-to-site routes and rejects global conflicts/defaults', () => {
    const withSiteRoute = buildRoutingPlan({
      interfaces,
      clients: [
        { ...clients[0]!, serverAllowedIps: ['192.0.2.7/24'] },
        clients[1]!,
      ],
      groups: [],
    });
    expect(withSiteRoute.routes).toContainEqual(
      expect.objectContaining({
        table: 51999,
        prefix: '192.0.2.0/24',
        device: 'wg0',
      })
    );
    expect(withSiteRoute.policyRules).toContainEqual(
      expect.objectContaining({ priority: 23000, table: 51999 })
    );

    expect(() => canonicalizeServerAllowedIps(['0.0.0.0/0'])).toThrow(
      'use a routing group'
    );
    expect(
      findServerAllowedIpConflicts([
        { id: 1, interfaceId: 'wg0', serverAllowedIps: ['192.0.2.0/24'] },
        { id: 2, interfaceId: 'awg1', serverAllowedIps: ['192.0.2.128/25'] },
      ])
    ).toEqual([
      expect.objectContaining({ code: 'server_allowed_ip_conflict' }),
    ]);
  });

  test('enforces cross-group WireGuard peer overlap constraints', () => {
    const routingClients = [
      { id: 10, interfaceId: 'awg1', serverAllowedIps: [] },
      { id: 11, interfaceId: 'awg1', serverAllowedIps: [] },
      { id: 12, interfaceId: 'awg2', serverAllowedIps: [] },
    ];
    const firstGroup = {
      id: 1,
      enabled: true,
      routedIpv4Prefixes: ['10.0.0.0/8'],
      exits: [{ clientId: 10, enabled: true }],
    };
    expect(
      findRoutingPrefixConflicts({
        clients: routingClients,
        groups: [
          firstGroup,
          {
            id: 2,
            enabled: true,
            routedIpv4Prefixes: ['10.1.0.0/16'],
            exits: [{ clientId: 11, enabled: true }],
          },
        ],
      })
    ).toContainEqual(
      expect.objectContaining({ code: 'routing_group_overlap' })
    );

    expect(
      findRoutingPrefixConflicts({
        clients: routingClients,
        groups: [
          firstGroup,
          {
            id: 2,
            enabled: true,
            routedIpv4Prefixes: ['10.1.0.0/16'],
            exits: [{ clientId: 12, enabled: true }],
          },
        ],
      })
    ).toEqual([]);

    expect(
      findRoutingPrefixConflicts({
        clients: [
          { id: 10, interfaceId: 'awg1', serverAllowedIps: [] },
          {
            id: 11,
            interfaceId: 'awg1',
            serverAllowedIps: ['10.1.0.0/16'],
          },
        ],
        groups: [firstGroup],
      })
    ).toContainEqual(
      expect.objectContaining({
        code: 'routing_server_allowed_ip_overlap',
      })
    );
  });

  test('accepts exact owned state and rejects non-owned reserved objects', () => {
    expect(routingMarkForSlot(17)).toBe(0x54110000);
    expect(formatMark(FWMARK_MASK)).toBe('0xffff0000');
    expect(
      preflightRoutingOwnership({
        policyRules: [
          {
            family: 4,
            priority: 22017,
            table: 52017,
            protocol: 186,
            fwmark: 0x54110000,
            mask: 0xffff0000,
          },
        ],
        routes: [
          { family: 4, table: 52017, protocol: 186, prefix: '0.0.0.0/0' },
        ],
        chains: [
          { table: 'mangle', name: 'WG_ROUTE_MARK', owner: 'wg-easy' },
          { table: 'nat', name: 'WG_ROUTE_NAT', owner: 'wg-easy' },
        ],
        markUses: [{ value: 0x54110000, mask: 0xffff0000, owner: 'wg-easy' }],
      })
    ).toEqual({ ok: true, conflicts: [] });

    const conflict = preflightRoutingOwnership({
      policyRules: [{ family: 4, priority: 22017, table: 100, protocol: 99 }],
      routes: [
        { family: 4, table: 52018, protocol: 99, prefix: '203.0.113.0/24' },
      ],
      chains: [{ table: 'mangle', name: 'WG_ROUTE_MARK', owner: 'other' }],
      markUses: [{ value: 0x54000000, mask: 0xff000000, owner: 'other' }],
    });
    expect(conflict.ok).toBe(false);
    expect(conflict.conflicts.map(({ kind }) => kind).sort()).toEqual([
      'chain',
      'mark',
      'route',
      'rule',
    ]);
  });

  test('selects exits with timeout, hold, immediate disable, and delayed failback', () => {
    const now = new Date('2026-08-04T12:00:00.000Z');
    const healthyAt = new Date(now.getTime() - 10_000);
    const base = {
      candidateEnabled: true,
      clientEnabled: true,
      interfaceEnabled: true,
      interfaceObservedUp: true,
      persistentKeepalive: 25,
      latestHandshakeAt: healthyAt,
      endpoint: '198.51.100.1:51820',
    };
    const settings = {
      healthTimeoutSeconds: 180,
      minHoldSeconds: 60,
      failbackDelaySeconds: 180,
    };

    expect(
      selectActiveExit({
        candidates: [
          { ...base, clientId: 1, priority: 10 },
          { ...base, clientId: 2, priority: 20 },
        ],
        current: { selectedExitClientId: null, selectedSince: null },
        settings,
        now,
      }).selectedExitClientId
    ).toBe(1);

    const held = selectActiveExit({
      candidates: [
        {
          ...base,
          clientId: 1,
          priority: 10,
          latestHandshakeAt: new Date(now.getTime() - 181_000),
        },
        { ...base, clientId: 2, priority: 20 },
      ],
      current: {
        selectedExitClientId: 1,
        selectedSince: new Date(now.getTime() - 30_000),
      },
      settings,
      now,
    });
    expect(held.selectedExitClientId).toBe(1);
    expect(held.reason).toContain('hold');

    const failedOver = selectActiveExit({
      candidates: [
        { ...base, clientId: 1, priority: 10, clientEnabled: false },
        { ...base, clientId: 2, priority: 20 },
      ],
      current: {
        selectedExitClientId: 1,
        selectedSince: new Date(now.getTime() - 5_000),
      },
      settings,
      now,
    });
    expect(failedOver.selectedExitClientId).toBe(2);

    const failedBack = selectActiveExit({
      candidates: [
        {
          ...base,
          clientId: 1,
          priority: 10,
          healthySince: new Date(now.getTime() - 181_000),
        },
        { ...base, clientId: 2, priority: 20 },
      ],
      current: {
        selectedExitClientId: 2,
        selectedSince: new Date(now.getTime() - 300_000),
      },
      settings,
      now,
    });
    expect(failedBack.selectedExitClientId).toBe(1);
    expect(failedBack.reason).toContain('failback');
  });

  test('rejects plans over the global generated-rule limit', () => {
    const groups = Array.from({ length: 5 }, (_, index) =>
      group({
        id: index + 1,
        routingSlot: index + 1,
        memberClientIds: Array.from(
          { length: 4096 },
          (_unused, memberIndex) => memberIndex + 1
        ),
      })
    );
    expect(() => buildRoutingPlan({ interfaces, clients, groups })).toThrow(
      RoutingValidationError
    );
  });
});
