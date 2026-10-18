import { describe, expect, test } from 'vitest';

import {
  compileRoutingPolicy,
  policyRangeCidrs,
  PolicyValidationError,
  POLICY_LIMITS,
} from '#server/utils/routingPolicy';
import { validateProposedRoutingState } from '#server/utils/routingPolicyValidation';
import type {
  PolicyClient,
  PolicyGroup,
  PolicySnapshot,
} from '#shared/types/routingPolicy';

const client = (
  id: number,
  interfaceId = 'tun1',
  enabled = true
): PolicyClient => ({
  id,
  name: `profile-${id}`,
  interfaceId,
  publicKey: `synthetic-public-${id}`,
  ipv4Address: `10.${interfaceId === 'tun0' ? 0 : interfaceId === 'tun1' ? 1 : 2}.0.${id + 1}`,
  enabled,
  serverAllowedIps: [],
});
const group = (
  id: number,
  prefixes = ['0.0.0.0/0'],
  members = [1, 2],
  exits = [30]
): PolicyGroup => ({
  id,
  name: `group-${id}`,
  routingSlot: id,
  enabled: true,
  natEnabled: true,
  allExitsDownPolicy: 'block',
  routedIpv4Prefixes: prefixes,
  excludedIpv4Prefixes: [],
  memberClientIds: members,
  exits: exits.map((clientId, priority) => ({
    clientId,
    priority,
    enabled: true,
  })),
});
function state(groups: PolicyGroup[]): PolicySnapshot {
  return {
    interfaces: [
      { interfaceId: 'tun0', ipv4Cidr: '10.0.0.0/24' },
      { interfaceId: 'tun1', ipv4Cidr: '10.1.0.0/24' },
      { interfaceId: 'tun2', ipv4Cidr: '10.2.0.0/24' },
    ],
    clients: [
      client(1, 'tun0'),
      client(2, 'tun0'),
      client(20, 'tun2'),
      client(21),
      client(30),
      client(40),
    ],
    groups,
  };
}
function winner(s: PolicySnapshot, member: number, ip: number) {
  const plan = compileRoutingPolicy(s);
  return plan.programs
    .find((p) => p.sources.some((s) => s.clientId === member))
    ?.cells.find((c) => c.start <= ip && ip < c.end)?.groupId;
}
function failure(s: PolicySnapshot, code: string) {
  try {
    compileRoutingPolicy(s);
    throw new Error('Expected policy rejection');
  } catch (e) {
    if (!(e instanceof PolicyValidationError)) throw e;
    expect(e.code).toBe(code);
    return e;
  }
}
const ip = (value: string) =>
  value.split('.').reduce((n, part) => n * 256 + Number(part), 0);
const privatePrefixes = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'];

describe('inactive subnet policy compiler', () => {
  test('aligned members permit a LAN backup on the internet output interface', () => {
    const s = state([group(1), group(2, ['10.20.0.0/16'], [1, 2], [20, 21])]);
    const p = compileRoutingPolicy(s);
    expect(winner(s, 1, ip('10.20.4.5'))).toBe(2);
    expect(winner(s, 1, ip('8.8.8.8'))).toBe(1);
    expect(p.groups[0]!.effectivePrefixes).not.toContain('0.0.0.0/0');
    expect(p.counts.programs).toBe(1);
    expect(p.programs[0]!.sources.length).toBe(2);
    expect(JSON.stringify(p)).not.toContain('synthetic-public');
    expect(p.fingerprint).toMatch(/^[0-9a-f]{64}$/);
  });
  test('rejects a backup-only independent peer conflict regardless of current health/enabled client', () => {
    const s = state([group(1), group(2, ['10.20.0.0/16'], [1], [20, 21])]);
    s.clients.find((c) => c.id === 21)!.enabled = false;
    const e = failure(s, 'peer_conflict');
    expect(e.detail.interfaceId).toBe('tun1');
    expect(e.detail.clientIds?.sort()).toEqual([21, 30]);
    expect(e.detail.destination).toBe('10.20.0.0');
  });
  test('same-group same-interface alternatives and compatible same peers are permitted', () => {
    expect(
      compileRoutingPolicy(state([group(1, ['10.20.0.0/16'], [1], [21, 30])]))
        .candidateClaims.length
    ).toBeGreaterThan(0);
    expect(
      compileRoutingPolicy(
        state([group(1, ['0.0.0.0/0'], [1]), group(2, ['0.0.0.0/0'], [2])])
      ).groups
    ).toHaveLength(2);
  });
  test('different interfaces can own identical destinations', () => {
    expect(
      compileRoutingPolicy(
        state([
          group(1, ['0.0.0.0/0'], [1]),
          group(2, ['0.0.0.0/0'], [2], [20]),
        ])
      ).groups
    ).toHaveLength(2);
  });
  test('ties are invalid even with the same exit; input order and slot never resolve them', () => {
    const s = state([group(1, ['192.0.0.0/8']), group(2, ['192.0.0.0/8'])]);
    const e = failure(s, 'equal_specificity');
    expect(e.detail.destination).toBe('192.0.0.0');
    s.groups = [...s.groups].reverse();
    expect(failure(s, 'equal_specificity').detail.groupIds).toEqual([1, 2]);
  });
  test('original include specificity survives exclusion fragments and nested includes', () => {
    const broad = { ...group(1), excludedIpv4Prefixes: privatePrefixes };
    const s = state([broad, group(2, ['192.0.0.0/8'], [1, 2], [20])]);
    expect(winner(s, 1, ip('192.169.1.1'))).toBe(2);
    expect(winner(s, 1, ip('192.168.1.1'))).toBe(2);
    expect(winner(s, 1, ip('172.16.1.1'))).toBeUndefined();
    s.groups = [
      { ...group(1, ['0.0.0.0/0', '192.0.0.0/8']) },
      group(2, ['128.0.0.0/1'], [1, 2], [20]),
    ];
    expect(winner(s, 1, ip('192.1.1.1'))).toBe(1);
    expect(winner(s, 1, ip('193.1.1.1'))).toBe(2);
  });
  test('managed networks always bypass, empty enabled policy rejects, shadowing is valid', () => {
    expect(winner(state([group(1)]), 1, ip('10.1.0.31'))).toBeUndefined();
    failure(
      state([{ ...group(1), excludedIpv4Prefixes: ['0.0.0.0/0'] }]),
      'empty_policy'
    );
    expect(
      compileRoutingPolicy(
        state([group(1), group(2, ['0.0.0.0/1', '128.0.0.0/1'], [1, 2], [20])])
      ).groups[0]!.shadowed
    ).toBe(true);
    expect(
      compileRoutingPolicy(state([{ ...group(1, []), enabled: false }])).groups
    ).toEqual([]);
  });
  test('specific winner scope persists for both all-down actions', () => {
    for (const allExitsDownPolicy of ['block', 'host'] as const) {
      const s = state([
        group(1),
        { ...group(2, ['10.20.0.0/16'], [1, 2], [20, 21]), allExitsDownPolicy },
      ]);
      s.clients
        .filter((c) => [20, 21].includes(c.id))
        .forEach((c) => {
          c.enabled = false;
        });
      expect(winner(s, 1, ip('10.20.1.1'))).toBe(2);
    }
  });
  test('delete, disable, and membership removal re-expose persistent legacy owners; safe exclusion permits repair', () => {
    const s = state([group(1), group(2, ['10.20.0.0/16'], [1, 2], [40])]);
    s.clients.find((c) => c.id === 40)!.serverAllowedIps = ['10.20.0.0/16'];
    expect(compileRoutingPolicy(s).groups).toHaveLength(2);
    for (const groups of [
      [s.groups[0]!],
      [s.groups[0]!, { ...s.groups[1]!, enabled: false }],
      [s.groups[0]!, { ...s.groups[1]!, memberClientIds: [1] }],
    ]) {
      failure({ ...s, groups }, 'peer_conflict');
      expect(
        compileRoutingPolicy({
          ...s,
          groups: groups.map((g) =>
            g.id === 1 ? { ...g, excludedIpv4Prefixes: ['10.20.0.0/16'] } : g
          ),
        }).version
      ).toBe(2);
    }
  });
  test('retains disabled address/key alternatives without extra source or peer state', () => {
    const s = state([group(1)]);
    const original = s.clients[0]!;
    const alternative = { ...original, id: 99, enabled: false };
    s.clients = [...s.clients, alternative];
    s.groups = [...s.groups, { ...group(2, ['10.20.0.0/16'], [99], [20]) }];
    const p = compileRoutingPolicy(s);
    expect(p.programs[0]!.sources.map((s) => s.clientId)).toEqual([1, 2]);
    expect(p.basePeers.some((p) => p.clientId === 99)).toBe(false);
    original.enabled = false;
    alternative.enabled = true;
    const switched = compileRoutingPolicy(s);
    expect(switched.basePeers.some((p) => p.clientId === 1)).toBe(false);
    original.enabled = true;
    failure(s, 'enabled_identity_conflict');
  });
  test('exclusivity requires identity constraints, never a disabled flag alone', () => {
    const s = state([
      group(1, ['10.20.0.0/16'], [1], [30]),
      group(2, ['10.20.0.0/16'], [2], [21]),
    ]);
    s.clients.find((c) => c.id === 21)!.ipv4Address = s.clients.find(
      (c) => c.id === 30
    )!.ipv4Address;
    s.clients.find((c) => c.id === 21)!.enabled = false;
    expect(compileRoutingPolicy(s).version).toBe(2);
  });
  test('canonicalization, bounds, stable fingerprint and output contain no signed overflow', () => {
    expect(policyRangeCidrs([{ start: 0, end: 2 ** 32 }])).toEqual([
      '0.0.0.0/0',
    ]);
    expect(policyRangeCidrs([{ start: 2 ** 32 - 1, end: 2 ** 32 }])).toEqual([
      '255.255.255.255/32',
    ]);
    const s = state([group(1, ['203.0.113.4/24', '203.0.113.0/24'])]);
    const p = compileRoutingPolicy(s);
    s.clients = [...s.clients].reverse();
    s.interfaces = [...s.interfaces].reverse();
    expect(compileRoutingPolicy(s).fingerprint).toBe(p.fingerprint);
    expect(p.groups[0]!.includedPrefixes).toEqual(['203.0.113.0/24']);
  });
  test('enforces desired membership and prefix limits, including disabled drafts', () => {
    failure(
      state(
        Array.from({ length: 17 }, (_, i) => ({
          ...group(i + 1),
          enabled: false,
        }))
      ),
      'budget_exceeded'
    );
    const e = failure(
      state([
        {
          ...group(1),
          enabled: false,
          excludedIpv4Prefixes: Array(65).fill('10.0.0.0/8'),
        },
      ]),
      'budget_exceeded'
    );
    expect(e.detail).toMatchObject({
      budget: 'excluded_prefixes',
      actual: 65,
      limit: 64,
    });
  });
  test('reuses programs for representative 1024-member default/RFC1918 policies', () => {
    const s: PolicySnapshot = {
      interfaces: [
        { interfaceId: 'tun0', ipv4Cidr: '10.0.0.0/16' },
        { interfaceId: 'tun1', ipv4Cidr: '10.1.0.0/16' },
      ],
      clients: [],
      groups: [],
    };
    const members = Array.from({ length: 1024 }, (_, i) => i + 1);
    s.clients = [
      ...members.map((id) => ({
        ...client(id, 'tun0'),
        ipv4Address: `10.0.${Math.floor((id + 1) / 256)}.${(id + 1) % 256}`,
      })),
      client(2000),
    ];
    s.clients.find((c) => c.id === 2000)!.ipv4Address = '10.1.0.2';
    s.groups = [
      {
        ...group(1, ['0.0.0.0/0'], members, [2000]),
        excludedIpv4Prefixes: privatePrefixes,
      },
    ];
    const p = compileRoutingPolicy(s);
    expect(p.counts.programs).toBe(1);
    expect(p.counts.sourceDispatches).toBe(1024);
    expect(p.counts.winnerWork).toBeLessThan(1000);
    expect(p.counts.dispatchEntries).toBeLessThan(1100);
  });
  test('rejects attempted winner work before allocation beyond the cap', () => {
    const s = state([]);
    const members = Array.from({ length: 300 }, (_, i) => i + 1);
    s.clients = [
      ...members.map((id) => ({
        ...client(id, 'tun0'),
        ipv4Address: `10.0.${Math.floor((id + 1) / 256)}.${(id + 1) % 256}`,
      })),
      { ...client(1001), ipv4Address: '10.1.0.2' },
    ];
    s.interfaces = [
      { interfaceId: 'tun0', ipv4Cidr: '10.0.0.0/16' },
      { interfaceId: 'tun1', ipv4Cidr: '10.1.0.0/24' },
    ];
    s.groups = members.map((id) =>
      group(
        id,
        Array.from(
          { length: 64 },
          (_, n) =>
            `198.${Math.floor((id * 64 + n) / 256)}.${(id * 64 + n) % 256}.0/24`
        ),
        [id],
        [1001]
      )
    );
    // This first exceeds partition size, before evaluating the huge matrix.
    const e = failure(s, 'budget_exceeded');
    expect(e.detail.budget).toBe('intervals');
    expect(e.detail.actual).toBe(POLICY_LIMITS.intervals + 1);
    // Keep the partition small, but make ranking work expensive.
    s.groups = members.map((id) =>
      group(
        id,
        Array.from({ length: 64 }, (_, n) => `198.18.${n}.0/24`),
        [id],
        [1001]
      )
    );
    const work = failure(s, 'budget_exceeded');
    expect(work.detail).toMatchObject({
      budget: 'winner_work',
      actual: 1000001,
      limit: 1000000,
    });
  });
  test('all-candidate proof agrees with exhaustive valid two-group choices', () => {
    let seed = 71;
    const random = () => {
      seed = (seed * 1664525 + 1013904223) % 2 ** 32;
      return seed;
    };
    for (let n = 0; n < 200; n++) {
      const s = state([
        group(1, ['192.0.2.0/24'], [1], [20, 21]),
        group(2, ['192.0.2.0/24'], [2], [30, 40]),
      ]);
      const exits = s.clients.filter((c) => c.id >= 20);
      for (const c of exits) {
        c.interfaceId = random() % 2 ? 'tun1' : 'tun2';
        c.ipv4Address = `10.${c.interfaceId === 'tun1' ? 1 : 2}.0.${20 + (random() % 4)}`;
        c.publicKey = `synthetic-${c.interfaceId}-${random() % 3}`;
        c.enabled = false;
      }
      let incompatible = false;
      for (const a of exits.slice(0, 2))
        for (const b of exits.slice(2)) {
          const mutuallyExclusive =
            a.ipv4Address === b.ipv4Address ||
            (a.interfaceId === b.interfaceId && a.publicKey === b.publicKey);
          if (
            !mutuallyExclusive &&
            a.interfaceId === b.interfaceId &&
            a.publicKey !== b.publicKey
          )
            incompatible = true;
        }
      let rejected = false;
      try {
        compileRoutingPolicy(s);
      } catch (e) {
        if (!(e instanceof PolicyValidationError) || e.code !== 'peer_conflict')
          throw e;
        rejected = true;
      }
      expect(rejected).toBe(incompatible);
    }
  });
  test('bounds actual candidate comparisons before a combinatorial proof can grow', () => {
    const s: PolicySnapshot = {
      interfaces: [
        { interfaceId: 'tun0', ipv4Cidr: '10.0.0.0/16' },
        { interfaceId: 'tun1', ipv4Cidr: '10.1.0.0/16' },
      ],
      clients: [],
      groups: [],
    };
    const members = Array.from({ length: 100 }, (_, i) => i + 1);
    const exits = Array.from({ length: 16 }, (_, i) => 1000 + i);
    s.clients = [
      ...members.map((id) => client(id, 'tun0')),
      ...exits.map((id) => ({
        ...client(id),
        ipv4Address: '10.1.0.2',
        enabled: false,
      })),
    ];
    s.groups = members.map((id) => group(id, ['192.0.2.0/24'], [id], exits));
    const e = failure(s, 'budget_exceeded');
    expect(e.detail).toMatchObject({
      budget: 'candidate_comparisons',
      actual: 1000001,
    });
  });
  test('v1 bridge rejects advanced writes and unknown versions; pure v2 remains opt-in', () => {
    expect(validateProposedRoutingState(1, state([group(1)]))).toBeNull();
    expect(() =>
      validateProposedRoutingState(1, state([group(1), group(2)]))
    ).toThrow(PolicyValidationError);
    expect(() => validateProposedRoutingState(99, state([]))).toThrow(
      'cannot activate'
    );
  });
  test('independent sampled reference agrees across deterministic random prefix/exclusion programs', () => {
    // The reference tests individual numeric addresses, never compiler ranges/helpers.
    let seed = 1776;
    const random = () => {
      seed = (seed * 1664525 + 1013904223) % 2 ** 32;
      return seed;
    };
    const matches = (cidr: string, destination: number) => {
      const [network, length] = cidr.split('/');
      const size = 2 ** (32 - Number(length));
      return Math.floor(ip(network!) / size) === Math.floor(destination / size);
    };
    for (let dataset = 0; dataset < 40; dataset++) {
      const g1 = { ...group(1), excludedIpv4Prefixes: privatePrefixes };
      const g2 = group(2, [`${128 + (random() % 64)}.0.0.0/8`], [1, 2], [20]);
      const s = state([g1, g2]);
      const plan = compileRoutingPolicy(s);
      for (let sample = 0; sample < 100; sample++) {
        const destination = random();
        const ranked = s.groups
          .filter(
            (g) =>
              g.routedIpv4Prefixes.some((p) => matches(p, destination)) &&
              !(g.excludedIpv4Prefixes ?? []).some((p) =>
                matches(p, destination)
              )
          )
          .map((g) => ({
            id: g.id,
            rank: Math.max(
              ...g.routedIpv4Prefixes
                .filter((p) => matches(p, destination))
                .map((p) => Number(p.split('/')[1]))
            ),
          }))
          .sort((a, b) => b.rank - a.rank);
        const bypass = s.interfaces.some((i) =>
          matches(i.ipv4Cidr, destination)
        );
        const actual = plan.programs[0]!.cells.find(
          (c) => c.start <= destination && destination < c.end
        )?.groupId;
        expect(actual).toBe(bypass ? undefined : ranked[0]?.id);
      }
    }
  });
});
