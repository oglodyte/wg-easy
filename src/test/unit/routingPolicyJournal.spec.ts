import { describe, expect, test } from 'vitest';

import { buildRoutingGuard } from '#server/utils/routingGuard';
import {
  parsePendingPolicyTransition,
  parseRoutingPolicyJournal,
} from '#server/utils/routingPolicyJournal';
import {
  routingPolicyRuntimeFingerprint,
  specializeRoutingPolicy,
} from '#server/utils/routingPolicyRuntime';
import type {
  AppliedRoutingPolicyPlan,
  RoutingPolicyJournal,
} from '#shared/types/routingPolicy';

function fixture(): RoutingPolicyJournal {
  const plan: AppliedRoutingPolicyPlan = {
    version: 2,
    interfaces: [
      { interfaceId: 'wg0', ipv4Cidr: '10.8.0.0/24', enabled: true },
    ],
    siteRoutes: [],
    bypassPrefixes: ['10.8.0.0/24'],
    programs: [],
    groups: [],
    peers: [],
  };
  return {
    revision: 7,
    fingerprint: routingPolicyRuntimeFingerprint(plan),
    plan,
  };
}
function pending() {
  return {
    ...fixture(),
    stage: 'prepared' as const,
    guardScopes: buildRoutingGuard(
      [
        {
          direction: 'output',
          source: '0.0.0.0/0',
          destination: '192.0.2.0/24',
        },
      ],
      { protectedPaths: [] }
    ).scopes,
    backupBasenames: ['policy-00000000-0000-0000-0000-000000000000.json'],
    errorCode: null,
  };
}

describe('strict inactive policy recovery records', () => {
  test('round-trips normalized non-secret evidence independent of object member ordering', () => {
    const value = fixture();
    expect(
      parseRoutingPolicyJournal(JSON.parse(JSON.stringify(value)))
    ).toEqual(value);
    expect(
      routingPolicyRuntimeFingerprint({
        peers: [],
        programs: [],
        groups: [],
        bypassPrefixes: value.plan.bypassPrefixes,
        interfaces: value.plan.interfaces,
        siteRoutes: [],
        version: 2,
      })
    ).toBe(value.fingerprint);
    expect(parsePendingPolicyTransition(pending())).toEqual(pending());
  });
  test('rejects secrets and unknown fields without echoing their values', () => {
    const value = fixture();
    let caught: unknown;
    try {
      parseRoutingPolicyJournal({
        ...value,
        plan: { ...value.plan, privateKey: 'sensitive-test-value' },
      });
    } catch (error) {
      caught = error;
    }
    expect(String(caught)).toBe(
      'RoutingPolicyJournalError: Routing policy recovery: invalid_record'
    );
    expect(JSON.stringify(caught)).not.toContain('sensitive-test-value');
    expect(() =>
      parseRoutingPolicyJournal({ ...value, desiredRevision: 8 })
    ).toThrow('invalid_record');
  });
  test('rejects fingerprints, invalid resource names, mismatched bypass and duplicated identities', () => {
    const value = fixture();
    expect(() =>
      parseRoutingPolicyJournal({ ...value, fingerprint: 'a'.repeat(64) })
    ).toThrow('invalid_record');
    for (const plan of [
      {
        ...value.plan,
        interfaces: [
          {
            interfaceId: 'wg0;anything',
            ipv4Cidr: '10.8.0.0/24',
            enabled: true,
          },
        ],
      },
      { ...value.plan, bypassPrefixes: [] },
      {
        ...value.plan,
        interfaces: [...value.plan.interfaces, ...value.plan.interfaces],
      },
    ])
      expect(() =>
        parseRoutingPolicyJournal({
          ...value,
          plan,
          fingerprint: routingPolicyRuntimeFingerprint(plan),
        })
      ).toThrow('invalid_record');
  });
  test('rejects unsafe guard scopes, arbitrary backup paths, duplicate refs and unknown stages', () => {
    const value = pending();
    expect(() =>
      parsePendingPolicyTransition({ ...value, stage: 'applied' })
    ).toThrow('invalid_pending_transition');
    expect(() =>
      parsePendingPolicyTransition({
        ...value,
        backupBasenames: ['../wg0.conf'],
      })
    ).toThrow('invalid_pending_transition');
    expect(() =>
      parsePendingPolicyTransition({
        ...value,
        backupBasenames: [...value.backupBasenames, ...value.backupBasenames],
      })
    ).toThrow('invalid_pending_transition');
    expect(() =>
      parsePendingPolicyTransition({
        ...value,
        guardScopes: [
          {
            direction: 'output',
            source: '0.0.0.0/0',
            destination: '0.0.0.0/0',
          },
        ],
      })
    ).toThrow('invalid_pending_transition');
    expect(() =>
      parsePendingPolicyTransition({
        ...value,
        errorCode: 'backend private input here',
      })
    ).toThrow('invalid_pending_transition');
  });
  test('accepts actual compiler-specialized peer/program evidence and rejects a corrupted action', () => {
    const result = specializeRoutingPolicy(
      {
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
            enabled: true,
            serverAllowedIps: [],
          },
          {
            id: 2,
            name: 'exit',
            interfaceId: 'awg1',
            publicKey: 'exit-public',
            ipv4Address: '10.9.0.2',
            enabled: true,
            serverAllowedIps: [],
          },
        ],
        groups: [
          {
            id: 1,
            name: 'LAN',
            routingSlot: 1,
            enabled: true,
            natEnabled: true,
            allExitsDownPolicy: 'block',
            routedIpv4Prefixes: ['192.168.0.0/16'],
            memberClientIds: [1],
            exits: [{ clientId: 2, priority: 0, enabled: true }],
          },
        ],
      },
      {
        selectedExitClientIds: new Map([[1, 2]]),
        enabledInterfaceIds: new Set(['wg0', 'awg1']),
        upInterfaceIds: new Set(['wg0', 'awg1']),
        enableIpv6: true,
      }
    );
    const record = {
      revision: 8,
      fingerprint: result.fingerprint,
      plan: result.plan,
    };
    expect(parseRoutingPolicyJournal(record)).toEqual(record);
    const bad = structuredClone(result.plan);
    bad.programs[0]!.branches[0]!.action = 'host';
    expect(() =>
      parseRoutingPolicyJournal({
        ...record,
        plan: bad,
        fingerprint: routingPolicyRuntimeFingerprint(bad),
      })
    ).toThrow('invalid_record');
    const wrongSource = structuredClone(result.plan);
    wrongSource.programs[0]!.sources[0]!.clientId = 999;
    expect(() =>
      parseRoutingPolicyJournal({
        ...record,
        plan: wrongSource,
        fingerprint: routingPolicyRuntimeFingerprint(wrongSource),
      })
    ).toThrow('invalid_record');
    const missing = structuredClone(result.plan);
    missing.peers = missing.peers.filter((p) => p.clientId !== 2);
    expect(() =>
      parseRoutingPolicyJournal({
        ...record,
        plan: missing,
        fingerprint: routingPolicyRuntimeFingerprint(missing),
      })
    ).toThrow('invalid_record');
  });
});
