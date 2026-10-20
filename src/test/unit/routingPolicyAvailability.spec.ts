import { describe, expect, test } from 'vitest';

import { deriveRoutingAvailabilityWithdrawal } from '#server/utils/routingPolicyAvailability';
import {
  readRoutingKernelNamespace,
  RoutingKernelNamespaceSchema,
} from '#server/utils/routingPolicyKernelContext';
import { specializeRoutingPolicy } from '#server/utils/routingPolicyRuntime';
import { parseRoutingPolicyJournal } from '#server/utils/routingPolicyJournal';
import { buildPolicyBootstrapBaseline } from '#server/utils/routingPolicyBootstrap';
import type { PolicySnapshot } from '#shared/types/routingPolicy';

const namespaceId = '11111111-1111-4111-8111-111111111111:4:4026531001',
  otherNamespace = '11111111-1111-4111-8111-111111111111:4:4026531002';
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
        serverAllowedIps: ['2001:db8:1::/64'],
      },
    ],
    groups: [
      {
        id: 1,
        name: 'LAN',
        routingSlot: 1,
        enabled: true,
        natEnabled: false,
        allExitsDownPolicy: 'block',
        routedIpv4Prefixes: ['192.168.0.0/16'],
        memberClientIds: [1],
        exits: [{ clientId: 2, priority: 0, enabled: true }],
      },
    ],
  };
  const result = specializeRoutingPolicy(snapshot, {
    selectedExitClientIds: new Map([[1, 2]]),
    enabledInterfaceIds: new Set(['wg0', 'awg1']),
    upInterfaceIds: new Set(['wg0', 'awg1']),
    enableIpv6: true,
    clientFirewall: {
      enableIpv6: true,
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
    },
    namespaceId,
  });
  return {
    snapshot,
    journal: {
      revision: 7,
      plan: result.plan,
      fingerprint: result.fingerprint,
    },
  };
}
describe('observed kernel availability evidence', () => {
  test('reads namespace identity through the same typed command runner and redacts failed observations', async () => {
    const calls: string[] = [];
    expect(
      await readRoutingKernelNamespace(async (binary, args) => {
        calls.push(`${binary}:${args?.join(',')}`);
        return binary === 'cat'
          ? '11111111-1111-4111-8111-111111111111'
          : binary === 'stat'
            ? '4:4026531001'
            : '317';
      })
    ).toBe(`${namespaceId}:317`);
    expect(calls).toEqual([
      'cat:/proc/sys/kernel/random/boot_id',
      'stat:-L,-c,%d:%i,/proc/self/ns/net',
      '/usr/local/bin/wg-easy-netns-cookie:',
    ]);
    const secret = 'private-untrusted-output';
    await expect(
      readRoutingKernelNamespace(async () => secret)
    ).rejects.toThrow('namespace unavailable');
    try {
      await readRoutingKernelNamespace(async () => {
        throw new Error(secret);
      });
    } catch (error) {
      expect(String(error).includes(secret)).toBe(false);
    }
  });
  test('distinguishes reused namespace inodes and retains historical journal parsing', async () => {
    const observe = (cookie: string) =>
      readRoutingKernelNamespace(async (binary) =>
        binary === 'cat'
          ? namespaceId.split(':')[0]!
          : binary === 'stat'
            ? '4:4026531001'
            : cookie
      );
    expect(await observe('317')).not.toBe(await observe('4395'));
    expect(await observe('317')).toBe(await observe('317'));
    expect(RoutingKernelNamespaceSchema.parse(namespaceId)).toBe(namespaceId);
    expect(await observe('18446744073709551615')).toBe(
      `${namespaceId}:18446744073709551615`
    );
    for (const value of ['0', '01', '-1', '18446744073709551616', '', 'bad'])
      await expect(observe(value)).rejects.toThrow('namespace unavailable');
    expect(
      RoutingKernelNamespaceSchema.safeParse(`${namespaceId}:bad`).success
    ).toBe(false);
  });
  test('withdraws the missing exit, retaining the configured partition and old hook evidence without selecting a backup', () => {
    const { journal } = fixture(),
      before = structuredClone(journal),
      down = deriveRoutingAvailabilityWithdrawal(journal, new Set(['awg1']), {
        namespaceId,
      });
    expect(down.revision).toBe(7);
    expect(down.plan.groups[0]).toMatchObject({
      selectedExitClientId: null,
      exitInterfaceId: null,
      serverIpv4Address: null,
    });
    expect(
      down.plan.programs[0]?.branches.every((b) => b.action === 'block')
    ).toBe(true);
    expect(
      down.plan.interfaces.find((i) => i.interfaceId === 'awg1')
    ).toMatchObject({ enabled: true, observedUp: false, hooksApplied: true });
    expect(down.plan.peers.map((p) => p.interfaceId)).toEqual(['wg0']);
    expect(down.plan.siteRoutes).toEqual([]);
    expect(down.plan.bypassPrefixes).toEqual(journal.plan.bypassPrefixes);
    expect(journal).toEqual(before);
    expect(parseRoutingPolicyJournal(down)).toEqual(down);
  });
  test('a namespace reset withdraws every device and old hook ownership while retaining policy semantics', () => {
    const { journal } = fixture(),
      down = deriveRoutingAvailabilityWithdrawal(
        journal,
        new Set(['wg0', 'awg1']),
        { namespaceId: otherNamespace, resetHooks: true }
      );
    expect(
      down.plan.interfaces.every(
        (i) => !i.observedUp && i.hooksApplied === false
      )
    ).toBe(true);
    expect(down.plan.peers).toEqual([]);
    expect(down.plan.clientFirewall.interfaces).toEqual([]);
    expect(down.plan.clientFirewall.entries).toEqual([]);
    expect(down.plan.namespaceId).toBe(otherNamespace);
    expect(down.plan.programs[0]?.sources).toEqual(
      journal.plan.programs[0]?.sources
    );
    expect(down.fingerprint).not.toBe(journal.fingerprint);
    expect(() =>
      deriveRoutingAvailabilityWithdrawal(journal, new Set(['awg1']), {
        namespaceId: otherNamespace,
        resetHooks: true,
      })
    ).toThrow('invalid_availability_withdrawal');
    expect(() =>
      deriveRoutingAvailabilityWithdrawal(journal, new Set(['awg1']), {
        namespaceId: otherNamespace,
      })
    ).toThrow('namespace_reset_mismatch');
  });
  test('active normalized evidence requires completed hooks and preserves bootstrap namespace identity', () => {
    const { snapshot, journal } = fixture();
    expect(() => buildPolicyBootstrapBaseline(snapshot, journal)).not.toThrow();
    const broken = structuredClone(journal);
    broken.plan.interfaces[0]!.hooksApplied = false;
    expect(() => parseRoutingPolicyJournal(broken)).toThrow('invalid_record');
    expect(() =>
      deriveRoutingAvailabilityWithdrawal(journal, new Set(['unknown0']), {
        namespaceId,
      })
    ).toThrow('invalid_availability_withdrawal');
    expect(() =>
      deriveRoutingAvailabilityWithdrawal(journal, new Set(), { namespaceId })
    ).toThrow('invalid_availability_withdrawal');
  });
  test('a controlled stop removes only its old hook ownership and can clean a retained-hook down baseline', () => {
    const { journal } = fixture(),
      down = deriveRoutingAvailabilityWithdrawal(journal, new Set(['awg1']), {
        namespaceId,
        stopInterfaceIds: new Set(['awg1']),
      });
    expect(
      down.plan.interfaces.find((i) => i.interfaceId === 'awg1')
    ).toMatchObject({ observedUp: false, hooksApplied: false });
    expect(
      down.plan.interfaces.find((i) => i.interfaceId === 'wg0')
    ).toMatchObject({ observedUp: true, hooksApplied: true });
    const missing = deriveRoutingAvailabilityWithdrawal(
      journal,
      new Set(['awg1']),
      { namespaceId }
    );
    expect(
      deriveRoutingAvailabilityWithdrawal(missing, new Set(['awg1']), {
        namespaceId,
        stopInterfaceIds: new Set(['awg1']),
      }).plan
    ).toEqual(down.plan);
  });
});
