import { describe, expect, test } from 'vitest';

import {
  ConfigFormatSchema,
  InterfaceNameSchema,
  Ipv4CidrSchema,
  Ipv6CidrSchema,
  NetworkDeviceSchema,
  RoutingGroupPrefixSchema,
  RoutingGroupSchema,
  RoutingHealthSettingsSchema,
  RoutingSlotSchema,
  ServerAllowedIpsSchema,
} from '#shared/utils/schemas';
import { getInterfaceRuntimeAction } from '#shared/utils/interfaceLifecycle';

describe('shared Phase 1 schemas', () => {
  test('accepts command-safe Linux names and rejects injection shapes', () => {
    expect(InterfaceNameSchema.parse('awg-prod.1')).toBe('awg-prod.1');
    expect(NetworkDeviceSchema.parse('eth0')).toBe('eth0');

    for (const invalid of [
      'interface-name-too-long',
      'wg0; touch /tmp/x',
      'wg0$(id)',
      'wg0\nnext',
      '..',
      '😀',
    ]) {
      expect(() => InterfaceNameSchema.parse(invalid)).toThrow();
    }
  });

  test('canonicalizes versioned CIDRs with usable address capacity', () => {
    expect(Ipv4CidrSchema.parse('10.8.0.9/24')).toBe('10.8.0.0/24');
    expect(Ipv6CidrSchema.parse('fd42:251::abcd/64')).toBe('fd42:251::/64');
    expect(RoutingGroupPrefixSchema.parse('192.0.2.8/24')).toBe('192.0.2.0/24');
    expect(RoutingGroupPrefixSchema.parse('192.0.2.8/32')).toBe('192.0.2.8/32');

    expect(() => Ipv4CidrSchema.parse('10.8.0.0/31')).toThrow();
    expect(() => Ipv4CidrSchema.parse('fd42:251::/64')).toThrow();
    expect(() => Ipv6CidrSchema.parse('10.8.0.0/24')).toThrow();
    expect(() => RoutingGroupPrefixSchema.parse('192.0.2.8')).toThrow();
  });

  test('locks config-format and routing-slot contracts', () => {
    expect(ConfigFormatSchema.parse('auto')).toBe('auto');
    expect(ConfigFormatSchema.parse('wireguard')).toBe('wireguard');
    expect(ConfigFormatSchema.parse('amneziawg')).toBe('amneziawg');
    expect(() => ConfigFormatSchema.parse('migration_pending')).toThrow();

    expect(RoutingSlotSchema.parse(1)).toBe(1);
    expect(RoutingSlotSchema.parse(999)).toBe(999);
    expect(() => RoutingSlotSchema.parse(0)).toThrow();
    expect(() => RoutingSlotSchema.parse(1000)).toThrow();
  });

  test('locks routing health ranges and site-prefix safety', () => {
    expect(
      RoutingHealthSettingsSchema.parse({
        healthCheckIntervalSeconds: 60,
        healthTimeoutSeconds: 180,
        minHoldSeconds: 60,
        failbackDelaySeconds: 180,
      })
    ).toMatchObject({ healthTimeoutSeconds: 180 });
    expect(() =>
      RoutingHealthSettingsSchema.parse({
        healthCheckIntervalSeconds: 9,
        healthTimeoutSeconds: 180,
        minHoldSeconds: 60,
        failbackDelaySeconds: 180,
      })
    ).toThrow();
    expect(ServerAllowedIpsSchema.parse(['192.0.2.7/24'])).toEqual([
      '192.0.2.0/24',
    ]);
    expect(() => ServerAllowedIpsSchema.parse(['0.0.0.0/0'])).toThrow();
    expect(() => ServerAllowedIpsSchema.parse(['::/0'])).toThrow();
  });

  test('locks the interface lifecycle action matrix', () => {
    expect(getInterfaceRuntimeAction({ kind: 'create', enabled: false })).toBe(
      'none'
    );
    expect(getInterfaceRuntimeAction({ kind: 'create', enabled: true })).toBe(
      'up'
    );
    expect(
      getInterfaceRuntimeAction({
        kind: 'enabled',
        before: false,
        after: true,
      })
    ).toBe('up');
    expect(
      getInterfaceRuntimeAction({
        kind: 'enabled',
        before: true,
        after: false,
      })
    ).toBe('down');
    expect(getInterfaceRuntimeAction({ kind: 'peer' })).toBe('sync');
    expect(getInterfaceRuntimeAction({ kind: 'endpoint' })).toBe('none');
    expect(getInterfaceRuntimeAction({ kind: 'server' })).toBe('restart');
    expect(getInterfaceRuntimeAction({ kind: 'delete' })).toBe('down');
  });

  test('normalizes routing groups and rejects unsafe enabled aggregates', () => {
    expect(
      RoutingGroupSchema.parse({
        name: 'phones',
        enabled: true,
        exits: [{ clientId: 9, priority: 10, enabled: true }],
        natEnabled: true,
        allExitsDownPolicy: 'block',
        routedIpv4Prefixes: ['10.0.0.7/24', '10.0.0.0/24'],
        memberClientIds: [2, 2, 3],
      })
    ).toMatchObject({
      routedIpv4Prefixes: ['10.0.0.0/24'],
      memberClientIds: [2, 3],
    });

    expect(() =>
      RoutingGroupSchema.parse({
        name: 'invalid',
        enabled: true,
        exits: [{ clientId: 9, priority: 10, enabled: true }],
        natEnabled: true,
        allExitsDownPolicy: 'block',
        routedIpv4Prefixes: ['0.0.0.0/0'],
        memberClientIds: [9],
      })
    ).toThrow();

    expect(() =>
      RoutingGroupSchema.parse({
        name: 'draft-but-enabled',
        enabled: true,
        exits: [],
        natEnabled: true,
        allExitsDownPolicy: 'block',
        routedIpv4Prefixes: [],
        memberClientIds: [],
      })
    ).toThrow();
  });
});
