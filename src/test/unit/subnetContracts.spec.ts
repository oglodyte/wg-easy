import { randomBytes } from 'node:crypto';

import { describe, expect, test } from 'vitest';

import {
  ClientConfigurationCreateSchema,
  ClientConfigurationUpdateSchema,
  ClientCreateSchema,
  ClientUpdateSchema,
} from '#db/repositories/client/types';
import {
  prepareClientCredentials,
  deriveClientPublicKey,
} from '#server/utils/clientCredentials';
import { deriveImportPublicKey } from '#server/utils/legacyImport';
import { RoutingGroupSchema } from '#shared/utils/schemas';

const key = () => randomBytes(32).toString('base64');
const fields = {
  name: 'complete-profile',
  enabled: true,
  expiresAt: null,
  ipv4Address: '10.8.0.2',
  ipv6Address: null,
  preUp: '',
  postUp: '',
  preDown: '',
  postDown: '',
  allowedIps: ['0.0.0.0/0'],
  serverAllowedIps: [],
  firewallIps: null,
  mtu: 1420,
  jC: null,
  jMin: null,
  jMax: null,
  i1: null,
  i2: null,
  i3: null,
  i4: null,
  i5: null,
  persistentKeepalive: 25,
  serverEndpoint: null,
  dns: null,
};

describe('inactive full configuration and credential contracts', () => {
  test('covers every current supported edit field, preferred format and credential replacement', () => {
    const privateKey = key();
    const input = {
      ...fields,
      privateKey,
      publicKey: deriveClientPublicKey(privateKey),
      preSharedKey: null,
      preferredConfigFormat: 'auto',
    };
    // Boolean comparison prevents secret values from appearing in failure output.
    expect(
      JSON.stringify(ClientConfigurationUpdateSchema.parse(input)) ===
        JSON.stringify(input)
    ).toBe(true);
    expect(Object.keys(ClientConfigurationUpdateSchema.shape).sort()).toEqual(
      [
        ...Object.keys(ClientUpdateSchema.shape),
        'privateKey',
        'publicKey',
        'preSharedKey',
        'preferredConfigFormat',
      ].sort()
    );
  });
  test('accepts supplied private keys, derives and checks the pair, preserves generated defaults', () => {
    const privateKey = key();
    const credentials = prepareClientCredentials({ privateKey });
    expect(credentials.privateKey === privateKey).toBe(true);
    expect(credentials.publicKey === deriveImportPublicKey(privateKey)).toBe(
      true
    );
    expect(credentials.preSharedKey !== null).toBe(true);
    expect(
      prepareClientCredentials({ preSharedKey: null }).preSharedKey
    ).toBeNull();
    expect(prepareClientCredentials({}).privateKey.length).toBe(44);
    expect(() =>
      prepareClientCredentials({ privateKey, publicKey: key() })
    ).toThrow('key_mismatch');
  });
  test('old edits preserve all secrets, explicit PSK replacement/clear never changes identity', () => {
    const original = prepareClientCredentials({});
    expect(
      JSON.stringify(prepareClientCredentials({}, original)) ===
        JSON.stringify(original)
    ).toBe(true);
    const replacement = key();
    const changed = prepareClientCredentials(
      { preSharedKey: replacement },
      original
    );
    expect(
      changed.preSharedKey === replacement &&
        changed.privateKey === original.privateKey &&
        changed.publicKey === original.publicKey
    ).toBe(true);
    expect(
      prepareClientCredentials({ preSharedKey: null }, original).preSharedKey
    ).toBeNull();
  });
  test.each([
    '',
    '********',
    'not-a-key',
    'A'.repeat(43) + 'A',
    'A'.repeat(42) + 'B=',
  ])(
    'rejects invalid/masked/noncanonical keys without echoing them',
    (value) => {
      expect(
        ClientConfigurationCreateSchema.safeParse({
          name: 'test',
          privateKey: value,
        }).success
      ).toBe(false);
      let message = '';
      try {
        prepareClientCredentials({ privateKey: value });
      } catch (e) {
        message = (e as Error).message;
      }
      expect(message).toBe('Client credentials: invalid_key');
    }
  );
  test('null private key rejects, immutable fields cannot enter normal edits, routes remain inactive', () => {
    expect(
      ClientConfigurationCreateSchema.safeParse({
        name: 'test',
        privateKey: null,
      }).success
    ).toBe(false);
    const secret = key();
    const create = ClientConfigurationCreateSchema.parse({
      ...fields,
      privateKey: secret,
      interfaceId: 'tun0',
      id: 7,
      userId: 99,
    });
    expect(create.privateKey === secret).toBe(true);
    expect(Object.hasOwn(create, 'id') || Object.hasOwn(create, 'userId')).toBe(
      false
    );
    const old = ClientCreateSchema.parse({
      name: 'old',
      expiresAt: null,
      privateKey: secret,
    });
    expect(Object.hasOwn(old, 'privateKey')).toBe(false);
  });
  test('keeps actual API spelling and omitted versus explicit empty exclusions distinct', () => {
    const group = {
      name: 'test',
      enabled: false,
      natEnabled: true,
      allExitsDownPolicy: 'block',
      routedIpv4Prefixes: [],
      memberClientIds: [],
      exits: [],
    };
    const omitted = RoutingGroupSchema.parse(group);
    expect(omitted.excludedIpv4Prefixes).toBeUndefined();
    expect(
      RoutingGroupSchema.parse({ ...group, excludedIpv4Prefixes: [] })
        .excludedIpv4Prefixes
    ).toEqual([]);
    expect(
      RoutingGroupSchema.safeParse({
        ...group,
        routedIpv4Prefixes: undefined,
        includedIpv4Prefixes: [],
      }).success
    ).toBe(false);
    expect(
      RoutingGroupSchema.parse({
        ...group,
        excludedIpv4Prefixes: ['10.1.2.3/8', '10.0.0.0/8'],
      }).excludedIpv4Prefixes
    ).toEqual(['10.0.0.0/8']);
  });
});
