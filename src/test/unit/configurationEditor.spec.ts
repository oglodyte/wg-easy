import { randomBytes } from 'node:crypto';

import { describe, expect, test } from 'vitest';

import {
  blankClientConfiguration,
  blankCredentials,
  clientCreatePayload,
  clientEditPayload,
  credentialsValid,
} from '../../app/utils/clientConfigurationEditor';
import {
  parsePrefixList,
  previewMatches,
  routingStatusKey,
  withPrivateExclusions,
} from '../../app/utils/routingEditor';

import { ClientConfigurationCreateSchema } from '#db/repositories/client/types';
import { RoutingGroupSchema } from '#shared/utils/schemas';

describe('operator configuration drafts', () => {
  test('runtime states retain truthful translation keys when the locale uses English fallback', () => {
    expect(routingStatusKey('active')).toBe('admin.routing.states.active');
    expect(routingStatusKey('host_fallback')).toBe('admin.routing.states.host');
    expect(routingStatusKey('draft_invalid')).toBe(
      'admin.routing.states.draft_invalid'
    );
    expect(routingStatusKey('unknown')).toBe(
      'admin.routing.states.unavailable'
    );
    expect(routingStatusKey('constructor')).toBe(
      'admin.routing.states.unavailable'
    );
  });
  test('untouched credential fields remain omitted, explicit PSK clearing and replacement are distinct', () => {
    const source = {
      ...blankClientConfiguration(),
      id: 17,
      userId: 9,
      privateKey: 'never resubmit',
      preSharedKey: 'never resubmit',
      publicKey: 'immutable response',
      hasPreSharedKey: true,
      interfaceId: 'unrelated',
    };
    const credentials = blankCredentials();
    const plain = clientEditPayload(source, credentials);
    for (const field of [
      'privateKey',
      'publicKey',
      'preSharedKey',
      'id',
      'userId',
      'interfaceId',
      'hasPreSharedKey',
    ])
      expect(Object.hasOwn(plain, field)).toBe(false);
    const key = randomBytes(32).toString('base64');
    credentials.pskAction = 'clear';
    expect(clientEditPayload(source, credentials).preSharedKey === null).toBe(
      true
    );
    credentials.pskAction = 'replace';
    credentials.preSharedKey = key;
    credentials.replacePrivateKey = true;
    credentials.privateKey = key;
    expect(credentialsValid(credentials)).toBe(true);
    expect(clientEditPayload(source, credentials).privateKey === key).toBe(
      true
    );
    expect(clientEditPayload(source, credentials).preSharedKey === key).toBe(
      true
    );
    credentials.privateKey = '';
    expect(credentialsValid(credentials)).toBe(false);
  });
  test('creation inherits automatic addresses while preserving explicit addresses, zero and empty overrides', () => {
    const data = blankClientConfiguration();
    data.name = 'operator';
    const options = {
      interfaceId: 'wg0',
      overrideAwg: false,
    };
    const first = ClientConfigurationCreateSchema.parse(
      clientCreatePayload(data, blankCredentials(), options)
    );
    expect(first.ipv4Address).toBeUndefined();
    expect(first.ipv6Address).toBeUndefined();
    expect(first.mtu).toBeUndefined();
    expect(first.persistentKeepalive).toBeUndefined();
    expect(first.jC).toBeUndefined();
    data.persistentKeepalive = 0;
    data.dns = [];
    data.ipv6Address = 'fd42::2';
    data.jMin = 0;
    const next = ClientConfigurationCreateSchema.parse(
      clientCreatePayload(data, blankCredentials(), {
        ...options,
        overrideAwg: true,
      })
    );
    expect(next.persistentKeepalive).toBe(0);
    expect(next.ipv6Address).toBe('fd42::2');
    expect(next.dns).toEqual([]);
    expect(next.allowedIps).toBeNull();
    expect(next.jMin).toBe(0);
  });
  test('bulk input preserves whole-field validation and private preset adds only three ordinary exclusions', () => {
    const included = parsePrefixList(' 0.0.0.0/0,\n198.51.100.0/24\n');
    expect(included).toEqual(['0.0.0.0/0', '198.51.100.0/24']);
    const text = withPrivateExclusions('10.0.0.0/8\n203.0.113.0/24');
    expect(parsePrefixList(text)).toEqual([
      '10.0.0.0/8',
      '203.0.113.0/24',
      '172.16.0.0/12',
      '192.168.0.0/16',
    ]);
    expect(withPrivateExclusions(text)).toBe(text);
    const group = {
      name: 'draft',
      enabled: false,
      natEnabled: true,
      allExitsDownPolicy: 'block',
      routedIpv4Prefixes: included,
      excludedIpv4Prefixes: parsePrefixList('10.0.0.0/8,broken'),
      memberClientIds: [],
      exits: [],
    };
    expect(RoutingGroupSchema.safeParse(group).success).toBe(false);
  });
  test('a new draft or concurrent revision invalidates preview without changing editable values', () => {
    const draft = {
      excludedIpv4Prefixes: ['10.0.0.0/8'],
      memberClientIds: [1, 8],
    };
    const key = JSON.stringify(draft),
      proof = { draft: key, revision: 12 };
    expect(previewMatches(proof, key, 12)).toBe(true);
    expect(previewMatches(proof, key, 13)).toBe(false);
    expect(
      previewMatches(
        proof,
        JSON.stringify({ ...draft, memberClientIds: [1] }),
        12
      )
    ).toBe(false);
    expect(draft).toEqual({
      excludedIpv4Prefixes: ['10.0.0.0/8'],
      memberClientIds: [1, 8],
    });
  });
});
