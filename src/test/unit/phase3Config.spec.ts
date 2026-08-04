import { describe, expect, test, vi } from 'vitest';

import { wg } from '#server/utils/wgHelper';
import type { ClientType } from '#db/repositories/client/types';
import type { HooksType } from '#db/repositories/hooks/types';
import type { InterfaceType } from '#db/repositories/interface/types';
import type { UserConfigType } from '#db/repositories/userConfig/types';

vi.mock('#server/utils/config', () => ({
  WG_ENV: { WG_EXECUTABLE: 'awg', PORT: 51821 },
}));

const client = {
  id: 7,
  interfaceId: 'awg1',
  name: 'phone',
  privateKey: 'client-private',
  preSharedKey: 'shared',
  ipv4Address: '10.252.0.2',
  ipv6Address: 'fd42:252::2',
  mtu: 1280,
  preUp: null,
  postUp: null,
  preDown: null,
  postDown: null,
  dns: null,
  allowedIps: null,
  persistentKeepalive: 25,
  preferredConfigFormat: 'auto',
  jC: 7,
  jMin: 10,
  jMax: 1000,
  i1: '<b 0x01>',
  i2: null,
  i3: null,
  i4: null,
  i5: null,
} as unknown as ClientType;

const userConfig = {
  host: 'awg1.example.test',
  port: 51831,
  defaultDns: ['1.1.1.1'],
  defaultAllowedIps: ['0.0.0.0/0'],
} as unknown as UserConfigType;

const compatibilityInterface = {
  name: 'awg1',
  publicKey: 'awg1-server-public',
  awgParametersEnabled: false,
  defaultConfigFormat: 'wireguard',
  s1: 128,
  s2: 56,
  s3: null,
  s4: null,
  h1: '111',
  h2: '222',
  h3: '333',
  h4: '444',
} as unknown as InterfaceType;

describe('Phase 3 assigned-interface config generation', () => {
  test('keeps managed server routing tables disabled', () => {
    const serverInterface = {
      ...compatibilityInterface,
      privateKey: 'server-private',
      port: 51831,
      mtu: 1280,
      ipv4Cidr: '10.252.0.0/24',
      ipv6Cidr: 'fd42:252::/64',
      device: 'eth0',
      jC: 7,
      jMin: 10,
      jMax: 1000,
      i1: null,
      i2: null,
      i3: null,
      i4: null,
      i5: null,
    } as InterfaceType;
    const config = wg.generateServerInterface(serverInterface, {
      preUp: '',
      postUp: '',
      preDown: '',
      postDown: '',
    } as HooksType);

    expect(config).toContain('\nTable = off\n');
    expect(config).not.toContain('\nJc =');
  });

  test('uses the assigned interface key and endpoint in compatibility mode', () => {
    const config = wg.generateClientConfig(
      compatibilityInterface,
      userConfig,
      client,
      { format: 'auto' }
    );

    expect(config).toContain('PublicKey = awg1-server-public');
    expect(config).toContain('Endpoint = awg1.example.test:51831');
    expect(config).not.toContain('Jc =');
    expect(config).not.toContain('I1 =');
  });

  test('emits AWG fields only for an AWG export and rejects WG export', () => {
    const obfuscatedInterface = {
      ...compatibilityInterface,
      awgParametersEnabled: true,
      defaultConfigFormat: 'amneziawg',
    } as InterfaceType;

    const config = wg.generateClientConfig(
      obfuscatedInterface,
      userConfig,
      client,
      { format: 'auto' }
    );
    expect(config).toContain('Jc = 7');
    expect(config).toContain('H1 = 111');
    expect(() =>
      wg.generateClientConfig(obfuscatedInterface, userConfig, client, {
        format: 'wireguard',
      })
    ).toThrow('WireGuard export is unavailable for interface awg1');
  });
});
