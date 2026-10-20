import { randomBytes } from 'node:crypto';

import { describe, expect, test } from 'vitest';

import { deriveClientPublicKey } from '#server/utils/clientCredentials';
import {
  managedInterfaceRequiresRestart,
  parseManagedInterfaceConfig,
  verifyManagedInterfaceState,
  verifyRecoverableManagedInterfaceState,
} from '#server/utils/managedInterfaceState';

function fixture() {
  const privateKey = randomBytes(32).toString('base64'),
    publicKey = deriveClientPublicKey(randomBytes(32).toString('base64'));
  const config = `[Interface]\nPrivateKey = ${privateKey}\nListenPort = 62001\nAddress = 10.8.0.1/24, fd41:1::1/64\nMTU = 1420\nTable = off\nPostUp = echo operator-hook\n[Peer]\nPublicKey = ${publicKey}\nAllowedIPs = 10.8.0.2/32, fd41:1::2/128\nEndpoint = router.invalid:51820\n`;
  const showconf = `[Interface]\nPrivateKey = ${privateKey}\nListenPort = 62001\nJc = 0\nJmin = 0\nJmax = 0\nS1 = 0\nS2 = 0\nS3 = 0\nS4 = 0\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\n[Peer]\nPublicKey = ${publicKey}\nAdvancedSecurity = off\nAllowedIPs = fd41:1::2/128, 10.8.0.2/32\nEndpoint = 192.0.2.99:55555\n`;
  const links = [
    {
      ifname: 'wg0',
      flags: ['POINTOPOINT', 'UP'],
      mtu: 1420,
      addr_info: [
        { family: 'inet', local: '10.8.0.1', prefixlen: 24, scope: 'global' },
        {
          family: 'inet6',
          local: 'fd41:0001::1',
          prefixlen: 64,
          scope: 'global',
        },
        { family: 'inet6', local: 'fe80::1234', prefixlen: 64, scope: 'link' },
      ],
    },
  ];
  return {
    privateKey,
    publicKey,
    config,
    showconf,
    links,
    observed: { showconf, addresses: JSON.stringify(links) },
  };
}

describe('complete private managed-interface verification', () => {
  test('recognizes only the pinned userspace blank TUN ephemeral listen port during guarded recovery', () => {
    const f = fixture(),
      link = {
        ifname: 'wg0',
        flags: [],
        mtu: 1420,
        linkinfo: {
          info_kind: 'tun',
          info_data: { type: 'tun', persist: false },
        },
        addr_info: [] as object[],
      },
      partial = {
        showconf:
          '[Interface]\nListenPort = 58242\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\n',
        addresses: JSON.stringify([link]),
      };
    expect(() =>
      verifyRecoverableManagedInterfaceState('wg0', [f.config], partial, {
        allowPartialStart: true,
      })
    ).not.toThrow();
    expect(() =>
      verifyManagedInterfaceState('wg0', f.config, partial)
    ).toThrow();
    expect(() =>
      verifyRecoverableManagedInterfaceState('wg0', [f.config], partial)
    ).toThrow('unknown_partial_state');
    for (const changed of [
      { ...link, flags: ['UP'] },
      { ...link, mtu: 1500 },
      { ...link, linkinfo: { info_kind: 'amneziawg' } },
      {
        ...link,
        linkinfo: {
          ...link.linkinfo,
          info_data: { type: 'tun', persist: true },
        },
      },
      {
        ...link,
        addr_info: [
          { family: 'inet', local: '10.8.0.1', prefixlen: 24, scope: 'global' },
        ],
      },
    ])
      expect(() =>
        verifyRecoverableManagedInterfaceState(
          'wg0',
          [f.config],
          { ...partial, addresses: JSON.stringify([changed]) },
          { allowPartialStart: true }
        )
      ).toThrow('unknown_partial_state');
  });
  test('admits only known partial startup/sync states for guarded recovery, never as Applied', () => {
    const f = fixture(),
      target = f.config.replace('62001', '62002'),
      partial = {
        showconf: '[Interface]\n',
        addresses: JSON.stringify([
          { ifname: 'wg0', flags: [], mtu: 1420, addr_info: [] },
        ]),
      };
    expect(() =>
      verifyRecoverableManagedInterfaceState(
        'wg0',
        [f.config, target],
        partial,
        { allowPartialStart: true }
      )
    ).not.toThrow();
    expect(() =>
      verifyRecoverableManagedInterfaceState('wg0', [f.config, target], partial)
    ).toThrow('unknown_partial_state');
    expect(() => verifyManagedInterfaceState('wg0', target, partial)).toThrow();
    const configured = {
      showconf: f.showconf.replace('62001', '62002').split('[Peer]')[0]!,
      addresses: partial.addresses,
    };
    expect(() =>
      verifyRecoverableManagedInterfaceState(
        'wg0',
        [f.config, target],
        configured,
        { allowPartialStart: true }
      )
    ).not.toThrow();
    expect(() =>
      verifyRecoverableManagedInterfaceState('wg0', [f.config, target], {
        ...f.observed,
        showconf: f.showconf.replace(
          'AllowedIPs = fd41:1::2/128, 10.8.0.2/32',
          'AllowedIPs = 10.8.0.2/32'
        ),
      })
    ).not.toThrow();
  });

  test.each([
    'server',
    'peer',
    'prefix',
    'psk',
    'mtu',
    'address',
    'parameter',
    'uninitialized peer',
  ])('refuses unknown partial %s without leaking private input', (caseName) => {
    const f = fixture(),
      secret = randomBytes(32).toString('base64'),
      state = { ...f.observed };
    if (caseName === 'server')
      state.showconf = state.showconf.replace(f.privateKey, secret);
    if (caseName === 'peer')
      state.showconf = state.showconf.replace(
        f.publicKey,
        deriveClientPublicKey(secret)
      );
    if (caseName === 'prefix')
      state.showconf = state.showconf.replace(
        'AllowedIPs = fd41:1::2/128, 10.8.0.2/32',
        'AllowedIPs = 198.51.100.0/24'
      );
    if (caseName === 'psk') state.showconf += `PresharedKey = ${secret}\n`;
    if (caseName === 'mtu')
      state.addresses = state.addresses.replace('1420', '1401');
    if (caseName === 'address')
      state.addresses = state.addresses.replace('10.8.0.1', '10.9.0.1');
    if (caseName === 'parameter')
      state.showconf = state.showconf.replace('Jc = 0', 'Jc = 29');
    if (caseName === 'uninitialized peer')
      state.showconf = state.showconf.replace(
        `PrivateKey = ${f.privateKey}\n`,
        ''
      );
    expect(() =>
      verifyRecoverableManagedInterfaceState('wg0', [f.config], state, {
        allowPartialStart: true,
      })
    ).toThrow('unknown_partial_state');
    try {
      verifyRecoverableManagedInterfaceState('wg0', [f.config], state, {
        allowPartialStart: true,
      });
    } catch (error) {
      expect(String(error)).not.toContain(secret);
    }
  });
  test('preserves address host bits, canonical prefixes, compatibility defaults and authenticated endpoint roaming', () => {
    const f = fixture();
    expect(() =>
      verifyManagedInterfaceState('wg0', f.config, f.observed)
    ).not.toThrow();
    const clamped = Buffer.from(f.privateKey, 'base64');
    clamped[0] = clamped[0]! & 248;
    clamped[31] = (clamped[31]! & 127) | 64;
    expect(() =>
      verifyManagedInterfaceState('wg0', f.config, {
        ...f.observed,
        showconf: f.showconf.replace(f.privateKey, clamped.toString('base64')),
      })
    ).not.toThrow();
  });

  test.each([
    [
      'server key',
      (f: ReturnType<typeof fixture>) =>
        f.showconf.replace(f.privateKey, randomBytes(32).toString('base64')),
    ],
    [
      'listen port',
      (f: ReturnType<typeof fixture>) => f.showconf.replace('62001', '62002'),
    ],
    [
      'peer key',
      (f: ReturnType<typeof fixture>) =>
        f.showconf.replace(
          f.publicKey,
          deriveClientPublicKey(randomBytes(32).toString('base64'))
        ),
    ],
    [
      'stale peer',
      (f: ReturnType<typeof fixture>) =>
        f.showconf +
        '\n[Peer]\nPublicKey = ' +
        deriveClientPublicKey(randomBytes(32).toString('base64')) +
        '\nAllowedIPs = 10.8.0.9/32\n',
    ],
    [
      'stale prefix',
      (f: ReturnType<typeof fixture>) =>
        f.showconf.replace('10.8.0.2/32', '10.8.0.2/32, 198.51.100.0/24'),
    ],
    [
      'keepalive',
      (f: ReturnType<typeof fixture>) =>
        f.showconf + 'PersistentKeepalive = 30\n',
    ],
    [
      'mark',
      (f: ReturnType<typeof fixture>) =>
        f.showconf.replace('ListenPort', 'FwMark = 0x100\nListenPort'),
    ],
    [
      'junk count',
      (f: ReturnType<typeof fixture>) => f.showconf.replace('Jc = 0', 'Jc = 4'),
    ],
    [
      'header',
      (f: ReturnType<typeof fixture>) =>
        f.showconf.replace('H1 = 1', 'H1 = 99'),
    ],
    [
      'signature',
      (f: ReturnType<typeof fixture>) =>
        f.showconf.replace('Jc = 0', 'I1 = <r 10>\nJc = 0'),
    ],
    [
      'duplicate section',
      (f: ReturnType<typeof fixture>) =>
        f.showconf + '[Interface]\nListenPort = 62001\n',
    ],
  ] as const)(
    'refuses unverified %s with a scoped safe error',
    (_name, mutate) => {
      const f = fixture();
      expect(() =>
        verifyManagedInterfaceState('wg0', f.config, {
          ...f.observed,
          showconf: mutate(f),
        })
      ).toThrow('Managed interface verification:');
    }
  );

  test.each(['mtu', 'missing address', 'extra address', 'down', 'tentative'])(
    'refuses unverified %s',
    (failure) => {
      const f = fixture();
      if (failure === 'mtu') f.links[0]!.mtu++;
      if (failure === 'missing address') f.links[0]!.addr_info.shift();
      if (failure === 'extra address')
        f.links[0]!.addr_info.push({
          family: 'inet',
          local: '10.8.0.9',
          prefixlen: 24,
          scope: 'global',
        });
      if (failure === 'down') f.links[0]!.flags = [];
      if (failure === 'tentative')
        Object.assign(f.links[0]!.addr_info[1]!, { tentative: true });
      expect(() =>
        verifyManagedInterfaceState('wg0', f.config, {
          showconf: f.showconf,
          addresses: JSON.stringify(f.links),
        })
      ).toThrow('interface_addresses_unverified');
    }
  );

  test('compares PSKs only in memory and never exposes a retained secret or parser input', () => {
    const f = fixture(),
      secret = randomBytes(32).toString('base64');
    const showconf = f.showconf + `PresharedKey = ${secret}\n`;
    for (const observed of [
      { ...f.observed, showconf },
      { ...f.observed, addresses: secret },
    ]) {
      let message = '';
      try {
        verifyManagedInterfaceState('wg0', f.config, observed);
      } catch (error) {
        message = String(error);
      }
      expect(message).toContain('Managed interface verification:');
      for (const value of [secret, f.privateKey, f.publicKey])
        expect(message).not.toContain(value);
    }
    expect(() =>
      verifyManagedInterfaceState(
        'wg0',
        f.config + `PresharedKey = ${secret}\n`,
        { ...f.observed, showconf }
      )
    ).not.toThrow();
  });

  test('accepts exact AWG ranges and signature strings, while preserving untouched operator hooks', () => {
    const f = fixture();
    const config = f.config.replace(
      'MTU =',
      'Jc = 3\nH1 = 100-200\nI1 = <r 10>\nMTU ='
    );
    const showconf = f.showconf
      .replace('Jc = 0', 'Jc = 3\nI1 = <r 10>')
      .replace('H1 = 1\n', 'H1 = 100-200\n');
    expect(() =>
      verifyManagedInterfaceState('wg0', config, { ...f.observed, showconf })
    ).not.toThrow();
    expect(() =>
      verifyManagedInterfaceState('wg0', config, {
        ...f.observed,
        showconf: showconf.replace(
          'AdvancedSecurity = off',
          'AdvancedSecurity = on'
        ),
      })
    ).not.toThrow();
    expect(() =>
      verifyManagedInterfaceState('wg0', f.config, {
        ...f.observed,
        showconf: f.showconf.replace(
          'AdvancedSecurity = off',
          'AdvancedSecurity = on'
        ),
      })
    ).toThrow('peer_advanced_security_unverified');
    expect(() =>
      verifyManagedInterfaceState('wg0', config, {
        ...f.observed,
        showconf: showconf.replace(
          'AdvancedSecurity = off',
          'AdvancedSecurity = invalid'
        ),
      })
    ).toThrow('peer_advanced_security_unverified');
    const parsed = parseManagedInterfaceConfig('wg0', config);
    expect(parsed.fields.get('postup')).toBe('echo operator-hook');
    expect(
      managedInterfaceRequiresRestart(
        parsed,
        parseManagedInterfaceConfig('wg0', config.replace('62001', '62002'))
      )
    ).toBe(true);
    expect(
      managedInterfaceRequiresRestart(
        parsed,
        parseManagedInterfaceConfig(
          'wg0',
          config.replace('10.8.0.2/32', '10.8.0.3/32')
        )
      )
    ).toBe(false);
  });

  test('refuses unsafe interface identifiers and malformed private configuration without echoing supplied data', () => {
    const f = fixture();
    for (const config of [
      f.config.replace('Table = off', 'Table = auto'),
      f.config.replace('MTU = 1420', 'MTU = not-a-number'),
      f.config + 'Unknown = private-fixture-data\n',
      f.config.replace(f.privateKey, 'private-fixture-data'),
    ]) {
      expect(() => parseManagedInterfaceConfig('wg0', config)).toThrow(
        'invalid_configuration'
      );
    }
    expect(() =>
      parseManagedInterfaceConfig('../private-fixture-data', f.config)
    ).toThrow('invalid_configuration');
  });
  test('validates seed/observed endpoints and credentials before writes, while permitting scoped IPv6 roaming', () => {
    const f = fixture();
    for (const value of [
      '192.0.2.1:0',
      '192.0.2.1:65536',
      '999.1.1.1:2',
      '[fe80::1%../bad]:2',
    ]) {
      expect(() =>
        verifyManagedInterfaceState('wg0', f.config, {
          ...f.observed,
          showconf: f.showconf.replace('192.0.2.99:55555', value),
        })
      ).toThrow('peer_configuration_unverified');
    }
    expect(() =>
      verifyManagedInterfaceState('wg0', f.config, {
        ...f.observed,
        showconf: f.showconf.replace(
          '192.0.2.99:55555',
          '[fe80::1%eth0]:51820'
        ),
      })
    ).not.toThrow();
    expect(() =>
      parseManagedInterfaceConfig(
        'wg0',
        f.config.replace(f.publicKey, 'invalid-private-input')
      )
    ).toThrow('invalid_configuration');
    expect(() =>
      parseManagedInterfaceConfig(
        'wg0',
        f.config + 'PresharedKey = invalid-private-input\n'
      )
    ).toThrow('invalid_configuration');
  });
});
