import { describe, expect, test } from 'vitest';

import { resolveCompatibilityMode } from '#db/phase1Migration';

describe('Phase 1 compatibility-mode resolution', () => {
  test('uses generated config as authoritative evidence', () => {
    expect(
      resolveCompatibilityMode({
        generatedConfig: '[Interface]\nPrivateKey = hidden\nListenPort = 51820',
        legacyEnvironment: {
          EXPERIMENTAL_AWG: 'true',
          OVERRIDE_AUTO_AWG: 'awg',
        },
        freshInstall: false,
      })
    ).toMatchObject({
      awgParametersEnabled: false,
      configFormat: 'wireguard',
      source: 'generated_config',
    });

    expect(
      resolveCompatibilityMode({
        generatedConfig:
          '[Interface]\nPrivateKey = hidden\nJc = 7\nH1 = 12345\nI1 = <b 0x01>',
        legacyEnvironment: { EXPERIMENTAL_AWG: 'false' },
        freshInstall: false,
      })
    ).toMatchObject({
      awgParametersEnabled: true,
      configFormat: 'amneziawg',
      source: 'generated_config',
    });
  });

  test('treats omitted or all-zero AWG parameters as WireGuard compatible', () => {
    expect(
      resolveCompatibilityMode({
        generatedConfig: '[Interface]\nJc = 0\nH1 = 0\nH2 = 0-0',
        legacyEnvironment: {},
        freshInstall: false,
      })
    ).toMatchObject({
      awgParametersEnabled: false,
      configFormat: 'wireguard',
    });
  });

  test('uses only explicit legacy settings when config evidence is absent', () => {
    expect(
      resolveCompatibilityMode({
        legacyEnvironment: {
          EXPERIMENTAL_AWG: 'true',
          OVERRIDE_AUTO_AWG: 'awg',
        },
        freshInstall: false,
      })
    ).toMatchObject({ awgParametersEnabled: true });

    expect(
      resolveCompatibilityMode({
        legacyEnvironment: { EXPERIMENTAL_AWG: 'false' },
        freshInstall: false,
      })
    ).toMatchObject({ awgParametersEnabled: false });

    expect(
      resolveCompatibilityMode({
        legacyEnvironment: { EXPERIMENTAL_AWG: 'true' },
        freshInstall: false,
      })
    ).toBeNull();
  });

  test('defaults only an uninitialized fresh install to compatibility mode', () => {
    expect(
      resolveCompatibilityMode({
        legacyEnvironment: {},
        freshInstall: true,
      })
    ).toMatchObject({
      awgParametersEnabled: false,
      configFormat: 'wireguard',
      source: 'fresh_install',
    });

    expect(
      resolveCompatibilityMode({
        legacyEnvironment: {},
        freshInstall: false,
      })
    ).toBeNull();
  });
});
