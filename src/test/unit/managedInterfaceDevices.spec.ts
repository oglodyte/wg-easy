import { randomBytes } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

import { describe, expect, test } from 'vitest';

import { LinuxManagedInterfaceDevices } from '#server/utils/managedInterfaceDevices';
import { deriveClientPublicKey } from '#server/utils/clientCredentials';
import { parseManagedInterfaceConfig } from '#server/utils/managedInterfaceState';
import type { execFile } from '#server/utils/cmd';

function fixture() {
  const privateKey = randomBytes(32).toString('base64'),
    publicKey = deriveClientPublicKey(randomBytes(32).toString('base64')),
    config = `[Interface]\nPrivateKey = ${privateKey}\nAddress = 10.8.0.1/24\nListenPort = 62001\nMTU = 1420\nTable = off\nPreUp = opaque operator text\nPostDown = opaque operator text\n[Peer]\nPublicKey = ${publicKey}\nAllowedIPs = 10.8.0.2/32\n`,
    runtime = new Map<string, string>(),
    calls: { binary: string; args: readonly string[] }[] = [],
    files: string[] = [];
  let kind = 'amneziawg';
  function stripped(text: string) {
    return text
      .split('\n')
      .filter(
        (line) =>
          !/^\s*(Address|MTU|Table|PreUp|PostUp|PreDown|PostDown)\s*=/i.test(
            line
          )
      )
      .join('\n');
  }
  const run: typeof execFile = async (binary, args = [], options = {}) => {
    calls.push({ binary, args });
    expect(options.log).toBe(false);
    if (binary === 'ip' && args[0] === '-d')
      return JSON.stringify(
        [...runtime.keys()].map((ifname) => ({
          ifname,
          flags: ['UP'],
          mtu: 1420,
          linkinfo: { info_kind: kind },
          addr_info: [
            {
              family: 'inet',
              scope: 'global',
              local: '10.8.0.1',
              prefixlen: 24,
            },
          ],
        }))
      );
    if (binary === 'awg' && args.join(' ') === 'show interfaces')
      return [...runtime.keys()].join(' ');
    if (binary === 'awg' && args[0] === 'showconf')
      return stripped(runtime.get(args[1]!)!);
    if (
      binary === 'awg' &&
      args[0] === 'show' &&
      args[2] === 'preshared-keys'
    ) {
      return parseManagedInterfaceConfig(args[1]!, runtime.get(args[1]!)!)
        .peers.map(
          (p) => `${p.get('publickey')}\t${p.get('presharedkey') ?? '(none)'}`
        )
        .join('\n');
    }
    if (binary === 'awg-quick') {
      const file = args[1]!,
        contents = await fs.readFile(file, 'utf8');
      files.push(file);
      expect((await fs.stat(file)).mode & 0o777).toBe(0o600);
      expect((await fs.stat(path.dirname(file))).mode & 0o777).toBe(0o700);
      expect(path.basename(file)).toBe('wg0.conf');
      expect(contents).not.toContain('opaque operator text');
      if (args[0] === 'strip') return stripped(contents);
      if (args[0] === 'up') {
        runtime.set('wg0', contents);
        return '';
      }
    }
    if (binary === 'awg' && args[0] === 'syncconf') {
      const input = await fs.readFile(args[2]!, 'utf8');
      files.push(args[2]!);
      expect(input).toContain(
        `PresharedKey = ${Buffer.alloc(32).toString('base64')}`
      );
      runtime.set(
        args[1]!,
        input.replace(
          '[Interface]',
          '[Interface]\nAddress = 10.8.0.1/24\nMTU = 1420\nTable = off'
        )
      );
      return '';
    }
    if (binary === 'ip' && args[0] === 'link' && args[1] === 'delete') {
      runtime.delete(args[3]!);
      return '';
    }
    throw new Error('unexpected command');
  };
  return {
    config,
    runtime,
    calls,
    files,
    run,
    devices: new LinuxManagedInterfaceDevices(run),
    kind: (value: string) => {
      kind = value;
    },
  };
}

describe('concrete guarded AWG lifecycle ports', () => {
  test.each(['amneziawg', 'tun'])(
    'preserves %s implementation and never sends operator hooks to quick',
    async (kind) => {
      const f = fixture();
      f.kind(kind);
      await f.devices.validate('wg0', f.config);
      expect(await f.devices.observe('wg0')).toBeNull();
      await f.devices.up('wg0', f.config);
      await f.devices.verifyRecoverable('wg0', [f.config], false);
      await f.devices.sync('wg0', f.config);
      await f.devices.down('wg0', f.config);
      expect(await f.devices.observe('wg0')).toBeNull();
      expect(
        f.calls.some((c) => c.binary === 'awg-quick' && c.args[0] === 'down')
      ).toBe(false);
      expect(
        f.calls.some(
          (c) =>
            c.binary.includes('tables') ||
            c.binary === 'sh' ||
            c.binary === 'bash'
        )
      ).toBe(false);
      for (const file of f.files)
        await expect(fs.stat(file)).rejects.toMatchObject({ code: 'ENOENT' });
    }
  );

  test('refuses unknown device type and invalid identity before destructive tooling', async () => {
    const f = fixture();
    f.runtime.set('wg0', f.config);
    f.kind('veth');
    await expect(f.devices.down('wg0', f.config)).rejects.toThrow(
      'stop_failed'
    );
    expect(f.calls.some((c) => c.args[0] === 'link')).toBe(false);
    const before = f.calls.length;
    await expect(f.devices.up('wg0; opaque', f.config)).rejects.toThrow(
      'invalid_interface'
    );
    expect(f.calls).toHaveLength(before);
  });

  test('redacts private tool diagnostics and cleans restricted input files on failure', async () => {
    const f = fixture(),
      secret = randomBytes(32).toString('base64'),
      paths: string[] = [],
      run: typeof execFile = async (binary, args = [], options = {}) => {
        if (binary === 'awg-quick') {
          paths.push(args[1]!);
          throw new Error(secret);
        }
        return f.run(binary, args, options);
      },
      devices = new LinuxManagedInterfaceDevices(run);
    await expect(devices.validate('wg0', f.config)).rejects.toMatchObject({
      code: 'configuration_invalid',
      interfaceId: 'wg0',
    });
    try {
      await devices.up('wg0', f.config);
    } catch (error) {
      expect(String(error)).not.toContain(secret);
    }
    for (const file of paths)
      await expect(fs.stat(file)).rejects.toMatchObject({ code: 'ENOENT' });
  });
});
