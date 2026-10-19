import fs from 'node:fs/promises';

import { describe, expect, test, vi } from 'vitest';

import {
  preparePeerSyncConfig,
  verifyPeerSyncPresharedKeys,
} from '#server/utils/peerSyncConfig';
import { wg } from '#server/utils/wgHelper';

const mocks = vi.hoisted(() => ({
  stripped: '',
  observed: '',
  input: '',
  file: '',
  args: [] as string[][],
  fail: false,
}));
vi.mock('#server/utils/config', () => ({ WG_ENV: { WG_EXECUTABLE: 'awg' } }));
vi.mock('#server/utils/cmd', async (original) => {
  const actual = await original<typeof import('#server/utils/cmd')>();
  return {
    ...actual,
    execFile: vi.fn(
      async (
        binary: string,
        args: string[],
        options: { log?: boolean } = {}
      ) => {
        mocks.args.push([binary, ...args]);
        if (mocks.fail) throw new Error('sensitive-tool-input');
        if (binary === 'awg-quick') return mocks.stripped;
        if (args[0] === 'syncconf') {
          mocks.file = args[2]!;
          mocks.input = await fs.readFile(mocks.file, 'utf8');
          expect((await fs.stat(mocks.file)).mode & 0o777).toBe(0o600);
          return '';
        }
        expect(args).toEqual(['show', 'wg0', 'preshared-keys']);
        expect(options.log).toBe(false);
        return mocks.observed;
      }
    ),
  };
});
const key = (byte: number) => Buffer.alloc(32, byte).toString('base64');
const config = (psk?: string) =>
  `[Interface]\nPrivateKey = private-fixture\n[Peer]\nPublicKey = ${key(1)}\nAllowedIPs = 10.8.0.2/32\n${psk ? `PresharedKey = ${psk}\n` : ''}`;

describe('ephemeral authoritative peer synchronization', () => {
  test('adds explicit clear only to absent peer PSKs, preserving supplied keys and source text', () => {
    const source =
      config() +
      `\n[Peer]\nPublicKey = ${key(2)}\nPresharedKey = ${key(3)}\nAllowedIPs = 10.8.0.3/32\n`;
    const prepared = preparePeerSyncConfig(source);
    expect(prepared).toContain(`PresharedKey = ${key(0)}\n`);
    expect(prepared).toContain(`PresharedKey = ${key(3)}\n`);
    expect(prepared.match(/PresharedKey = /g)).toHaveLength(2);
    expect(preparePeerSyncConfig(prepared)).toBe(prepared);
    expect(source.match(/PresharedKey = /g)).toHaveLength(1);
    expect(
      preparePeerSyncConfig('[Interface]\nPrivateKey = fixture\n')
    ).not.toContain('PresharedKey');
  });
  test('handles case, comments, CRLF and separate sections without treating a commented key as configured', () => {
    const source = `[Interface]\r\n# PresharedKey = ignored\r\n[peer]\r\nPublicKey = ${key(1)}\r\n# PresharedKey = ignored\r\n[Peer]\r\nPublicKey = ${key(2)}\r\npresharedkey = ${key(4)}\r\n`;
    const prepared = preparePeerSyncConfig(source);
    expect(
      prepared.match(new RegExp(`PresharedKey = ${key(0)}`, 'g'))
    ).toHaveLength(1);
    expect(prepared).toContain(`presharedkey = ${key(4)}`);
  });
  test('verifies absent, explicit and cleared keys across both runtime zero representations', () => {
    expect(() =>
      verifyPeerSyncPresharedKeys('wg0', config(), `${key(1)}\t(none)`)
    ).not.toThrow();
    expect(() =>
      verifyPeerSyncPresharedKeys('wg0', config(), `${key(1)}\t${key(0)}`)
    ).not.toThrow();
    expect(() =>
      verifyPeerSyncPresharedKeys('wg0', config(key(5)), `${key(1)}\t${key(5)}`)
    ).not.toThrow();
    expect(() =>
      verifyPeerSyncPresharedKeys('wg0', '[Interface]\n', '')
    ).not.toThrow();
  });
  test('rejects retained/missing/extra/duplicate peers and malformed state using only safe scoped errors', () => {
    for (const observed of [
      `${key(1)}\t${key(5)}`,
      '',
      `${key(2)}\t(none)`,
      `${key(1)}\t(none)\n${key(1)}\t(none)`,
      `${key(1)}\tmasked-private-input`,
    ]) {
      let error: unknown;
      try {
        verifyPeerSyncPresharedKeys('wg0', config(), observed);
      } catch (caught) {
        error = caught;
      }
      expect(String(error)).toBe(
        'PeerSyncCredentialError: Peer synchronization: preshared_keys_unverified'
      );
      expect(error).toMatchObject({
        code: 'preshared_keys_unverified',
        interfaceId: 'wg0',
      });
      expect(JSON.stringify(error)).not.toContain(key(5));
      expect(JSON.stringify(error)).not.toContain('masked-private-input');
    }
    expect(() =>
      verifyPeerSyncPresharedKeys(
        'wg0',
        config() + `PublicKey = ${key(2)}\n`,
        ''
      )
    ).toThrow('preshared_keys_unverified');
  });
  test('normal sync uses a private disposable adapted input, keeps exports untouched and checks actual credentials', async () => {
    mocks.args = [];
    mocks.stripped = config();
    mocks.observed = `${key(1)}\t(none)`;
    await wg.sync('wg0');
    expect(mocks.input).toContain(`PresharedKey = ${key(0)}`);
    expect(mocks.stripped).not.toContain('PresharedKey');
    await expect(fs.stat(mocks.file)).rejects.toMatchObject({ code: 'ENOENT' });
    expect(mocks.args.map((a) => a.slice(0, 2))).toEqual([
      ['awg-quick', 'strip'],
      ['awg', 'syncconf'],
      ['awg', 'show'],
    ]);
    mocks.observed = `${key(1)}\t${key(5)}`;
    await expect(wg.sync('wg0')).rejects.toThrow('preshared_keys_unverified');
  });
  test('tool errors cannot expose private input through runtime status or CLI errors', async () => {
    mocks.fail = true;
    try {
      await expect(wg.sync('wg0')).rejects.toMatchObject({
        code: 'sync_failed',
        interfaceId: 'wg0',
        message: 'Peer synchronization: sync_failed',
      });
    } finally {
      mocks.fail = false;
    }
  });
});
