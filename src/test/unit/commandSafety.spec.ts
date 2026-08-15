import fs from 'node:fs/promises';
import path from 'node:path';

import { afterEach, describe, expect, test, vi } from 'vitest';

import { generateAwgParameterLines } from '#server/utils/awgConfig';
import { commandTestExports, withSecureInputFile } from '#server/utils/cmd';

afterEach(() => {
  vi.unstubAllEnvs();
  vi.resetModules();
});

describe('typed command and AWG config contracts', () => {
  test('formats argument vectors for logs without creating a shell command', () => {
    expect(
      commandTestExports.formatCommand('ip', [
        'link',
        'show',
        'wg0; touch /tmp/not-executed',
      ])
    ).toBe('ip link show "wg0; touch /tmp/not-executed"');
  });

  test('provides filename-only command input privately and removes it', async () => {
    let capturedPath = '';

    await withSecureInputFile('sensitive input\n', async (inputPath) => {
      capturedPath = inputPath;
      const [contents, fileStat, directoryStat] = await Promise.all([
        fs.readFile(inputPath, 'utf8'),
        fs.stat(inputPath),
        fs.stat(path.dirname(inputPath)),
      ]);

      expect(contents).toBe('sensitive input\n');
      expect(fileStat.mode & 0o777).toBe(0o600);
      expect(directoryStat.mode & 0o777).toBe(0o700);
    });

    await expect(fs.access(capturedPath)).rejects.toMatchObject({
      code: 'ENOENT',
    });
  });

  test('omits every AWG-only line in compatibility mode', () => {
    const parameters = {
      Jc: 7,
      Jmin: 10,
      Jmax: 1000,
      S1: 128,
      H1: '12345',
      I1: '<b 0x01>',
    };

    expect(generateAwgParameterLines(false, parameters, 'awg')).toEqual([]);
    expect(generateAwgParameterLines(true, parameters, 'awg')).toEqual([
      'Jc = 7',
      'Jmin = 10',
      'Jmax = 1000',
      'S1 = 128',
      'H1 = 12345',
      'I1 = <b 0x01>',
    ]);
    expect(generateAwgParameterLines(true, parameters, 'wg')).toEqual([]);
  });
});
