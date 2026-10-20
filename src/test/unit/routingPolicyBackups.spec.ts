import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, test } from 'vitest';

import { RoutingPolicyBackups } from '#server/utils/routingPolicyBackups';

const roots: string[] = [];
async function setup() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'wge-policy-backup-'));
  roots.push(root);
  return { root, backups: new RoutingPolicyBackups(root) };
}
afterEach(async () => {
  for (const root of roots.splice(0))
    await fs.rm(root, { recursive: true, force: true });
});
const oldConfig = '[Interface]\n# restricted fixture before replacement\n';
const newConfig = '[Interface]\n# restricted fixture after replacement\n';

describe('private routing configuration recovery backups', () => {
  test('retains explicit restart intent for identical bytes and strictly binds it to both private generations', async () => {
    const { root, backups } = await setup();
    await fs.writeFile(path.join(root, 'wg0.conf'), oldConfig, { mode: 0o600 });
    const intent = {
      interfaces: [
        { interfaceId: 'wg0', previousUp: true, targetUp: true, restart: true },
      ],
      hooks: [],
    };
    const reference = await backups.create(['wg0'], {
      candidateConfigurations: new Map([['wg0', oldConfig]]),
      lifecycleIntent: intent,
    });
    expect(
      await new RoutingPolicyBackups(root).readPrivateLifecycleIntent(reference)
    ).toEqual(intent);
    await backups.restore(reference);
    expect(await backups.readPrivateLifecycleIntent(reference)).toEqual(intent);
    for (const options of [
      { lifecycleIntent: intent },
      {
        candidateConfigurations: new Map([['wg0', null]]),
        lifecycleIntent: intent,
      },
      {
        candidateConfigurations: new Map([['wg0', oldConfig]]),
        lifecycleIntent: {
          ...intent,
          interfaces: [{ ...intent.interfaces[0]!, interfaceId: 'other0' }],
        },
      },
    ])
      await expect(backups.create(['wg0'], options)).rejects.toThrow(
        'Routing recovery backup:'
      );
    const file = path.join(backups.directory, reference),
      saved = JSON.parse(await fs.readFile(file, 'utf8'));
    saved.lifecycle.interfaces[0].command = 'opaque';
    await fs.writeFile(file, JSON.stringify(saved));
    await expect(backups.readPrivateLifecycleIntent(reference)).rejects.toThrow(
      'invalid_or_missing_backup'
    );
    expect(await fs.readFile(path.join(root, 'wg0.conf'), 'utf8')).toBe(
      oldConfig
    );
  });

  test('retains both private generations after reopen, including new and removed interface files', async () => {
    const { root, backups } = await setup();
    await fs.writeFile(path.join(root, 'wg0.conf'), oldConfig, { mode: 0o600 });
    await fs.writeFile(path.join(root, 'removed0.conf'), oldConfig, {
      mode: 0o600,
    });
    const reference = await backups.create(['wg0', 'new0', 'removed0'], {
      candidateConfigurations: new Map([
        ['wg0', newConfig],
        ['new0', newConfig],
        ['removed0', null],
      ]),
    });
    const reopened = new RoutingPolicyBackups(root);
    expect(await reopened.readPrivateConfigurations(reference)).toEqual([
      { interfaceId: 'new0', config: null, candidate: newConfig },
      { interfaceId: 'removed0', config: oldConfig, candidate: null },
      { interfaceId: 'wg0', config: oldConfig, candidate: newConfig },
    ]);
    await fs.writeFile(path.join(root, 'wg0.conf'), newConfig);
    await fs.writeFile(path.join(root, 'new0.conf'), newConfig);
    await fs.unlink(path.join(root, 'removed0.conf'));
    await reopened.restore(reference);
    expect(await fs.readFile(path.join(root, 'wg0.conf'), 'utf8')).toBe(
      oldConfig
    );
    expect(await fs.readFile(path.join(root, 'removed0.conf'), 'utf8')).toBe(
      oldConfig
    );
    await expect(fs.stat(path.join(root, 'new0.conf'))).rejects.toMatchObject({
      code: 'ENOENT',
    });
    expect(
      (await reopened.readPrivateConfigurations(reference))[2]?.candidate
    ).toBe(newConfig);
    expect(
      (await fs.stat(path.join(backups.directory, reference))).mode & 0o777
    ).toBe(0o600);
  });

  test('rejects unknown candidate identities and malformed candidate bytes before touching runtime files', async () => {
    const { root, backups } = await setup();
    await fs.writeFile(path.join(root, 'wg0.conf'), oldConfig, { mode: 0o600 });
    await expect(
      backups.create(['wg0'], {
        candidateConfigurations: new Map([['../foreign', newConfig]]),
      })
    ).rejects.toThrow('invalid_candidate');
    const reference = await backups.create(['wg0'], {
      candidateConfigurations: new Map([['wg0', newConfig]]),
    });
    const file = path.join(backups.directory, reference);
    const manifest = JSON.parse(await fs.readFile(file, 'utf8'));
    manifest.interfaces[0].candidate = { unexpected: 'private fixture bytes' };
    await fs.writeFile(file, JSON.stringify(manifest));
    await expect(backups.readPrivateConfigurations(reference)).rejects.toThrow(
      'invalid_or_missing_backup'
    );
    await expect(backups.restore(reference)).rejects.toThrow(
      'invalid_or_missing_backup'
    );
    expect(await fs.readFile(path.join(root, 'wg0.conf'), 'utf8')).toBe(
      oldConfig
    );
  });

  test('restores exact historical bytes without desired client/key rows and removes newly created configs', async () => {
    const { root, backups } = await setup();
    await fs.writeFile(path.join(root, 'wg0.conf'), oldConfig, { mode: 0o600 });
    const reference = await backups.create(['wg0', 'new0']);
    expect(reference).toMatch(/^policy-[0-9a-f-]+\.json$/);
    expect((await fs.stat(backups.directory)).mode & 0o777).toBe(0o700);
    expect(
      (await fs.stat(path.join(backups.directory, reference))).mode & 0o777
    ).toBe(0o600);
    await fs.writeFile(path.join(root, 'wg0.conf'), newConfig);
    await fs.writeFile(path.join(root, 'new0.conf'), newConfig);
    await fs.writeFile(path.join(root, 'unrelated.txt'), 'preserve');
    await new RoutingPolicyBackups(root).restore(reference);
    expect(await fs.readFile(path.join(root, 'wg0.conf'), 'utf8')).toBe(
      oldConfig
    );
    await expect(fs.stat(path.join(root, 'new0.conf'))).rejects.toMatchObject({
      code: 'ENOENT',
    });
    expect(await fs.readFile(path.join(root, 'unrelated.txt'), 'utf8')).toBe(
      'preserve'
    );
    expect((await fs.stat(path.join(root, 'wg0.conf'))).mode & 0o777).toBe(
      0o600
    );
    await backups.remove(reference);
    await expect(
      fs.stat(path.join(backups.directory, reference))
    ).rejects.toMatchObject({ code: 'ENOENT' });
  });
  test('refuses traversal, unowned directories and linked source files', async () => {
    const { backups } = await setup();
    await expect(backups.restore('../wg0.conf')).rejects.toThrow(
      'invalid_reference'
    );
    await fs.mkdir(backups.directory);
    await fs.writeFile(path.join(backups.directory, 'foreign'), 'keep');
    await expect(backups.create(['wg0'])).rejects.toThrow('unowned_directory');
    expect(
      await fs.readFile(path.join(backups.directory, 'foreign'), 'utf8')
    ).toBe('keep');
    const other = await setup();
    await fs.writeFile(path.join(other.root, 'foreign'), oldConfig);
    await fs.symlink(
      path.join(other.root, 'foreign'),
      path.join(other.root, 'wg0.conf')
    );
    await expect(other.backups.create(['wg0'])).rejects.toThrow(
      'source_unavailable'
    );
    expect(await fs.readFile(path.join(other.root, 'foreign'), 'utf8')).toBe(
      oldConfig
    );
  });
  test('preflights all target identities before restoring any file', async () => {
    const { root, backups } = await setup();
    for (const name of ['awg1', 'awg2'])
      await fs.writeFile(path.join(root, name + '.conf'), oldConfig);
    const reference = await backups.create(['awg1', 'awg2']);
    await fs.writeFile(path.join(root, 'awg1.conf'), newConfig);
    await fs.unlink(path.join(root, 'awg2.conf'));
    await fs.writeFile(path.join(root, 'foreign'), newConfig);
    await fs.symlink(path.join(root, 'foreign'), path.join(root, 'awg2.conf'));
    await expect(backups.restore(reference)).rejects.toThrow(
      'non_regular_target'
    );
    expect(await fs.readFile(path.join(root, 'awg1.conf'), 'utf8')).toBe(
      newConfig
    );
    expect(await fs.readFile(path.join(root, 'foreign'), 'utf8')).toBe(
      newConfig
    );
  });
  test('keeps the backup and current file after configuration validation fails', async () => {
    const { root, backups } = await setup();
    await fs.writeFile(path.join(root, 'wg0.conf'), oldConfig);
    const reference = await backups.create(['wg0']);
    await fs.writeFile(path.join(root, 'wg0.conf'), newConfig);
    await expect(
      backups.restore(reference, async () => {
        throw new Error('injected validation failure');
      })
    ).rejects.toMatchObject({ code: 'restore_failed', interfaceId: 'wg0' });
    expect(await fs.readFile(path.join(root, 'wg0.conf'), 'utf8')).toBe(
      newConfig
    );
    expect(
      (await fs.stat(path.join(backups.directory, reference))).isFile()
    ).toBe(true);
    expect(
      (await fs.readdir(root)).filter((name) => name.startsWith('.wge-'))
    ).toEqual([]);
  });
  test('cleans only marked orphan backups and retains pending references and foreign files', async () => {
    const { backups } = await setup();
    const retained = await backups.create(['wg0']),
      orphan = await backups.create(['awg1']);
    const foreign = 'policy-00000000-0000-0000-0000-000000000000.json';
    await fs.writeFile(path.join(backups.directory, foreign), 'unowned', {
      mode: 0o600,
    });
    expect(await backups.cleanupOrphans(new Set([retained]))).toBe(1);
    expect(
      (await fs.stat(path.join(backups.directory, retained))).isFile()
    ).toBe(true);
    expect(
      await fs.readFile(path.join(backups.directory, foreign), 'utf8')
    ).toBe('unowned');
    await expect(
      fs.stat(path.join(backups.directory, orphan))
    ).rejects.toMatchObject({ code: 'ENOENT' });
  });
});
