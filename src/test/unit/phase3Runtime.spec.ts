import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { createClient } from '@libsql/client';
import { drizzle } from 'drizzle-orm/libsql';
import { migrate } from 'drizzle-orm/libsql/migrator';
import { afterEach, describe, expect, test, vi } from 'vitest';

import {
  RuntimeReconciler,
  runIsolatedInterfaceOperations,
} from '#server/utils/RuntimeReconciler';
import { atomicWriteFile } from '#server/utils/atomicFile';
import {
  RuntimeStateService,
  bumpDesiredRevision,
  getSafeRuntimeErrorMessage,
  toSafeRuntimeState,
} from '#db/repositories/runtime/service';
import * as schema from '#db/schema';
import type { DBType } from '#db/sqlite';
import type { MutationResult } from '#shared/types/runtime';

const migrationsDirectory = fileURLToPath(
  new URL('../../server/database/migrations', import.meta.url)
);
const temporaryRoots: string[] = [];

afterEach(async () => {
  vi.restoreAllMocks();
  await Promise.all(
    temporaryRoots
      .splice(0)
      .map((root) => fs.rm(root, { recursive: true, force: true }))
  );
});

const appliedResult: MutationResult = {
  success: true,
  revision: 2,
  runtime: { status: 'applied', appliedRevision: 2 },
};

describe('Phase 3 runtime reconciliation', () => {
  test('coalesces simultaneous requests into one serialized pass', async () => {
    const executor = vi.fn(async () => appliedResult);
    const reconciler = new RuntimeReconciler(executor);

    const first = reconciler.requestReconcile('client-create', [
      { interfaceId: 'wg0', action: 'sync' },
    ]);
    const second = reconciler.requestReconcile('interface-update', [
      { interfaceId: 'wg0', action: 'restart' },
    ]);

    await expect(Promise.all([first, second])).resolves.toEqual([
      appliedResult,
      appliedResult,
    ]);
    expect(executor).toHaveBeenCalledTimes(1);
    expect(executor).toHaveBeenCalledWith({
      reasons: ['client-create', 'interface-update'],
      impacts: [{ interfaceId: 'wg0', action: 'restart' }],
    });
  });

  test('runs a fresh follow-up pass for a request received during apply', async () => {
    let releaseFirst: (() => void) | undefined;
    const firstBlocked = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    let enteredFirst: (() => void) | undefined;
    const firstEntered = new Promise<void>((resolve) => {
      enteredFirst = resolve;
    });
    const requests: string[][] = [];
    const executor = vi.fn(
      async ({ reasons }: { reasons: readonly string[] }) => {
        requests.push([...reasons]);
        if (requests.length === 1) {
          enteredFirst?.();
          await firstBlocked;
        }
        return appliedResult;
      }
    );
    const reconciler = new RuntimeReconciler(executor);

    const first = reconciler.requestReconcile('first');
    await firstEntered;
    const second = reconciler.requestReconcile('state-changed-while-running');
    releaseFirst?.();
    await Promise.all([first, second]);

    expect(requests).toEqual([['first'], ['state-changed-while-running']]);
  });

  test('isolates one interface failure and continues unrelated work', async () => {
    const attempted: string[] = [];
    const failures = await runIsolatedInterfaceOperations(
      ['wg0', 'awg1', 'awg2'],
      (interfaceId) => interfaceId,
      async (interfaceId) => {
        attempted.push(interfaceId);
        if (interfaceId === 'awg1') throw new Error('injected failure');
      }
    );

    expect(attempted).toEqual(['wg0', 'awg1', 'awg2']);
    expect(failures).toHaveLength(1);
    expect(failures[0]).toMatchObject({ interfaceId: 'awg1' });
  });

  test('atomically replaces configs with private permissions', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'wg-easy-atomic-'));
    temporaryRoots.push(root);
    const target = path.join(root, 'awg1.conf');
    await fs.writeFile(target, 'old', { mode: 0o644 });

    await atomicWriteFile(target, 'new config\n');

    expect(await fs.readFile(target, 'utf8')).toBe('new config\n');
    expect((await fs.stat(target)).mode & 0o777).toBe(0o600);
    expect(await fs.readdir(root)).toEqual(['awg1.conf']);
  });

  test('keeps the previous config when validation fails', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'wg-easy-atomic-'));
    temporaryRoots.push(root);
    const target = path.join(root, 'wg0.conf');
    await fs.writeFile(target, 'last safe config\n', { mode: 0o600 });

    await expect(
      atomicWriteFile(target, 'invalid replacement\n', async () => {
        throw new Error('strip validation failed');
      })
    ).rejects.toThrow('strip validation failed');

    expect(await fs.readFile(target, 'utf8')).toBe('last safe config\n');
    expect(await fs.readdir(root)).toEqual(['wg0.conf']);
  });

  test('tracks desired and applied revisions independently', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'wg-easy-runtime-'));
    temporaryRoots.push(root);
    const client = createClient({ url: `file:${path.join(root, 'test.db')}` });
    const db = drizzle({ client, schema });
    await migrate(db, { migrationsFolder: migrationsDirectory });
    const typedDb = db as unknown as DBType;
    const runtime = new RuntimeStateService(typedDb);

    expect(await runtime.getGlobal()).toMatchObject({
      desiredRevision: 1,
      appliedRevision: 0,
      status: 'pending',
    });
    await bumpDesiredRevision(typedDb, ['wg0']);
    await runtime.markApplying();
    await runtime.markInterfaceApplying('wg0', 'starting');
    await runtime.markInterfaceApplied('wg0', true);
    await runtime.markGlobalApplied();

    expect(await runtime.getGlobal()).toMatchObject({
      desiredRevision: 2,
      appliedRevision: 2,
      status: 'idle',
    });
    expect(await runtime.getInterface('wg0')).toMatchObject({
      desiredRevision: 2,
      appliedRevision: 2,
      status: 'up',
      observedUp: true,
    });
  });

  test('does not claim a revision committed after a pass started', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'wg-easy-runtime-'));
    temporaryRoots.push(root);
    const client = createClient({ url: `file:${path.join(root, 'test.db')}` });
    const db = drizzle({ client, schema });
    await migrate(db, { migrationsFolder: migrationsDirectory });
    const typedDb = db as unknown as DBType;
    const runtime = new RuntimeStateService(typedDb);

    await bumpDesiredRevision(typedDb, ['wg0']);
    const passRevision = await runtime.markApplying();
    expect(passRevision).toBe(2);
    await bumpDesiredRevision(typedDb, ['wg0']);

    await runtime.markInterfaceApplied('wg0', true, passRevision);
    await runtime.markGlobalApplied(passRevision);

    expect(await runtime.getGlobal()).toMatchObject({
      desiredRevision: 3,
      appliedRevision: 2,
      status: 'pending',
    });
    expect(await runtime.getInterface('wg0')).toMatchObject({
      desiredRevision: 3,
      appliedRevision: 2,
      status: 'pending',
      observedUp: true,
    });
  });

  test('keeps raw runtime errors out of public readiness summaries', () => {
    expect(
      toSafeRuntimeState({
        interfaceId: 'awg1',
        status: 'degraded',
        lastError: 'operator hook stderr',
      })
    ).toEqual({ interfaceId: 'awg1', status: 'degraded' });
    expect(
      getSafeRuntimeErrorMessage(
        new Error('awg-quick failed with exit code 1: PrivateKey = secret')
      )
    ).toBe('awg-quick failed with exit code 1');
  });
});
