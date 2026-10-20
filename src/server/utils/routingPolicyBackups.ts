import { randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import fs from 'node:fs/promises';
import path from 'node:path';

import { atomicWriteFile } from '#server/utils/atomicFile';
import {
  parseManagedLifecycleIntent,
  type ManagedLifecycleIntent,
} from '#server/utils/managedLifecycleIntent';
import { InterfaceNameSchema } from '#shared/utils/schemas';

const OWNER = 'wg-easy routing policy config backup v1';
const BASENAME =
  /^policy-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.json$/;
export function isRoutingPolicyBackupReference(value: string) {
  return BASENAME.test(value) && path.basename(value) === value;
}
type SavedConfigurations = {
  owner: typeof OWNER;
  lifecycle?: ManagedLifecycleIntent;
  interfaces: {
    interfaceId: string;
    config: string | null;
    candidate?: string | null;
  }[];
};
export class RoutingPolicyBackupError extends Error {
  constructor(
    readonly code: string,
    readonly interfaceId?: string
  ) {
    // Never include configuration text or filesystem error causes in messages.
    super(`Routing recovery backup: ${code}`);
    this.name = 'RoutingPolicyBackupError';
  }
}
async function syncDirectory(directory: string) {
  const handle = await fs.open(directory, 'r');
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}
async function regularFile(filePath: string) {
  const handle = await fs.open(
    filePath,
    constants.O_RDONLY | constants.O_NOFOLLOW
  );
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.nlink !== 1)
      throw new RoutingPolicyBackupError('non_regular_file');
    return await handle.readFile('utf8');
  } finally {
    await handle.close();
  }
}
function parse(value: unknown): SavedConfigurations {
  if (
    !value ||
    typeof value !== 'object' ||
    !('owner' in value) ||
    value.owner !== OWNER ||
    !('interfaces' in value) ||
    !Array.isArray(value.interfaces) ||
    !['interfaces,owner', 'interfaces,lifecycle,owner'].includes(
      Object.keys(value).sort().join(',')
    )
  )
    throw new RoutingPolicyBackupError('invalid_manifest');
  const ids = new Set<string>();
  const interfaces = value.interfaces.map((entry: unknown) => {
    if (
      !entry ||
      typeof entry !== 'object' ||
      !('interfaceId' in entry) ||
      !('config' in entry) ||
      !['config,interfaceId', 'candidate,config,interfaceId'].includes(
        Object.keys(entry).sort().join(',')
      ) ||
      ('candidate' in entry &&
        typeof entry.candidate !== 'string' &&
        entry.candidate !== null) ||
      (typeof entry.config !== 'string' && entry.config !== null)
    )
      throw new RoutingPolicyBackupError('invalid_manifest');
    const parsed = InterfaceNameSchema.safeParse(entry.interfaceId);
    if (!parsed.success || ids.has(parsed.data))
      throw new RoutingPolicyBackupError('invalid_manifest');
    ids.add(parsed.data);
    return {
      interfaceId: parsed.data,
      config: entry.config,
      ...('candidate' in entry
        ? { candidate: entry.candidate as string | null }
        : {}),
    };
  });
  const lifecycle =
    'lifecycle' in value
      ? parseManagedLifecycleIntent(value.lifecycle)
      : undefined;
  if (
    lifecycle &&
    (lifecycle.interfaces.length !== interfaces.length ||
      lifecycle.interfaces.some((entry) => !ids.has(entry.interfaceId)) ||
      interfaces.some((entry) => !('candidate' in entry)) ||
      lifecycle.interfaces.some((intent) => {
        const entry = interfaces.find(
          (i) => i.interfaceId === intent.interfaceId
        )!;
        return (
          ((intent.previousUp || intent.previousHooksApplied) &&
            entry.config === null) ||
          ((intent.targetUp || intent.targetHooksApplied) &&
            entry.candidate === null)
        );
      }))
  )
    throw new RoutingPolicyBackupError('invalid_manifest');
  return { owner: OWNER, interfaces, ...(lifecycle ? { lifecycle } : {}) };
}

/** Private durable bytes; recovery needs no surviving desired client/key rows. */
export class RoutingPolicyBackups {
  readonly directory: string;
  constructor(private readonly configDirectory: string) {
    if (!path.isAbsolute(configDirectory))
      throw new RoutingPolicyBackupError('invalid_root');
    this.directory = path.join(configDirectory, '.routing-policy-backups');
  }
  private reference(basename: string) {
    if (!isRoutingPolicyBackupReference(basename))
      throw new RoutingPolicyBackupError('invalid_reference');
    return path.join(this.directory, basename);
  }
  private async ownedDirectory() {
    let created = false;
    try {
      await fs.mkdir(this.directory, { mode: 0o700 });
      created = true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST')
        throw new RoutingPolicyBackupError('directory_unavailable');
    }
    const stat = await fs.lstat(this.directory);
    if (!stat.isDirectory() || stat.isSymbolicLink())
      throw new RoutingPolicyBackupError('unowned_directory');
    const marker = path.join(this.directory, 'owner');
    if (created) {
      const handle = await fs.open(marker, 'wx', 0o600);
      try {
        await handle.writeFile(OWNER + '\n');
        await handle.sync();
      } finally {
        await handle.close();
      }
      await syncDirectory(this.directory);
      await syncDirectory(this.configDirectory);
    }
    try {
      if ((await regularFile(marker)) !== OWNER + '\n') throw new Error();
    } catch {
      throw new RoutingPolicyBackupError('unowned_directory');
    }
    await fs.chmod(this.directory, 0o700);
  }
  async create(
    interfaceIds: readonly string[],
    {
      candidateConfigurations,
      lifecycleIntent,
      expectedPreviousConfigurations,
    }: {
      candidateConfigurations?: ReadonlyMap<string, string | null>;
      lifecycleIntent?: ManagedLifecycleIntent;
      expectedPreviousConfigurations?: ReadonlyMap<string, string | null>;
    } = {}
  ) {
    const ids = [...new Set(interfaceIds)].sort();
    if (ids.some((id) => !InterfaceNameSchema.safeParse(id).success))
      throw new RoutingPolicyBackupError('invalid_interface');
    const knownIds = new Set(ids);
    if (
      expectedPreviousConfigurations &&
      (expectedPreviousConfigurations.size !== ids.length ||
        ids.some((id) => !expectedPreviousConfigurations.has(id)))
    )
      throw new RoutingPolicyBackupError('invalid_expected_previous');
    if (
      candidateConfigurations &&
      [...candidateConfigurations].some(
        ([id, config]) =>
          !knownIds.has(id) || (typeof config !== 'string' && config !== null)
      )
    )
      throw new RoutingPolicyBackupError('invalid_candidate');
    const lifecycle =
      lifecycleIntent === undefined
        ? undefined
        : parseManagedLifecycleIntent(lifecycleIntent);
    if (
      lifecycle &&
      (lifecycle.interfaces.length !== ids.length ||
        lifecycle.interfaces.some((i) => !knownIds.has(i.interfaceId)) ||
        !candidateConfigurations ||
        ids.some((id) => !candidateConfigurations.has(id)))
    )
      throw new RoutingPolicyBackupError('invalid_lifecycle_intent');
    await this.ownedDirectory();
    const interfaces: SavedConfigurations['interfaces'] = [];
    for (const interfaceId of ids) {
      let config: string | null;
      try {
        config = await regularFile(
          path.join(this.configDirectory, `${interfaceId}.conf`)
        );
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT') config = null;
        else throw new RoutingPolicyBackupError('source_unavailable');
      }
      interfaces.push({
        interfaceId,
        config,
        ...(candidateConfigurations?.has(interfaceId)
          ? { candidate: candidateConfigurations.get(interfaceId)! }
          : {}),
      });
      if (
        expectedPreviousConfigurations &&
        config !== expectedPreviousConfigurations.get(interfaceId)
      )
        throw new RoutingPolicyBackupError('baseline_changed', interfaceId);
    }
    const saved = parse({
      owner: OWNER,
      interfaces,
      ...(lifecycle ? { lifecycle } : {}),
    });
    const basename = `policy-${randomUUID()}.json`;
    const handle = await fs.open(this.reference(basename), 'wx', 0o600);
    try {
      await handle.writeFile(JSON.stringify(saved));
      await handle.sync();
    } finally {
      await handle.close();
    }
    await syncDirectory(this.directory);
    return basename;
  }
  private async read(basename: string) {
    const file = this.reference(basename);
    await this.ownedDirectory();
    try {
      const stat = await fs.lstat(file);
      if ((stat.mode & 0o777) !== 0o600) throw new Error();
      return parse(JSON.parse(await regularFile(file)) as unknown);
    } catch {
      throw new RoutingPolicyBackupError('invalid_or_missing_backup');
    }
  }
  /** Private in-memory bytes only; never expose through an API or diagnostics. */
  async readPrivateConfigurations(basename: string) {
    return (await this.read(basename)).interfaces;
  }
  async readPrivateLifecycleIntent(basename: string) {
    return (await this.read(basename)).lifecycle;
  }
  /** Refuse unknown private bytes before cold-namespace file-only restoration. */
  async verifyKnownCurrentConfigurations(basename: string) {
    const saved = await this.read(basename);
    for (const entry of saved.interfaces) {
      let current: string | null;
      try {
        current = await regularFile(
          path.join(this.configDirectory, `${entry.interfaceId}.conf`)
        );
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT') current = null;
        else
          throw new RoutingPolicyBackupError(
            'source_unavailable',
            entry.interfaceId
          );
      }
      if (
        current !== entry.config &&
        (entry.candidate === undefined || current !== entry.candidate)
      )
        throw new RoutingPolicyBackupError(
          'unknown_configuration',
          entry.interfaceId
        );
    }
  }
  async restore(
    basename: string,
    validate?: (interfaceId: string, temporaryPath: string) => Promise<void>
  ) {
    const saved = await this.read(basename);
    // Validate the complete manifest before the first write or removal.
    for (const { interfaceId } of saved.interfaces) {
      const target = path.join(this.configDirectory, `${interfaceId}.conf`);
      const existing = await fs
        .lstat(target)
        .catch((error: NodeJS.ErrnoException) => {
          if (error.code === 'ENOENT') return undefined;
          throw error;
        });
      if (
        existing &&
        (!existing.isFile() ||
          existing.isSymbolicLink() ||
          existing.nlink !== 1)
      )
        throw new RoutingPolicyBackupError('non_regular_target');
    }
    for (const { interfaceId, config } of saved.interfaces) {
      const target = path.join(this.configDirectory, `${interfaceId}.conf`);
      if (config === null)
        await fs.unlink(target).catch((error: NodeJS.ErrnoException) => {
          if (error.code !== 'ENOENT') throw error;
        });
      else {
        try {
          await atomicWriteFile(
            target,
            config,
            (temporary) =>
              validate?.(interfaceId, temporary) ?? Promise.resolve()
          );
        } catch {
          throw new RoutingPolicyBackupError('restore_failed', interfaceId);
        }
      }
    }
    await syncDirectory(this.configDirectory);
  }
  async remove(basename: string) {
    await this.read(basename);
    await fs.unlink(this.reference(basename));
    await syncDirectory(this.directory);
  }
  /** Unknown files are left alone; only explicitly marked valid backups qualify. */
  async cleanupOrphans(retained: ReadonlySet<string>) {
    await this.ownedDirectory();
    let removed = 0;
    for (const basename of await fs.readdir(this.directory)) {
      if (!BASENAME.test(basename) || retained.has(basename)) continue;
      try {
        await this.read(basename);
      } catch {
        continue;
      }
      await fs.unlink(this.reference(basename));
      removed++;
    }
    if (removed) await syncDirectory(this.directory);
    return removed;
  }
}
