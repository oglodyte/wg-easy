import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { execFile, withSecureInputFile } from '#server/utils/cmd';
import {
  parseManagedInterfaceConfig,
  ManagedInterfaceStateError,
  verifyManagedInterfaceState,
  verifyRecoverableManagedInterfaceState,
} from '#server/utils/managedInterfaceState';
import {
  ManagedInterfaceTransitionError,
  type ManagedDeviceObservation,
  type ManagedInterfaceDevices,
} from '#server/utils/managedInterfaceTransition';
import {
  preparePeerSyncConfig,
  verifyPeerSyncPresharedKeys,
} from '#server/utils/peerSyncConfig';
import { InterfaceNameSchema } from '#shared/utils/schemas';

type Runner = typeof execFile;

/** Preserve pinned quick kernel/userspace selection; operator hooks never run. */
export class LinuxManagedInterfaceDevices implements ManagedInterfaceDevices {
  constructor(private readonly run: Runner = execFile) {}

  private async safe<T>(
    interfaceId: string,
    operation: string,
    work: () => Promise<T>
  ) {
    if (!InterfaceNameSchema.safeParse(interfaceId).success)
      throw new ManagedInterfaceTransitionError('invalid_interface');
    try {
      return await work();
    } catch (error) {
      if (error instanceof ManagedInterfaceStateError) throw error;
      throw new ManagedInterfaceTransitionError(operation, interfaceId);
    }
  }
  private async withQuickConfig<T>(
    interfaceId: string,
    config: string,
    work: (file: string) => Promise<T>
  ) {
    parseManagedInterfaceConfig(interfaceId, config);
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'wge-managed-quick-')),
      file = path.join(root, `${interfaceId}.conf`);
    try {
      await fs.chmod(root, 0o700);
      const hookless =
        config
          .split(/\r?\n/)
          .filter(
            (line) => !/^\s*(PreUp|PostUp|PreDown|PostDown)\s*=/i.test(line)
          )
          .join('\n') + '\n';
      await fs.writeFile(file, hookless, { mode: 0o600, flag: 'wx' });
      return await work(file);
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  }
  async observe(interfaceId: string): Promise<ManagedDeviceObservation | null> {
    return this.safe(interfaceId, 'observation_failed', async () => {
      const links = JSON.parse(
        await this.run('ip', ['-d', '-j', 'address', 'show'], { log: false })
      );
      if (!Array.isArray(links)) throw new Error();
      const found = links.filter((link) => link.ifname === interfaceId);
      if (found.length === 0) return null;
      if (
        found.length !== 1 ||
        !['amneziawg', 'tun'].includes(found[0].linkinfo?.info_kind)
      )
        throw new Error();
      const interfaces = (
        await this.run('awg', ['show', 'interfaces'], { log: false })
      )
        .split(/\s+/)
        .filter(Boolean);
      if (!interfaces.includes(interfaceId)) throw new Error();
      return {
        showconf: await this.run('awg', ['showconf', interfaceId], {
          log: false,
        }),
        addresses: JSON.stringify(found),
      };
    });
  }
  async validate(interfaceId: string, config: string) {
    await this.safe(interfaceId, 'configuration_invalid', () =>
      this.withQuickConfig(interfaceId, config, async (file) => {
        await this.run('awg-quick', ['strip', file], { log: false });
      })
    );
  }
  async up(interfaceId: string, config: string) {
    await this.safe(interfaceId, 'start_failed', async () => {
      if (await this.observe(interfaceId)) throw new Error();
      await this.withQuickConfig(interfaceId, config, async (file) => {
        await this.run('awg-quick', ['up', file], { log: false });
      });
      // IPv6 address DAD can briefly outlive quick startup. This is one bounded
      // verification of the operation, not another reconciliation loop.
      for (let attempt = 0; attempt < 30; attempt++) {
        const observed = await this.observe(interfaceId);
        if (!observed) throw new Error();
        try {
          verifyManagedInterfaceState(interfaceId, config, observed);
          return;
        } catch (error) {
          if (attempt === 29) throw error;
        }
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
    });
  }
  async down(interfaceId: string, config: string) {
    await this.safe(interfaceId, 'stop_failed', async () => {
      parseManagedInterfaceConfig(interfaceId, config);
      // Table=off, no DNS/SaveConfig and admitted hooks are handled separately.
      // Avoid quick's pattern-based firewall cleanup of unrelated host rules.
      if (await this.observe(interfaceId))
        await this.run('ip', ['link', 'delete', 'dev', interfaceId], {
          log: false,
        });
      if (await this.observe(interfaceId)) throw new Error();
      // The pinned userspace implementation removes its control socket after
      // TUN deletion. Never unlink it by path or race a replacement process.
      for (let attempt = 0; attempt < 30; attempt++) {
        const remaining = (
          await this.run('awg', ['show', 'interfaces'], { log: false })
        ).split(/\s+/);
        if (!remaining.includes(interfaceId)) return;
        if (attempt === 29) throw new Error();
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
    });
  }
  async sync(interfaceId: string, config: string) {
    await this.safe(interfaceId, 'sync_failed', async () => {
      await this.withQuickConfig(interfaceId, config, async (file) => {
        const stripped = await this.run('awg-quick', ['strip', file], {
          log: false,
        });
        await withSecureInputFile(preparePeerSyncConfig(stripped), (input) =>
          this.run('awg', ['syncconf', interfaceId, input], { log: false })
        );
        verifyPeerSyncPresharedKeys(
          interfaceId,
          config,
          await this.run('awg', ['show', interfaceId, 'preshared-keys'], {
            log: false,
          })
        );
      });
      const observed = await this.observe(interfaceId);
      if (!observed) throw new Error();
      verifyManagedInterfaceState(interfaceId, config, observed);
    });
  }
  async verifyRecoverable(
    interfaceId: string,
    configs: readonly string[],
    allowPartialStart: boolean
  ) {
    await this.safe(interfaceId, 'unknown_device_state', async () => {
      const observed = await this.observe(interfaceId);
      if (observed)
        verifyRecoverableManagedInterfaceState(interfaceId, configs, observed, {
          allowPartialStart,
        });
    });
  }
}
