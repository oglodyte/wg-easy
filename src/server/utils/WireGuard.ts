import fs from 'node:fs/promises';

import { createDebug } from 'obug';

import Database from '#server/utils/Database';
import {
  RuntimeReconciler,
  runIsolatedInterfaceOperations,
} from '#server/utils/RuntimeReconciler';
import { atomicWriteFile } from '#server/utils/atomicFile';
import { mergeClientStatuses } from '#server/utils/clientStatus';
import { OLD_ENV, WG_ENV } from '#server/utils/config';
import { firewall } from '#server/utils/firewall';
import { encodeQRCode } from '#server/utils/qr';
import type { ID } from '#server/utils/types';
import { wg } from '#server/utils/wgHelper';
import { setIntervalImmediately } from '#shared/utils/time';
import type {
  ConfigFormat,
  InterfaceChangeImpact,
  InterfaceRuntimeAction,
  MutationResult,
} from '#shared/types/runtime';
import type { ClientQueryType } from '#db/repositories/client/types';
import type { InterfaceType } from '#db/repositories/interface/types';
import { getSafeRuntimeErrorMessage } from '#db/repositories/runtime/service';

const WG_DEBUG = createDebug('WireGuard');

const generateRandomHeaderValue = () =>
  Math.floor(Math.random() * 2147483642) + 5;

type ReconcileRequest = {
  reasons: readonly string[];
  impacts: readonly InterfaceChangeImpact[];
};

type InterfaceDump = Awaited<ReturnType<typeof wg.dump>>[number] & {
  interfaceId: string;
};
type FirewallState = Parameters<typeof firewall.rebuildAllRules>[0][number];

class WireGuard {
  #cronStarted = false;
  #cronTimer?: ReturnType<typeof setInterval>;
  #reconciler = new RuntimeReconciler((request) => this.#reconcile(request));

  requestReconcile(
    reason: string,
    impacts: readonly InterfaceChangeImpact[] = []
  ) {
    return this.#reconciler.requestReconcile(reason, impacts);
  }

  async saveConfig(interfaceId?: string) {
    const target = interfaceId ?? (await Database.interfaces.getDefault()).name;
    return this.requestReconcile('save-interface-config', [
      { interfaceId: target, action: 'sync' },
    ]);
  }

  async saveAllConfigs() {
    const interfaces = await Database.interfaces.getAll();
    return this.requestReconcile(
      'save-all-interface-configs',
      interfaces.map(({ name }) => ({ interfaceId: name, action: 'sync' }))
    );
  }

  async saveAffectedConfigs({
    interfaceIds = [],
    clientIds = [],
  }: {
    interfaceIds?: readonly string[];
    clientIds?: readonly ID[];
  }) {
    const affected = new Set(interfaceIds);
    for (const clientId of clientIds) {
      const client = await Database.clients.get(clientId);
      if (client) affected.add(client.interfaceId);
    }
    return this.requestReconcile(
      'save-affected-interface-configs',
      [...affected].map((interfaceId) => ({ interfaceId, action: 'sync' }))
    );
  }

  async startupInterface(interfaceId: string) {
    return this.requestReconcile('startup-interface', [
      { interfaceId, action: 'up' },
    ]);
  }

  async startupAll() {
    const interfaces = await Database.interfaces.getAll();
    const result = await this.requestReconcile(
      'startup-all-interfaces',
      interfaces.map(({ name, enabled }) => ({
        interfaceId: name,
        action: enabled ? 'up' : 'down',
      }))
    );
    this.startCronJob();
    return result;
  }

  async shutdownInterface(interfaceId: string) {
    return this.requestReconcile('shutdown-interface', [
      { interfaceId, action: 'down' },
    ]);
  }

  async restart(interfaceId: string) {
    return this.requestReconcile('restart-interface', [
      { interfaceId, action: 'restart' },
    ]);
  }

  async dumpInterface(interfaceId: string): Promise<InterfaceDump[]> {
    const dump = await wg.dump(interfaceId);
    return dump.map((status) => ({ ...status, interfaceId }));
  }

  async dumpAll() {
    const interfaces = (await Database.interfaces.getAll()).filter(
      ({ enabled, pendingDelete }) => enabled && !pendingDelete
    );
    const results = await Promise.all(
      interfaces.map(async ({ name }) => {
        try {
          return {
            interfaceId: name,
            statuses: await this.dumpInterface(name),
          };
        } catch (error) {
          WG_DEBUG(`Dump failed for interface ${name}`);
          return {
            interfaceId: name,
            statuses: [] as InterfaceDump[],
            error: error instanceof Error ? error.message : String(error),
          };
        }
      })
    );

    return {
      statuses: results.flatMap(({ statuses }) => statuses),
      failures: results.flatMap(({ interfaceId, error }) =>
        error ? [{ interfaceId, error }] : []
      ),
    };
  }

  async getClientsForUser(userId: ID, query: ClientQueryType) {
    const clients = (await Database.clients.getAllForUser(userId, query)).map(
      (client) => ({
        ...client,
        latestHandshakeAt: null as Date | null,
        endpoint: null as string | null,
        transferRx: null as number | null,
        transferTx: null as number | null,
      })
    );
    const dump = await this.dumpAll();
    return mergeClientStatuses(clients, dump.statuses);
  }

  async dumpClient(interfaceId: string, publicKey: string) {
    try {
      const dump = await this.dumpInterface(interfaceId);
      return dump.find(
        (status) =>
          status.interfaceId === interfaceId && status.publicKey === publicKey
      );
    } catch {
      WG_DEBUG(`Client status dump failed for interface ${interfaceId}`);
      return undefined;
    }
  }

  async getAllClients(query: ClientQueryType = {}) {
    const clients = (await Database.clients.getAllPublic(query)).map(
      (client) => ({
        ...client,
        latestHandshakeAt: null as Date | null,
        endpoint: null as string | null,
        transferRx: null as number | null,
        transferTx: null as number | null,
      })
    );
    const dump = await this.dumpAll();
    return mergeClientStatuses(clients, dump.statuses);
  }

  async getClientConfiguration({
    clientId,
    format = 'auto',
  }: {
    clientId: ID;
    format?: ConfigFormat;
  }) {
    const client = await Database.clients.get(clientId);
    if (!client) throw new Error('Client not found');

    const [wgInterface, userConfig] = await Promise.all([
      Database.interfaces.getByName(client.interfaceId),
      Database.userConfigs.get(client.interfaceId),
    ]);

    return wg.generateClientConfig(wgInterface, userConfig, client, {
      enableIpv6: !WG_ENV.DISABLE_IPV6,
      format,
    });
  }

  async getClientQRCodeSVG({
    clientId,
    format = 'auto',
  }: {
    clientId: ID;
    format?: ConfigFormat;
  }) {
    const config = await this.getClientConfiguration({ clientId, format });
    return encodeQRCode(config);
  }

  cleanClientFilename(name: string): string {
    return name
      .replace(/[^a-zA-Z0-9_=+.-]/g, '-')
      .replace(/(-{2,}|-$)/g, '-')
      .replace(/-$/, '')
      .substring(0, 32);
  }

  async getRuntimeSnapshot() {
    const [global, interfaces] = await Promise.all([
      Database.runtime.getGlobal(),
      Database.runtime.getAllInterfaces(),
    ]);
    return { global, interfaces };
  }

  async Startup() {
    WG_DEBUG('Starting managed AWG interfaces...');
    const result = await this.startupAll();
    if (result.runtime.status === 'degraded') {
      console.error(
        `One or more managed interfaces failed to start: ${result.runtime.error}`
      );
    }
  }

  startCronJob() {
    if (this.#cronStarted) return;
    this.#cronStarted = true;
    this.#cronTimer = setIntervalImmediately(() => {
      this.cronJob().catch((error) => {
        WG_DEBUG('Running Cron Job failed.');
        console.error(error);
      });
    }, 60 * 1000);
  }

  async Shutdown() {
    if (this.#cronTimer) clearInterval(this.#cronTimer);
    await this.#reconciler.stop();
    const [interfaces, runtimeStates] = await Promise.all([
      Database.interfaces.getAll(),
      Database.runtime.getAllInterfaces(),
    ]);
    const observed = new Map(
      runtimeStates.map((state) => [state.interfaceId, state.observedUp])
    );
    for (const wgInterface of interfaces) {
      if (!observed.get(wgInterface.name)) continue;
      try {
        await this.#downInterface(wgInterface.name);
        await Database.runtime.markInterfaceApplied(wgInterface.name, false);
      } catch (error) {
        const stillUp = await wg.interfaceExists(wgInterface.name);
        await Database.runtime.markInterfaceFailed(
          wgInterface.name,
          error,
          stillUp
        );
        console.error(`Failed to stop interface ${wgInterface.name}`, error);
      }
    }
  }

  async Restart(interfaceId?: string) {
    const target = interfaceId ?? (await Database.interfaces.getDefault()).name;
    return this.restart(target);
  }

  async cronJob() {
    const clients = await Database.clients.getAll();
    const affectedInterfaces = new Set<string>();

    for (const client of clients) {
      if (
        client.enabled &&
        client.expiresAt !== null &&
        new Date() > new Date(client.expiresAt)
      ) {
        WG_DEBUG(`Client ${client.id} on ${client.interfaceId} expired.`);
        await Database.clients.toggle(client.id, false);
        affectedInterfaces.add(client.interfaceId);
      }
    }

    for (const client of clients) {
      if (
        client.oneTimeLink !== null &&
        new Date() > new Date(client.oneTimeLink.expiresAt)
      ) {
        WG_DEBUG(`OneTimeLink for Client ${client.id} expired.`);
        await Database.oneTimeLinks.delete(client.id);
      }
    }

    if (affectedInterfaces.size > 0) {
      await this.requestReconcile(
        'expire-clients',
        [...affectedInterfaces].map((interfaceId) => ({
          interfaceId,
          action: 'sync',
        }))
      );
    }
  }

  async #reconcile({
    reasons,
    impacts,
  }: ReconcileRequest): Promise<MutationResult> {
    WG_DEBUG(`Reconciling runtime state: ${reasons.join(', ')}`);
    const applyingRevision = await Database.runtime.markApplying();

    // Runtime revisions are captured before desired rows. A concurrent commit
    // can therefore make this pass conservatively under-claim, never claim a
    // revision whose desired interface row was not read by this pass.
    const runtimeStates = await Database.runtime.getAllInterfaces();
    const interfaces = await Database.interfaces.getAll();
    const stateByInterface = new Map(
      runtimeStates.map((state) => [state.interfaceId, state])
    );
    const actionByInterface = new Map(
      impacts.map(({ interfaceId, action }) => [interfaceId, action])
    );
    const failureDetails: string[] = [];
    const failedScopes: string[] = [];

    const interfaceFailures = await runIsolatedInterfaceOperations(
      interfaces,
      ({ name }) => name,
      async (wgInterface) => {
        const runtimeState = stateByInterface.get(wgInterface.name);
        if (!runtimeState) {
          throw new Error('runtime state is missing');
        }

        let action = actionByInterface.get(wgInterface.name) ?? 'none';
        if (wgInterface.pendingDelete || !wgInterface.enabled) {
          action = runtimeState.observedUp ? 'down' : 'none';
        } else if (action === 'down') {
          // A newer desired state enabled the interface; fresh state wins over a
          // stale queued down request.
          action = 'up';
        } else if (!runtimeState.observedUp) {
          action = 'up';
        } else if (runtimeState.restartRequired) {
          action = 'restart';
        } else if (
          action === 'none' &&
          !actionByInterface.has(wgInterface.name) &&
          runtimeState.desiredRevision > runtimeState.appliedRevision
        ) {
          // A persisted mutation may outlive the request that originally
          // carried its impact (for example after a process interruption).
          // Without a durable impact kind, restart is the safe recovery.
          action = 'restart';
        }

        await this.#applyInterface(
          wgInterface,
          action,
          runtimeState.observedUp,
          runtimeState.desiredRevision
        );
      }
    );
    for (const { interfaceId, error } of interfaceFailures) {
      const message = getSafeRuntimeErrorMessage(error);
      failureDetails.push(`${interfaceId}: ${message}`);
      failedScopes.push(interfaceId);
      const stillUp = await wg.interfaceExists(interfaceId);
      await Database.runtime.markInterfaceFailed(interfaceId, error, stillUp);
    }

    let firewallStates: FirewallState[] = [];
    try {
      firewallStates = await this.#getFirewallStates();
      await firewall.rebuildAllRules(firewallStates, !WG_ENV.DISABLE_IPV6);
    } catch (error) {
      failureDetails.push(`firewall: ${getSafeRuntimeErrorMessage(error)}`);
      failedScopes.push('firewall');
      for (const { wgInterface, observedUp } of firewallStates) {
        if (observedUp && wgInterface.enabled && wgInterface.firewallEnabled) {
          await Database.runtime.markInterfaceFailed(
            wgInterface.name,
            error,
            true,
            false
          );
        }
      }
    }

    if (failureDetails.length > 0) {
      const state = await Database.runtime.markGlobalFailed(
        new Error(failureDetails.join('; '))
      );
      return {
        success: true,
        revision: applyingRevision,
        runtime: {
          status: 'degraded',
          appliedRevision: state.appliedRevision,
          error: `Runtime reconciliation failed for: ${failedScopes.join(', ')}`,
        },
      };
    }

    const state = await Database.runtime.markGlobalApplied(applyingRevision);
    return {
      success: true,
      revision: applyingRevision,
      runtime: {
        status:
          state.desiredRevision > state.appliedRevision ? 'pending' : 'applied',
        appliedRevision: state.appliedRevision,
      },
    };
  }

  async #applyInterface(
    wgInterface: InterfaceType,
    action: InterfaceRuntimeAction,
    observedUp: boolean,
    appliedRevision: number
  ) {
    if (wgInterface.pendingDelete || !wgInterface.enabled) {
      if (observedUp || action === 'down') {
        await Database.runtime.markInterfaceApplying(
          wgInterface.name,
          'stopping'
        );
        await this.#downInterface(wgInterface.name);
      }
      await Database.runtime.markInterfaceApplied(
        wgInterface.name,
        false,
        appliedRevision
      );
      if (wgInterface.pendingDelete) {
        await firewall.removeInterfaceJump(
          wgInterface.name,
          !WG_ENV.DISABLE_IPV6
        );
        await fs
          .unlink(`/etc/wireguard/${wgInterface.name}.conf`)
          .catch((error: NodeJS.ErrnoException) => {
            if (error.code !== 'ENOENT') throw error;
          });
        await Database.interfaces.finalizeDelete(wgInterface.name);
      }
      return;
    }

    if (wgInterface.defaultConfigFormat === 'migration_pending') {
      throw new Error(
        'compatibility migration requires an explicit legacy backend setting'
      );
    }

    const prepared = await this.#prepareInterface(wgInterface);
    if (action === 'none' && observedUp) {
      await Database.runtime.markInterfaceApplied(
        prepared.name,
        true,
        appliedRevision
      );
      return;
    }

    await this.#saveInterfaceConfig(prepared);

    if (action === 'sync' && observedUp) {
      await wg.sync(prepared.name);
    } else {
      await Database.runtime.markInterfaceApplying(prepared.name, 'starting');
      await this.#downInterface(prepared.name);
      await wg.up(prepared.name);
      await wg.sync(prepared.name);
    }

    await Database.runtime.markInterfaceApplied(
      prepared.name,
      true,
      appliedRevision
    );
  }

  async #downInterface(interfaceId: string) {
    if (!(await wg.interfaceExists(interfaceId))) return;

    const awgError = await wg.down(interfaceId).then(
      () => undefined,
      (error) => error
    );
    if (!(await wg.interfaceExists(interfaceId))) return;

    // Phase 3 is the one-time runtime transition from the accepted legacy
    // WireGuard backend to AWG compatibility mode. The fallback is used only
    // when an exact managed device still exists after awg-quick down.
    await wg.downLegacy(interfaceId).catch((legacyError) => {
      throw new AggregateError(
        [awgError, legacyError].filter((error) => error !== undefined),
        `Failed to stop managed interface ${interfaceId}`
      );
    });
    if (await wg.interfaceExists(interfaceId)) {
      throw new Error(
        `Managed interface ${interfaceId} remained up after down`
      );
    }
  }

  async #prepareInterface(wgInterface: InterfaceType) {
    if (
      wgInterface.privateKey === '---default---' &&
      wgInterface.publicKey === '---default---'
    ) {
      const privateKey = await wg.generatePrivateKey();
      const publicKey = await wg.getPublicKey(privateKey);
      await Database.interfaces.updateKeyPair(
        wgInterface.name,
        privateKey,
        publicKey
      );
      wgInterface = await Database.interfaces.getByName(wgInterface.name);
    }

    if (wgInterface.awgParametersEnabled && wgInterface.h1 === '0') {
      const headers = new Set<number>();
      while (headers.size < 4) headers.add(generateRandomHeaderValue());
      const [h1, h2, h3, h4] = [...headers];
      await Database.interfaces.updateAwgHeaders(wgInterface.name, {
        h1: String(h1),
        h2: String(h2),
        h3: String(h3),
        h4: String(h4),
      });
      wgInterface = await Database.interfaces.getByName(wgInterface.name);
    }

    return wgInterface;
  }

  async #saveInterfaceConfig(wgInterface: InterfaceType) {
    const [clients, hooks] = await Promise.all([
      Database.clients.getAllForInterface(wgInterface.name),
      Database.hooks.get(wgInterface.name),
    ]);
    const sections = [
      wg.generateServerInterface(wgInterface, hooks, {
        enableIpv6: !WG_ENV.DISABLE_IPV6,
      }),
      ...clients
        .filter(({ enabled }) => enabled)
        .map((client) =>
          wg.generateServerPeer(client, {
            enableIpv6: !WG_ENV.DISABLE_IPV6,
          })
        ),
      '',
    ];
    await atomicWriteFile(
      `/etc/wireguard/${wgInterface.name}.conf`,
      sections.join('\n\n'),
      (temporaryPath) => wg.validateConfig(temporaryPath)
    );
  }

  async #getFirewallStates() {
    const [interfaces, runtimeStates] = await Promise.all([
      Database.interfaces.getAll(),
      Database.runtime.getAllInterfaces(),
    ]);
    const observed = new Map(
      runtimeStates.map((state) => [state.interfaceId, state.observedUp])
    );
    return Promise.all(
      interfaces.map(async (wgInterface) => ({
        wgInterface,
        observedUp: observed.get(wgInterface.name) === true,
        clients: await Database.clients.getAllForInterface(wgInterface.name),
        userConfig: await Database.userConfigs.get(wgInterface.name),
      }))
    );
  }
}

if (OLD_ENV.PASSWORD || OLD_ENV.PASSWORD_HASH) {
  throw new Error(
    `
You are using an invalid Configuration for wg-easy
Please follow the instructions on https://wg-easy.github.io/wg-easy/latest/advanced/migrate/from-14-to-15/ to migrate
`
  );
}

export default new WireGuard();
