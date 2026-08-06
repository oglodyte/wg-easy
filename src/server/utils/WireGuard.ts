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
import {
  buildRoutingPlan,
  buildSafetyRoutingPlan,
  evaluateExitReadiness,
  selectActiveExit,
  type ExitCandidateObservation,
  type ExitSelectionResult,
  type RoutingPlan,
} from '#server/utils/routing';
import { RoutingExecutor } from '#server/utils/routingExecutor';
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
type RoutingPlannerSnapshot = Awaited<
  ReturnType<typeof Database.routingGroups.getPlannerSnapshot>
>;
type RoutingEvaluation = {
  snapshot: RoutingPlannerSnapshot;
  dump: {
    statuses: InterfaceDump[];
    failures: { interfaceId: string; error: string }[];
  };
  evaluations: Array<{
    groupId: number;
    selection: ExitSelectionResult;
  }>;
  plan: RoutingPlan;
  now: Date;
};

class WireGuard {
  #cronStarted = false;
  #cronTimer?: ReturnType<typeof setInterval>;
  #routingHealthTimer?: ReturnType<typeof setInterval>;
  #routingBootstrapped = false;
  #lastSafeRoutingPlan?: RoutingPlan;
  #exitHealthySince = new Map<string, Date>();
  #routingExecutor = new RoutingExecutor();
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
    await this.startRoutingHealthMonitor();
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

  async startRoutingHealthMonitor() {
    if (this.#routingHealthTimer) return;
    const { settings } = await Database.routingGroups.getPlannerSnapshot();
    this.#routingHealthTimer = setInterval(() => {
      this.requestReconcile('routing-health-check').catch((error) => {
        WG_DEBUG('Routing health reconciliation failed.');
        console.error(error);
      });
    }, settings.healthCheckIntervalSeconds * 1000);
  }

  async Shutdown() {
    if (this.#cronTimer) clearInterval(this.#cronTimer);
    if (this.#routingHealthTimer) clearInterval(this.#routingHealthTimer);
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

  async #evaluateRouting({
    bootstrap = false,
  } = {}): Promise<RoutingEvaluation> {
    const now = new Date();
    const [snapshot, dump] = await Promise.all([
      Database.routingGroups.getPlannerSnapshot(),
      bootstrap
        ? Promise.resolve({ statuses: [], failures: [] })
        : this.dumpAll(),
    ]);
    const interfaceById = new Map(
      snapshot.interfaces.map((wgInterface) => [
        wgInterface.interfaceId,
        wgInterface,
      ])
    );
    const clientById = new Map(
      snapshot.clients.map((client) => [client.id, client])
    );
    const statusByPeer = new Map(
      dump.statuses.map((status) => [
        `${status.interfaceId}\u0000${status.publicKey}`,
        status,
      ])
    );
    const evaluations: Array<{
      groupId: number;
      selection: ExitSelectionResult;
    }> = [];

    const groups = snapshot.groups.map((group) => {
      if (!group.enabled || group.runtime?.status === 'draft_invalid') {
        return { ...group, enabled: false, selectedExitClientId: null };
      }
      if (bootstrap) {
        return { ...group, selectedExitClientId: null };
      }

      const candidates = group.exits.map((exit) => {
        const client = clientById.get(exit.clientId);
        if (!client) throw new Error(`Routing exit ${exit.clientId} not found`);
        const wgInterface = interfaceById.get(client.interfaceId);
        if (!wgInterface) {
          throw new Error(
            `Routing exit interface ${client.interfaceId} not found`
          );
        }
        const status = statusByPeer.get(
          `${client.interfaceId}\u0000${client.publicKey}`
        );
        const observation: ExitCandidateObservation = {
          clientId: client.id,
          priority: exit.priority,
          candidateEnabled: exit.enabled,
          clientEnabled: client.enabled,
          interfaceEnabled: wgInterface.enabled,
          interfaceObservedUp:
            wgInterface.observedUp && wgInterface.runtimeStatus === 'up',
          persistentKeepalive: client.persistentKeepalive,
          latestHandshakeAt: status?.latestHandshakeAt ?? null,
          endpoint: status?.endpoint ?? null,
        };
        const key = `${group.id}:${client.id}`;
        if (
          evaluateExitReadiness(observation, snapshot.settings, now)
            .observedHealthy
        ) {
          if (!this.#exitHealthySince.has(key)) {
            this.#exitHealthySince.set(key, now);
          }
        } else {
          this.#exitHealthySince.delete(key);
        }
        return {
          ...observation,
          healthySince: this.#exitHealthySince.get(key) ?? null,
        };
      });
      const selection = selectActiveExit({
        candidates,
        current: {
          selectedExitClientId: group.runtime?.selectedExitClientId ?? null,
          selectedSince: group.runtime?.selectedSince
            ? new Date(group.runtime.selectedSince)
            : null,
        },
        settings: snapshot.settings,
        now,
      });
      evaluations.push({ groupId: group.id, selection });
      return { ...group, selectedExitClientId: selection.selectedExitClientId };
    });

    const plan = buildRoutingPlan({
      interfaces: snapshot.interfaces.map((wgInterface) => ({
        ...wgInterface,
        observedUp: bootstrap ? wgInterface.enabled : wgInterface.observedUp,
      })),
      clients: snapshot.clients,
      groups,
    });
    return { snapshot, dump, evaluations, plan, now };
  }

  async #recordRoutingSelections(
    evaluation: RoutingEvaluation,
    revision: number
  ) {
    const evaluationByGroup = new Map(
      evaluation.evaluations.map((item) => [item.groupId, item.selection])
    );
    await Database.routingGroups.updateRuntimeStates(
      evaluation.snapshot.groups.map((group) => {
        const selection = evaluationByGroup.get(group.id);
        const selectedExitClientId = selection?.selectedExitClientId ?? null;
        const selectionChanged =
          selectedExitClientId !==
          (group.runtime?.selectedExitClientId ?? null);
        return {
          groupId: group.id,
          state: {
            selectedExitClientId,
            evaluatedRevision: revision,
            selectedSince: selectedExitClientId
              ? selectionChanged
                ? evaluation.now.toISOString()
                : (group.runtime?.selectedSince ?? evaluation.now.toISOString())
              : null,
            lastEvaluatedAt: evaluation.now.toISOString(),
            lastFailoverAt: selectionChanged
              ? evaluation.now.toISOString()
              : group.runtime?.lastFailoverAt,
            status: group.enabled
              ? selectedExitClientId
                ? ('selected_pending' as const)
                : ('awaiting_exit' as const)
              : ('disabled' as const),
            reason: group.enabled
              ? (selection?.reason ?? 'no healthy exit candidate')
              : null,
          },
        };
      })
    );
  }

  async #markRoutingApplied(evaluation: RoutingEvaluation, revision: number) {
    const groupById = new Map(
      evaluation.snapshot.groups.map((group) => [group.id, group])
    );
    await Database.routingGroups.updateRuntimeStates(
      evaluation.plan.groups.map((groupPlan) => {
        const group = groupById.get(groupPlan.groupId)!;
        const previous = group.runtime;
        const active = groupPlan.outcome === 'selected_exit';
        return {
          groupId: groupPlan.groupId,
          state: {
            appliedExitClientId: active ? groupPlan.selectedExitClientId : null,
            appliedRevision: revision,
            appliedSince:
              active &&
              previous?.appliedExitClientId === groupPlan.selectedExitClientId
                ? (previous.appliedSince ?? evaluation.now.toISOString())
                : active
                  ? evaluation.now.toISOString()
                  : null,
            status:
              groupPlan.outcome === 'selected_exit'
                ? ('active' as const)
                : groupPlan.outcome === 'block'
                  ? ('blocked' as const)
                  : groupPlan.outcome === 'host'
                    ? ('host_fallback' as const)
                    : ('disabled' as const),
            reason:
              groupPlan.outcome === 'selected_exit'
                ? 'selected exit and Linux policy verified'
                : groupPlan.outcome === 'block'
                  ? 'all exits are down; matching traffic is blocked'
                  : groupPlan.outcome === 'host'
                    ? 'all exits are down; host routing fallback is active'
                    : null,
          },
        };
      })
    );
  }

  async #markRoutingFailed(evaluation: RoutingEvaluation, error: unknown) {
    const reason = getSafeRuntimeErrorMessage(error);
    await Database.routingGroups.updateRuntimeStates(
      evaluation.snapshot.groups.map((group) => ({
        groupId: group.id,
        state: {
          status: group.enabled ? ('degraded' as const) : ('disabled' as const),
          reason: group.enabled ? reason : null,
        },
      }))
    );
  }

  #peerPrefixes(plan: RoutingPlan) {
    return new Map(
      plan.peerAllowedIps.map(({ clientId, prefixes }) => [clientId, prefixes])
    );
  }

  #routingPlansEqual(left: RoutingPlan, right?: RoutingPlan) {
    return (
      right !== undefined && JSON.stringify(left) === JSON.stringify(right)
    );
  }

  async #syncRoutingPeerConfigs(target: RoutingPlan, previous?: RoutingPlan) {
    const targetPrefixes = this.#peerPrefixes(target);
    const previousPrefixes = previous
      ? this.#peerPrefixes(previous)
      : new Map<number, string[]>();
    const changedClients = new Set<number>();
    for (const clientId of new Set([
      ...targetPrefixes.keys(),
      ...previousPrefixes.keys(),
    ])) {
      if (
        JSON.stringify(targetPrefixes.get(clientId) ?? []) !==
        JSON.stringify(previousPrefixes.get(clientId) ?? [])
      ) {
        changedClients.add(clientId);
      }
    }
    if (changedClients.size === 0) return;

    const clients = await Database.clients.getAll();
    const affectedInterfaces = new Set(
      clients
        .filter(({ id }) => changedClients.has(id))
        .map(({ interfaceId }) => interfaceId)
    );
    const runtimeByInterface = new Map(
      (await Database.runtime.getAllInterfaces()).map((runtime) => [
        runtime.interfaceId,
        runtime,
      ])
    );
    for (const interfaceId of affectedInterfaces) {
      const wgInterface = await Database.interfaces.getByName(interfaceId);
      if (!wgInterface.enabled || wgInterface.pendingDelete) continue;
      await this.#saveInterfaceConfig(wgInterface, targetPrefixes);
      if (runtimeByInterface.get(interfaceId)?.observedUp) {
        await wg.sync(interfaceId);
      }
    }
  }

  async #verifyRoutingPeerConfigs(target: RoutingPlan, previous?: RoutingPlan) {
    const targetPrefixes = this.#peerPrefixes(target);
    const previousPrefixes = previous
      ? this.#peerPrefixes(previous)
      : new Map<number, string[]>();
    const relevantClientIds = new Set([
      ...targetPrefixes.keys(),
      ...previousPrefixes.keys(),
    ]);
    if (relevantClientIds.size === 0) return;

    const clients = await Database.clients.getAll();
    const clientById = new Map(clients.map((client) => [client.id, client]));
    const relevantPrefixes = new Set([
      ...targetPrefixes.values().flatMap((prefixes) => prefixes),
      ...previousPrefixes.values().flatMap((prefixes) => prefixes),
    ]);
    const interfaceIds = new Set(
      [...relevantClientIds].flatMap((clientId) => {
        const client = clientById.get(clientId);
        return client ? [client.interfaceId] : [];
      })
    );
    const dumpByInterface = new Map(
      await Promise.all(
        [...interfaceIds].map(
          async (interfaceId) =>
            [interfaceId, await this.dumpInterface(interfaceId)] as const
        )
      )
    );

    for (const clientId of relevantClientIds) {
      const expected = new Set(targetPrefixes.get(clientId) ?? []);
      const client = clientById.get(clientId);
      if (!client) {
        if (expected.size > 0) {
          throw new Error(`Routing exit client ${clientId} no longer exists`);
        }
        continue;
      }
      const peer = dumpByInterface
        .get(client.interfaceId)
        ?.find(({ publicKey }) => publicKey === client.publicKey);
      if (!peer) {
        if (expected.size > 0) {
          throw new Error(
            `Routing exit client ${clientId} is missing from interface ${client.interfaceId}`
          );
        }
        continue;
      }
      const observed = new Set(
        peer.allowedIps
          .split(',')
          .map((prefix) => prefix.trim())
          .filter(Boolean)
      );
      if (
        [...expected].some((prefix) => !observed.has(prefix)) ||
        [...relevantPrefixes].some(
          (prefix) => !expected.has(prefix) && observed.has(prefix)
        )
      ) {
        throw new Error(
          `Routing peer prefixes were not verified for client ${clientId} on interface ${client.interfaceId}`
        );
      }
    }
  }

  async #reconcile({
    reasons,
    impacts,
  }: ReconcileRequest): Promise<MutationResult> {
    WG_DEBUG(`Reconciling runtime state: ${reasons.join(', ')}`);
    const applyingRevision = await Database.runtime.markApplying();

    const hasRoutingState =
      await Database.routingGroups.hasDeferredRoutingState();
    if (!this.#routingBootstrapped) {
      if (!hasRoutingState) {
        this.#routingBootstrapped = true;
      } else {
        const bootstrap = await this.#evaluateRouting({ bootstrap: true });
        const requiresBlockProtection = bootstrap.snapshot.groups.some(
          (group) => group.enabled && group.allExitsDownPolicy === 'block'
        );
        if (requiresBlockProtection) {
          try {
            await this.#routingExecutor.apply(bootstrap.plan, {
              previousPlan: this.#lastSafeRoutingPlan,
            });
            this.#lastSafeRoutingPlan = bootstrap.plan;
          } catch (error) {
            const clientById = new Map(
              bootstrap.snapshot.clients.map((client) => [client.id, client])
            );
            const affectedInterfaces = new Set(
              bootstrap.snapshot.groups
                .filter(
                  (group) =>
                    group.enabled && group.allExitsDownPolicy === 'block'
                )
                .flatMap((group) => group.memberClientIds)
                .flatMap((clientId) => {
                  const client = clientById.get(clientId);
                  return client ? [client.interfaceId] : [];
                })
            );
            for (const interfaceId of affectedInterfaces) {
              await this.#downInterface(interfaceId).catch(() => {});
              await Database.runtime.markInterfaceFailed(
                interfaceId,
                new Error(
                  'Common-routing bootstrap protection could not be installed'
                ),
                false
              );
            }
            await this.#markRoutingFailed(bootstrap, error);
            const state = await Database.runtime.markGlobalFailed(error);
            return {
              success: true,
              revision: applyingRevision,
              runtime: {
                status: 'degraded',
                appliedRevision: state.appliedRevision,
                error: 'Runtime reconciliation failed for: routing-bootstrap',
              },
            };
          }
        }
        this.#routingBootstrapped = true;
      }
    }

    const initialRouting =
      hasRoutingState || this.#lastSafeRoutingPlan
        ? await this.#evaluateRouting()
        : undefined;
    if (initialRouting) {
      const previousByGroup = new Map(
        (this.#lastSafeRoutingPlan?.groups ?? []).map((group) => [
          group.groupId,
          group,
        ])
      );
      const blockGroupIds = new Set(
        initialRouting.plan.groups
          .filter((group) => {
            if (group.outcome === 'disabled') return false;
            const configured = initialRouting.snapshot.groups.find(
              ({ id }) => id === group.groupId
            );
            if (configured?.allExitsDownPolicy !== 'block') return false;
            const previous = previousByGroup.get(group.groupId);
            return (
              !previous ||
              previous.selectedExitClientId !== group.selectedExitClientId
            );
          })
          .map(({ groupId }) => groupId)
      );
      if (blockGroupIds.size > 0) {
        const bootstrap = await this.#evaluateRouting({ bootstrap: true });
        const safetyPlan = buildSafetyRoutingPlan({
          previous: this.#lastSafeRoutingPlan,
          bootstrap: bootstrap.plan,
          blockGroupIds,
        });
        try {
          if (!this.#routingPlansEqual(safetyPlan, this.#lastSafeRoutingPlan)) {
            await this.#routingExecutor.apply(safetyPlan, {
              previousPlan: this.#lastSafeRoutingPlan,
            });
          }
          this.#lastSafeRoutingPlan = safetyPlan;
        } catch (error) {
          const clientById = new Map(
            bootstrap.snapshot.clients.map((client) => [client.id, client])
          );
          const affectedInterfaces = new Set(
            bootstrap.snapshot.groups
              .filter((group) => blockGroupIds.has(group.id))
              .flatMap((group) => group.memberClientIds)
              .flatMap((clientId) => {
                const client = clientById.get(clientId);
                return client ? [client.interfaceId] : [];
              })
          );
          for (const interfaceId of affectedInterfaces) {
            await this.#downInterface(interfaceId).catch(() => {});
            await Database.runtime.markInterfaceFailed(
              interfaceId,
              new Error(
                'Common-routing transition protection could not be installed'
              ),
              false
            );
          }
          await this.#markRoutingFailed(initialRouting, error);
          const state = await Database.runtime.markGlobalFailed(error);
          return {
            success: true,
            revision: applyingRevision,
            runtime: {
              status: 'degraded',
              appliedRevision: state.appliedRevision,
              error:
                'Runtime reconciliation failed for: routing-transition-safety',
            },
          };
        }
      }
    }
    const initialPeerPrefixes = initialRouting
      ? this.#peerPrefixes(initialRouting.plan)
      : new Map<number, string[]>();

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
          runtimeState.desiredRevision,
          initialPeerPrefixes
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

    const finalRouting =
      hasRoutingState || this.#lastSafeRoutingPlan
        ? await this.#evaluateRouting()
        : undefined;
    if (finalRouting) {
      await this.#recordRoutingSelections(finalRouting, applyingRevision);
    }

    let routingPeerConfigFailed = false;
    if (finalRouting) {
      try {
        await this.#syncRoutingPeerConfigs(
          finalRouting.plan,
          this.#lastSafeRoutingPlan
        );
      } catch (error) {
        routingPeerConfigFailed = true;
        failureDetails.push(
          `routing-peer-config: ${getSafeRuntimeErrorMessage(error)}`
        );
        failedScopes.push('routing-peer-config');
        await this.#markRoutingFailed(finalRouting, error);
        if (this.#lastSafeRoutingPlan) {
          await this.#syncRoutingPeerConfigs(
            this.#lastSafeRoutingPlan,
            finalRouting.plan
          ).catch(() => {});
        }
      }
    }

    let firewallStates: FirewallState[] = [];
    let firewallFailed = false;
    try {
      firewallStates = await this.#getFirewallStates();
      await firewall.rebuildAllRules(firewallStates, !WG_ENV.DISABLE_IPV6);
    } catch (error) {
      firewallFailed = true;
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

    if (finalRouting && !routingPeerConfigFailed && !firewallFailed) {
      const previousPlan = this.#lastSafeRoutingPlan;
      let linuxPlanApplied = false;
      try {
        if (!this.#routingPlansEqual(finalRouting.plan, previousPlan)) {
          await this.#routingExecutor.apply(finalRouting.plan, {
            previousPlan,
          });
          linuxPlanApplied = true;
          await this.#verifyRoutingPeerConfigs(finalRouting.plan, previousPlan);
        }
        await this.#markRoutingApplied(finalRouting, applyingRevision);
        await Database.routingGroups.releaseTombstones(applyingRevision);
        this.#lastSafeRoutingPlan = finalRouting.plan;
      } catch (error) {
        failureDetails.push(`routing: ${getSafeRuntimeErrorMessage(error)}`);
        failedScopes.push('routing');
        await this.#markRoutingFailed(finalRouting, error);
        if (linuxPlanApplied && previousPlan) {
          await this.#routingExecutor
            .apply(previousPlan, { previousPlan: finalRouting.plan })
            .catch(() => {});
        }
        if (previousPlan) {
          await this.#syncRoutingPeerConfigs(
            previousPlan,
            finalRouting.plan
          ).catch(() => {});
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
    appliedRevision: number,
    peerPrefixes: ReadonlyMap<number, readonly string[]>
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

    await this.#saveInterfaceConfig(prepared, peerPrefixes);

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

  async #saveInterfaceConfig(
    wgInterface: InterfaceType,
    peerPrefixes: ReadonlyMap<number, readonly string[]> = new Map()
  ) {
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
            additionalAllowedIps: peerPrefixes.get(client.id) ?? [],
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
