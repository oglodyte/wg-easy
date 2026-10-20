import fs from 'node:fs/promises';

import type { DBServiceType } from '#db/sqlite';
import type { PrivateDesiredRoutingGeneration } from '#db/repositories/runtime/generationSnapshot';
import { LinuxManagedInterfaceDevices } from '#server/utils/managedInterfaceDevices';
import {
  ManagedInterfaceTransition,
  readManagedInterfaceConfig,
} from '#server/utils/managedInterfaceTransition';
import {
  managedInterfaceRequiresRestart,
  parseManagedInterfaceConfig,
} from '#server/utils/managedInterfaceState';
import { ManagedServerHookEffects } from '#server/utils/managedServerHooks';
import {
  buildRoutingPlan,
  evaluateExitReadiness,
  selectActiveExit,
} from '#server/utils/routing';
import { RoutingExecutor } from '#server/utils/routingExecutor';
import { RoutingGuard } from '#server/utils/routingGuard';
import {
  observeRoutingManagementPaths,
  assertRoutingManagementDestinations,
} from '#server/utils/routingManagementPaths';
import {
  deriveRoutingAvailabilityWithdrawal,
  routingWithdrawalDeviceBaseline,
} from '#server/utils/routingPolicyAvailability';
import { RoutingPolicyBackups } from '#server/utils/routingPolicyBackups';
import { buildPolicyBootstrapBaseline } from '#server/utils/routingPolicyBootstrap';
import {
  cancelPendingBootstrapInNewNamespace,
  rebasePendingRoutingNamespace,
  verifyColdRoutingNamespace,
} from '#server/utils/routingPolicyColdStart';
import { RoutingPolicyFirewall } from '#server/utils/routingPolicyFirewall';
import {
  prepareDesiredRoutingConfigurations,
  specializePrivateRoutingGeneration,
} from '#server/utils/routingPolicyGeneration';
import { RoutingPolicyJournalError } from '#server/utils/routingPolicyJournal';
import { readRoutingKernelNamespace } from '#server/utils/routingPolicyKernelContext';
import {
  publishRoutingPolicyEvidence,
  publishRoutingNamespaceUnavailable,
} from '#server/utils/routingPolicyPublication';
import {
  applyGuardedRoutingPolicy,
  bootstrapPrevious,
  restorePendingRoutingPolicy,
  type PolicyRecoveryDependencies,
} from '#server/utils/routingPolicyRecovery';
import { wg } from '#server/utils/wgHelper';
import type {
  InterfaceChangeImpact,
  MutationResult,
} from '#shared/types/runtime';
import type {
  RoutingPolicyJournal,
  PendingPolicyTransition,
  PolicyBootstrapBaseline,
} from '#shared/types/routingPolicy';

type Provider = Pick<
  DBServiceType,
  'routingGeneration' | 'routingPolicy' | 'runtime' | 'interfaces'
>;
export function createRoutingPolicyApplicationPorts(
  configDirectory = '/etc/wireguard'
) {
  return {
    configDirectory,
    backups: new RoutingPolicyBackups(configDirectory),
    devices: new LinuxManagedInterfaceDevices(),
    hooks: new ManagedServerHookEffects(),
    executor: new RoutingExecutor(),
    guard: new RoutingGuard(),
    firewall: new RoutingPolicyFirewall(),
    namespace: readRoutingKernelNamespace,
    management: observeRoutingManagementPaths,
    dump: wg.dump,
  };
}
type Context = Awaited<ReturnType<RoutingPolicyApplication['context']>>;

/** Finite operations only. The existing RuntimeReconciler is the sole caller. */
export class RoutingPolicyApplication {
  private readonly healthySince = new Map<string, Date>();
  constructor(
    private readonly ports = createRoutingPolicyApplicationPorts(),
    private readonly enableIpv6 = true
  ) {}

  private async context(provider: Provider) {
    const generation =
        await provider.routingGeneration.readPrivateDesiredGeneration(),
      namespaceId = await this.ports.namespace(),
      ids = new Set([
        ...generation.interfaces.map((i) => i.name),
        ...(generation.policy.applied?.plan.interfaces.map(
          (i) => i.interfaceId
        ) ?? []),
        ...(generation.policy.pending?.plan.interfaces.map(
          (i) => i.interfaceId
        ) ?? []),
      ]),
      protectedPaths = await this.ports.management(ids);
    return { generation, namespaceId, protectedPaths };
  }
  private async configurations(ids: readonly string[]) {
    const result = new Map<string, string | null>();
    for (const id of new Set(ids))
      result.set(
        id,
        await readManagedInterfaceConfig(this.ports.configDirectory, id)
      );
    return result;
  }
  private async selections(
    generation: PrivateDesiredRoutingGeneration,
    up: ReadonlySet<string>
  ) {
    const observations = new Map<
      string,
      Awaited<ReturnType<typeof wg.dump>>[number]
    >();
    for (const id of up) {
      try {
        for (const p of await this.ports.dump(id))
          observations.set(`${id}\0${p.publicKey}`, p);
      } catch {
        /* A failed observation makes this interface's exits unready. */
      }
    }
    // Capture time after the observations, never before a potentially slow dump.
    const now = new Date(),
      settings = {
        healthCheckIntervalSeconds:
          generation.settings.routingExitHealthCheckIntervalSeconds,
        healthTimeoutSeconds:
          generation.settings.routingExitHealthTimeoutSeconds,
        minHoldSeconds: generation.settings.routingExitMinHoldSeconds,
        failbackDelaySeconds:
          generation.settings.routingExitFailbackDelaySeconds,
      },
      clients = new Map(generation.clients.map((c) => [c.id, c])),
      interfaces = new Map(generation.interfaces.map((i) => [i.name, i])),
      selections = new Map<number, number | null>();
    for (const group of generation.snapshot.groups) {
      if (!group.enabled) {
        selections.set(group.id, null);
        for (const key of this.healthySince.keys())
          if (key.startsWith(`${group.id}:`)) this.healthySince.delete(key);
        continue;
      }
      const current = generation.groupRuntime.find(
        (r) => r.groupId === group.id
      );
      const candidates = group.exits.map((exit) => {
        const client = clients.get(exit.clientId)!,
          iface = interfaces.get(client.interfaceId)!,
          observed = observations.get(
            `${client.interfaceId}\0${client.publicKey}`
          ),
          observation = {
            clientId: client.id,
            priority: exit.priority,
            candidateEnabled: exit.enabled,
            clientEnabled: client.enabled,
            interfaceEnabled: iface.enabled && !iface.pendingDelete,
            interfaceObservedUp: up.has(iface.name),
            persistentKeepalive: client.persistentKeepalive,
            latestHandshakeAt: observed?.latestHandshakeAt ?? null,
            endpoint: observed?.endpoint ?? null,
          },
          key = `${group.id}:${client.id}`;
        if (evaluateExitReadiness(observation, settings, now).observedHealthy) {
          if (!this.healthySince.has(key)) this.healthySince.set(key, now);
        } else this.healthySince.delete(key);
        return {
          ...observation,
          healthySince: this.healthySince.get(key) ?? null,
        };
      });
      selections.set(
        group.id,
        selectActiveExit({
          candidates,
          current: {
            selectedExitClientId: current?.selectedExitClientId ?? null,
            selectedSince: current?.selectedSince
              ? new Date(current.selectedSince)
              : null,
          },
          settings,
          now,
        }).selectedExitClientId
      );
    }
    return selections;
  }

  private dependencies(
    provider: Provider,
    context: Context,
    previous: RoutingPolicyJournal,
    target: RoutingPolicyJournal,
    transition: ManagedInterfaceTransition,
    {
      allowAbsent = false,
      configurationApplied = false,
      failures = new Map<string, string>(),
    } = {}
  ): PolicyRecoveryDependencies {
    const ports = this.ports,
      known = [previous.plan.clientFirewall, target.plan.clientFirewall],
      verify = (guard: Parameters<RoutingGuard['verify']>[0]) =>
        ports.guard.verify(guard);
    return {
      ...ports,
      journal: provider.routingPolicy,
      protectedPaths: context.protectedPaths,
      candidateConfigurations: transition.candidateConfigurations,
      previousConfigurations: transition.previousConfigurations,
      lifecycleIntent: transition.intent,
      preflightManagedState: async () => {
        assertRoutingManagementDestinations(
          target.plan,
          context.protectedPaths
        );
        await ports.firewall.prepare(target.plan.clientFirewall, known, null, {
          allowAbsent,
        });
      },
      applyManagedState: async (_plan, guard) => {
        await transition.apply(() => verify(guard));
        await ports.firewall.apply(target.plan.clientFirewall, known, guard, {
          allowAbsent,
        });
      },
      beforeRestoreManagedState: async (_previous, _target, _backup, guard) =>
        transition.beforeRestore(() => verify(guard)),
      restoreManagedState: async (_previous, _backup, guard) => {
        await transition.restorePrevious(() => verify(guard));
        await ports.firewall.apply(previous.plan.clientFirewall, known, guard, {
          allowAbsent,
        });
      },
      completeWithdrawalManagedState: async (_previous, pending, guard) => {
        const baseline = routingWithdrawalDeviceBaseline(previous, pending),
          reopened = await ManagedInterfaceTransition.reopen(
            ports,
            pending.backupBasenames[0]!,
            baseline.plan,
            pending.plan
          );
        await reopened.completeWithdrawal(() => verify(guard));
        await ports.firewall.apply(pending.plan.clientFirewall, known, guard, {
          allowAbsent,
        });
      },
      verifyManagedState: async (plan, guard, configuration) => {
        await transition.verify(configuration);
        await ports.firewall.verify(plan.clientFirewall, guard, {
          inspectIpv6: known.some((p) => p.enableIpv6),
        });
        await ports.guard.verify(guard, { families: [4, 6] });
      },
      validateConfig: async (id, file) =>
        ports.devices.validate(id, await fs.readFile(file, 'utf8')),
      publishGroups: async (tx, record, restored) =>
        publishRoutingPolicyEvidence(tx, record, {
          generation: context.generation,
          failures,
          configurationApplied: configurationApplied && !restored,
        }),
    };
  }

  /** Called before even the temporary v1 startup path. */
  async recover(provider: Provider) {
    let context = await this.context(provider);
    if (!context.generation.policy.pending) return;
    const cold = {
      ...this.ports,
      journal: provider.routingPolicy,
      protectedPaths: context.protectedPaths,
    };
    if (
      context.generation.policy.pending.plan.namespaceId !== context.namespaceId
    ) {
      if (context.generation.policy.version === 1) {
        await cancelPendingBootstrapInNewNamespace(
          cold,
          context.namespaceId,
          publishRoutingNamespaceUnavailable
        );
        return;
      }
      await rebasePendingRoutingNamespace(cold, context.namespaceId);
      context = await this.context(provider);
    }
    const pending = context.generation.policy.pending!,
      previous =
        context.generation.policy.applied ??
        bootstrapPrevious(pending, pending.bootstrap!),
      baseline = pending.withdrawal
        ? routingWithdrawalDeviceBaseline(previous, pending)
        : previous,
      transition = await ManagedInterfaceTransition.reopen(
        this.ports,
        pending.backupBasenames[0]!,
        baseline.plan,
        pending.plan
      ),
      result = await restorePendingRoutingPolicy(
        this.dependencies(provider, context, previous, pending, transition, {
          allowAbsent: !!pending.withdrawal?.resetNamespace,
        })
      );
    if (result.status === 'failed')
      throw new RoutingPolicyJournalError(result.errorCode);
  }

  /** Promotion is permitted only after the caller's normal v1 pass converges. */
  async promote(provider: Provider) {
    const context = await this.context(provider),
      g = context.generation;
    if (
      g.policy.version !== 1 ||
      g.policy.pending ||
      g.policy.runtime.desiredRevision !== g.policy.runtime.appliedRevision
    )
      return;
    if (
      g.interfaceRuntime.some(
        (i) =>
          i.appliedRevision !== i.desiredRevision ||
          i.restartRequired ||
          i.lastError !== null
      )
    )
      return;
    const files = await this.configurations(
        g.interfaces.filter((i) => !i.pendingDelete).map((i) => i.name)
      ),
      prepared = prepareDesiredRoutingConfigurations(g, files, this.enableIpv6);
    if (prepared.failures.size)
      throw new RoutingPolicyJournalError(
        'bootstrap_configuration_unavailable'
      );
    const up = new Set(
        g.interfaces
          .filter((i) => i.enabled && !i.pendingDelete)
          .map((i) => i.name)
      ),
      target = specializePrivateRoutingGeneration(g, prepared, {
        upInterfaceIds: up,
        hooksAppliedInterfaceIds: up,
        namespaceId: context.namespaceId,
        enableIpv6: this.enableIpv6,
        selectedExitClientIds: new Map(
          g.groupRuntime.map((r) => [r.groupId, r.appliedExitClientId])
        ),
      }),
      bootstrap = buildPolicyBootstrapBaseline(g.snapshot, target.record),
      previous = bootstrapPrevious(target.record, bootstrap);
    await this.ports.guard.verify(null, { families: [4, 6] });
    await this.ports.executor.verify(buildRoutingPlan(bootstrap), null);
    const result = await this.apply(
      provider,
      context,
      previous,
      target.record,
      target.configurations,
      {
        bootstrap,
        configurationApplied: true,
      }
    );
    if (result.status !== 'applied')
      throw new RoutingPolicyJournalError('bootstrap_not_applied');
  }

  private async apply(
    provider: Provider,
    context: Context,
    previous: RoutingPolicyJournal,
    target: RoutingPolicyJournal,
    configurations: ReadonlyMap<string, string | null>,
    {
      bootstrap,
      withdrawal,
      configurationApplied = false,
      failures = new Map<string, string>(),
    }: {
      bootstrap?: PolicyBootstrapBaseline;
      withdrawal?: PendingPolicyTransition['withdrawal'];
      configurationApplied?: boolean;
      failures?: ReadonlyMap<string, string>;
    } = {}
  ) {
    const baseline = withdrawal
        ? routingWithdrawalDeviceBaseline(previous, {
            ...target,
            withdrawal,
            stage: 'prepared',
            guardScopes: [],
            backupBasenames: [],
            errorCode: null,
          })
        : previous,
      transition = await ManagedInterfaceTransition.prepare(
        this.ports,
        baseline.plan,
        target.plan,
        configurations
      );
    // A concurrent desired write may introduce another lifecycle change after
    // the pass's withdrawal. Refuse it before mutation; the coalesced fresh pass
    // will first establish its own durable Down baseline.
    if (
      !withdrawal &&
      transition.intent.interfaces.some((i) => i.previousUp && i.restart)
    )
      throw new RoutingPolicyJournalError('availability_withdrawal_required');
    const deps = this.dependencies(
      provider,
      context,
      previous,
      target,
      transition,
      {
        allowAbsent: !!withdrawal?.resetNamespace,
        configurationApplied,
        failures: new Map(failures),
      }
    );
    return applyGuardedRoutingPolicy(deps, target, {
      bootstrap,
      withdrawal,
      forcePeerIds: transition.forcePeerIds,
    });
  }

  async reconcile(
    provider: Provider,
    impacts: readonly InterfaceChangeImpact[],
    shutdown = false
  ): Promise<MutationResult> {
    await this.recover(provider);
    let context = await this.context(provider),
      previous = context.generation.policy.applied;
    if (context.generation.policy.version !== 2 || !previous)
      throw new RoutingPolicyJournalError('applied_generation_missing');
    const withdraw = async (
      missing: Set<string>,
      stops = new Set<string>(),
      reset = false
    ) => {
      const target = deriveRoutingAvailabilityWithdrawal(previous!, missing, {
          namespaceId: context.namespaceId,
          resetHooks: reset,
          stopInterfaceIds: stops,
        }),
        files = await this.configurations(
          previous!.plan.interfaces.map((i) => i.interfaceId)
        ),
        result = await this.apply(provider, context, previous!, target, files, {
          withdrawal: {
            unavailableInterfaceIds: [...missing].sort(),
            resetNamespace: reset,
            ...(stops.size ? { stopInterfaceIds: [...stops].sort() } : {}),
          },
        });
      if (result.status !== 'applied')
        throw new RoutingPolicyJournalError('withdrawal_incomplete');
      context = await this.context(provider);
      previous = context.generation.policy.applied!;
    };
    if (previous.plan.namespaceId !== context.namespaceId) {
      await verifyColdRoutingNamespace(this.ports, [
        ...new Set([
          ...previous.plan.interfaces.map((i) => i.interfaceId),
          ...context.generation.interfaces.map((i) => i.name),
        ]),
      ]);
      await withdraw(
        new Set(previous.plan.interfaces.map((i) => i.interfaceId)),
        new Set(),
        true
      );
    } else {
      const missing = new Set<string>();
      for (const i of previous.plan.interfaces)
        if (i.observedUp && !(await this.ports.devices.observe(i.interfaceId)))
          missing.add(i.interfaceId);
      if (missing.size) await withdraw(missing);
    }
    const ids = [
        ...new Set([
          ...previous!.plan.interfaces.map((i) => i.interfaceId),
          ...context.generation.interfaces.map((i) => i.name),
        ]),
      ],
      files = await this.configurations(ids),
      prepared = prepareDesiredRoutingConfigurations(
        context.generation,
        files,
        this.enableIpv6
      ),
      requested = new Set(
        impacts.filter((i) => i.action === 'restart').map((i) => i.interfaceId)
      ),
      stops = new Set<string>();
    for (const old of previous!.plan.interfaces) {
      if (!old.observedUp && !old.hooksApplied) continue;
      const desired = context.generation.interfaces.find(
          (i) => i.name === old.interfaceId
        ),
        candidate = prepared.configurations.get(old.interfaceId),
        prior = files.get(old.interfaceId),
        changed =
          prior &&
          candidate &&
          managedInterfaceRequiresRestart(
            parseManagedInterfaceConfig(old.interfaceId, prior),
            parseManagedInterfaceConfig(old.interfaceId, candidate)
          );
      if (
        shutdown ||
        !desired?.enabled ||
        desired.pendingDelete ||
        requested.has(old.interfaceId) ||
        prepared.failures.has(old.interfaceId) ||
        changed
      )
        stops.add(old.interfaceId);
    }
    if (stops.size) await withdraw(stops, stops);
    if (!shutdown) {
      const failed = new Set<string>();
      // At most one start attempt per configured interface, plus the final policy.
      const limit = context.generation.interfaces.length + 1;
      for (let step = 0; step < limit; step++) {
        context = await this.context(provider);
        previous = context.generation.policy.applied!;
        const g = context.generation,
          files = await this.configurations([
            ...new Set([
              ...g.interfaces.map((i) => i.name),
              ...previous.plan.interfaces.map((i) => i.interfaceId),
            ]),
          ]),
          prepared = prepareDesiredRoutingConfigurations(
            g,
            files,
            this.enableIpv6
          ),
          up = new Set(
            previous.plan.interfaces
              .filter((i) => i.observedUp)
              .map((i) => i.interfaceId)
          ),
          next = g.interfaces.find(
            (i) =>
              i.enabled &&
              !i.pendingDelete &&
              !up.has(i.name) &&
              !prepared.failures.has(i.name) &&
              !failed.has(i.name)
          );
        if (next) up.add(next.name);
        for (const id of failed) prepared.failures.set(id, 'start_failed');
        const target = specializePrivateRoutingGeneration(g, prepared, {
          upInterfaceIds: up,
          hooksAppliedInterfaceIds: up,
          namespaceId: context.namespaceId,
          enableIpv6: this.enableIpv6,
          selectedExitClientIds: await this.selections(g, up),
        });
        // Keep historical removed interfaces available to recovery until publication.
        for (const [id, config] of files)
          if (!target.configurations.has(id))
            target.configurations.set(id, config);
        const result = await this.apply(
          provider,
          context,
          previous,
          target.record,
          target.configurations,
          {
            configurationApplied: true,
            failures: prepared.failures,
          }
        );
        if (result.status === 'failed')
          throw new RoutingPolicyJournalError(result.errorCode);
        if (result.status === 'restored') {
          if (!next)
            throw new RoutingPolicyJournalError('desired_generation_restored');
          failed.add(next.name);
          await provider.runtime.markInterfaceFailed(
            next.name,
            new Error('start_failed'),
            false
          );
        }
        if (!next) break;
      }
      const latest =
        await provider.routingGeneration.readPrivateDesiredGeneration();
      for (const iface of latest.interfaces.filter((i) => i.pendingDelete))
        await provider.interfaces.finalizeDelete(iface.name);
    }
    const state = await provider.routingPolicy.get();
    if (!state.pending)
      await this.ports.backups.cleanupOrphans(new Set()).catch(() => {});
    return {
      success: true,
      revision: state.runtime.desiredRevision,
      runtime: {
        status:
          state.runtime.status === 'idle'
            ? 'applied'
            : state.runtime.status === 'degraded'
              ? 'degraded'
              : 'pending',
        appliedRevision: state.runtime.appliedRevision,
        ...(state.runtime.lastError ? { error: state.runtime.lastError } : {}),
      },
    };
  }
}
