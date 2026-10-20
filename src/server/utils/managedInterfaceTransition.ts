import { constants } from 'node:fs';
import fs from 'node:fs/promises';
import path from 'node:path';

import { atomicWriteFile } from '#server/utils/atomicFile';
import {
  managedInterfaceRequiresRestart,
  parseManagedInterfaceConfig,
  verifyManagedInterfaceState,
  type ManagedInterfaceConfig,
} from '#server/utils/managedInterfaceState';
import {
  admitManagedServerHooks,
  managedHookRuleKey,
  resolveManagedServerHookPhase,
  resolveManagedServerHooks,
  type ManagedHookPhase,
  type ManagedHookRule,
  type ManagedServerHookEffects,
  type ManagedServerHooks,
  ManagedServerHookError,
} from '#server/utils/managedServerHooks';
import {
  parseManagedLifecycleIntent,
  type ManagedLifecycleIntent,
} from '#server/utils/managedLifecycleIntent';
import { policyPeerId } from '#server/utils/routingPolicy';
import type { RoutingPolicyBackups } from '#server/utils/routingPolicyBackups';
import { verifyRoutingPolicyPeerMap } from '#server/utils/routingPolicyRuntime';
import type { AppliedRoutingPolicyPlan } from '#shared/types/routingPolicy';
import {
  InterfaceNameSchema,
  NetworkDeviceSchema,
} from '#shared/utils/schemas';

export type ManagedDeviceObservation = { showconf: string; addresses: string };
/** Ports execute no operator hook text. The existing coordinator owns all calls. */
export type ManagedInterfaceDevices = {
  observe: (interfaceId: string) => Promise<ManagedDeviceObservation | null>;
  validate: (interfaceId: string, config: string) => Promise<void>;
  up: (interfaceId: string, config: string) => Promise<void>;
  down: (interfaceId: string, config: string) => Promise<void>;
  sync: (interfaceId: string, config: string) => Promise<void>;
  verifyRecoverable: (
    interfaceId: string,
    configs: readonly string[],
    allowPartialStart: boolean
  ) => Promise<void>;
};
type Dependencies = {
  configDirectory: string;
  backups: RoutingPolicyBackups;
  devices: ManagedInterfaceDevices;
  hooks: ManagedServerHookEffects;
};
type Generation = {
  config: string | null;
  parsed: ManagedInterfaceConfig | null;
  hooks: ManagedServerHooks | null;
  defaultEgress?: string;
  hookError?: ManagedServerHookError;
};
const EGRESS_MARKER = '# wg-easy managed hook egress: ';
type Entry = {
  interfaceId: string;
  previous: Generation;
  target: Generation;
};
export class ManagedInterfaceTransitionError extends Error {
  constructor(
    readonly code: string,
    readonly interfaceId?: string
  ) {
    super(`Managed interface transition: ${code}`);
    this.name = 'ManagedInterfaceTransitionError';
  }
}
function fail(code: string, interfaceId?: string): never {
  throw new ManagedInterfaceTransitionError(code, interfaceId);
}
async function readConfig(root: string, interfaceId: string) {
  if (!InterfaceNameSchema.safeParse(interfaceId).success)
    fail('invalid_interface');
  let handle: Awaited<ReturnType<typeof fs.open>> | undefined;
  try {
    handle = await fs.open(
      path.join(root, `${interfaceId}.conf`),
      constants.O_RDONLY | constants.O_NOFOLLOW
    );
    const stat = await handle.stat();
    if (!stat.isFile() || stat.nlink !== 1)
      fail('unknown_configuration', interfaceId);
    return await handle.readFile('utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
    fail('configuration_unavailable', interfaceId);
  } finally {
    await handle?.close();
  }
}
function generation(interfaceId: string, config: string | null): Generation {
  if (config === null) return { config, parsed: null, hooks: null };
  const parsed = parseManagedInterfaceConfig(interfaceId, config);
  const markers = config
    .split(/\r?\n/)
    .filter((line) => line.startsWith('# wg-easy managed hook egress'));
  let defaultEgress: string | undefined;
  if (markers.length) {
    if (markers.length !== 1 || !markers[0]!.startsWith(EGRESS_MARKER))
      fail('invalid_hook_binding', interfaceId);
    const value = markers[0]!.slice(EGRESS_MARKER.length),
      checked = NetworkDeviceSchema.safeParse(value);
    if (!checked.success) fail('invalid_hook_binding', interfaceId);
    defaultEgress = checked.data;
  }
  let hooks: ManagedServerHooks | null = null,
    hookError: ManagedServerHookError | undefined;
  try {
    hooks = admitManagedServerHooks(interfaceId, parsed.fields);
  } catch (error) {
    if (!(error instanceof ManagedServerHookError)) throw error;
    hookError = error;
  }
  if (defaultEgress && hooks && !hooks.dynamic)
    fail('invalid_hook_binding', interfaceId);
  return {
    config,
    parsed,
    hooks,
    ...(defaultEgress ? { defaultEgress } : {}),
    ...(hookError ? { hookError } : {}),
  };
}
function sameConfig(a: Generation, b: Generation) {
  const canonical = (parsed: ManagedInterfaceConfig | null) =>
    parsed
      ? [
          [...parsed.fields].sort(),
          parsed.peers
            .map((peer) => [...peer].sort())
            .sort((x, y) => JSON.stringify(x).localeCompare(JSON.stringify(y))),
        ]
      : null;
  return (
    JSON.stringify(canonical(a.parsed)) === JSON.stringify(canonical(b.parsed))
  );
}
function sameRules(
  a: readonly ManagedHookRule[],
  b: readonly ManagedHookRule[]
) {
  return (
    JSON.stringify(a.map(managedHookRuleKey).sort()) ===
    JSON.stringify(b.map(managedHookRuleKey).sort())
  );
}
function ruleCounts(rules: readonly ManagedHookRule[]) {
  const result = new Map<string, number>();
  for (const rule of rules) {
    const key = managedHookRuleKey(rule);
    result.set(key, (result.get(key) ?? 0) + 1);
  }
  return result;
}
function ids(
  previous: AppliedRoutingPolicyPlan,
  target: AppliedRoutingPolicyPlan
) {
  return [
    ...new Set(
      [...previous.interfaces, ...target.interfaces].map((i) => i.interfaceId)
    ),
  ].sort();
}
function verifyConfigPeers(
  plan: AppliedRoutingPolicyPlan,
  entries: readonly Entry[],
  which: 'previous' | 'target'
) {
  const up = new Set(
    plan.interfaces.filter((i) => i.observedUp).map((i) => i.interfaceId)
  );
  verifyRoutingPolicyPeerMap(
    plan,
    entries.flatMap((entry) =>
      up.has(entry.interfaceId)
        ? (entry[which].parsed?.peers ?? []).map((peer) => ({
            interfaceId: entry.interfaceId,
            publicKey: peer.get('publickey')!,
            allowedIps: (peer.get('allowedips') ?? '')
              .split(',')
              .map((p) => p.trim())
              .filter(Boolean),
          }))
        : []
    )
  );
}

/** No loop, no DB reads. Call only within the existing serialized coordinator. */
export class ManagedInterfaceTransition {
  readonly candidateConfigurations: ReadonlyMap<string, string | null>;
  readonly previousConfigurations: ReadonlyMap<string, string | null>;
  readonly forcePeerIds = new Set<string>();
  private constructor(
    private readonly deps: Dependencies,
    private readonly entries: Entry[],
    readonly intent: ManagedLifecycleIntent
  ) {
    this.candidateConfigurations = new Map(
      entries.map((e) => [e.interfaceId, e.target.config])
    );
    this.previousConfigurations = new Map(
      entries.map((e) => [e.interfaceId, e.previous.config])
    );
    for (const entry of entries) {
      const action = this.action(entry.interfaceId);
      const old = new Map(
          entry.previous.parsed?.peers.map((p) => [p.get('publickey')!, p]) ??
            []
        ),
        target = new Map(
          entry.target.parsed?.peers.map((p) => [p.get('publickey')!, p]) ?? []
        );
      for (const key of new Set([...old.keys(), ...target.keys()])) {
        if (
          action.restart ||
          (old.get(key)?.get('presharedkey') ?? null) !==
            (target.get(key)?.get('presharedkey') ?? null)
        )
          this.forcePeerIds.add(
            policyPeerId({ interfaceId: entry.interfaceId, publicKey: key })
          );
      }
    }
  }
  private action(interfaceId: string) {
    const result = this.intent.interfaces.find(
      (i) => i.interfaceId === interfaceId
    );
    if (!result) fail('invalid_lifecycle_intent', interfaceId);
    const previousHooksApplied =
        result.previousHooksApplied ?? result.previousUp,
      targetHooksApplied = result.targetHooksApplied ?? result.targetUp;
    return {
      ...result,
      previousHooksApplied,
      targetHooksApplied,
      hooksChanged:
        result.restart || previousHooksApplied !== targetHooksApplied,
    };
  }
  private rules(
    entry: Entry,
    which: 'previous' | 'target',
    phase?: ManagedHookPhase
  ) {
    const hooks = entry[which].hooks;
    if (!hooks) return [];
    const action = this.action(entry.interfaceId),
      egress =
        which === 'previous'
          ? action.previousDefaultEgress
          : action.targetDefaultEgress;
    return phase
      ? resolveManagedServerHookPhase(hooks, phase, egress)
      : resolveManagedServerHooks(hooks, egress);
  }
  private static async checkRoot(root: string) {
    if (!path.isAbsolute(root)) fail('invalid_root');
    const stat = await fs.lstat(root);
    if (!stat.isDirectory() || stat.isSymbolicLink()) fail('invalid_root');
  }

  static async prepare(
    deps: Dependencies,
    previous: AppliedRoutingPolicyPlan,
    target: AppliedRoutingPolicyPlan,
    candidates: ReadonlyMap<string, string | null>,
    {
      restartInterfaceIds = new Set<string>(),
    }: { restartInterfaceIds?: ReadonlySet<string> } = {}
  ) {
    await this.checkRoot(deps.configDirectory);
    const all = ids(previous, target);
    if (
      all.length !== candidates.size ||
      all.some((id) => !candidates.has(id)) ||
      [...restartInterfaceIds].some((id) => !all.includes(id))
    )
      fail('invalid_candidates');
    const entries: Entry[] = [];
    // Parse/admit the entire old/candidate set before even tool preflight.
    for (const interfaceId of all)
      entries.push({
        interfaceId,
        previous: generation(
          interfaceId,
          await readConfig(deps.configDirectory, interfaceId)
        ),
        target: generation(interfaceId, candidates.get(interfaceId)!),
      });
    verifyConfigPeers(previous, entries, 'previous');
    verifyConfigPeers(target, entries, 'target');
    const basicActions = entries.map((entry) => {
      const previousUp = previous.interfaces.some(
          (i) => i.interfaceId === entry.interfaceId && i.observedUp
        ),
        targetUp = target.interfaces.some(
          (i) => i.interfaceId === entry.interfaceId && i.observedUp
        );
      const previousHooksApplied =
          previous.interfaces.find((i) => i.interfaceId === entry.interfaceId)
            ?.hooksApplied ?? previousUp,
        targetHooksApplied =
          target.interfaces.find((i) => i.interfaceId === entry.interfaceId)
            ?.hooksApplied ?? targetUp;
      if (
        (previousUp && !previousHooksApplied) ||
        (targetUp && !targetHooksApplied)
      )
        fail('invalid_hook_availability', entry.interfaceId);
      if (previousHooksApplied && entry.previous.hookError)
        throw entry.previous.hookError;
      if (targetHooksApplied && entry.target.hookError)
        throw entry.target.hookError;
      if (
        ((previousUp || previousHooksApplied) && !entry.previous.parsed) ||
        ((targetUp || targetHooksApplied) && !entry.target.parsed)
      )
        fail('missing_configuration', entry.interfaceId);
      const restart =
        previousUp !== targetUp ||
        restartInterfaceIds.has(entry.interfaceId) ||
        (!!entry.previous.parsed &&
          !!entry.target.parsed &&
          managedInterfaceRequiresRestart(
            entry.previous.parsed,
            entry.target.parsed
          ));
      if (!previousHooksApplied && targetHooksApplied && !targetUp)
        fail('invalid_hook_availability', entry.interfaceId);
      return {
        interfaceId: entry.interfaceId,
        previousUp,
        targetUp,
        previousHooksApplied,
        targetHooksApplied,
        restart,
      };
    });
    const needsEgress = entries.some(
        (entry, i) =>
          (basicActions[i]!.previousHooksApplied &&
            entry.previous.hooks?.dynamic &&
            !entry.previous.defaultEgress) ||
          (basicActions[i]!.targetHooksApplied &&
            entry.target.hooks?.dynamic &&
            (basicActions[i]!.restart || !entry.previous.hooks?.dynamic))
      ),
      egress = needsEgress ? await deps.hooks.defaultEgress() : undefined;
    const actions = entries.map((entry, i) => {
      const basic = basicActions[i]!,
        previousDefaultEgress = entry.previous.hooks?.dynamic
          ? (entry.previous.defaultEgress ?? egress)
          : undefined,
        targetDefaultEgress = entry.target.hooks?.dynamic
          ? !basic.targetHooksApplied
            ? entry.target.defaultEgress
            : basic.restart || !entry.previous.hooks?.dynamic
              ? egress
              : previousDefaultEgress
          : undefined;
      if (entry.target.hooks?.dynamic && targetDefaultEgress) {
        if (!targetDefaultEgress)
          fail('invalid_hook_binding', entry.interfaceId);
        const text =
          entry.target
            .config!.split(/\r?\n/)
            .filter((line) => !line.startsWith(EGRESS_MARKER))
            .join('\n')
            .trimEnd() + `\n${EGRESS_MARKER}${targetDefaultEgress}\n`;
        entry.target = generation(entry.interfaceId, text);
      }
      return {
        ...basic,
        ...(previousDefaultEgress ? { previousDefaultEgress } : {}),
        ...(targetDefaultEgress ? { targetDefaultEgress } : {}),
      };
    });
    const transition = new ManagedInterfaceTransition(deps, entries, {
      interfaces: actions,
      hooks: [],
    });
    const movingOld: ManagedHookRule[] = [],
      movingTarget: ManagedHookRule[] = [],
      retained: ManagedHookRule[] = [];
    for (const entry of entries) {
      const action = transition.action(entry.interfaceId);
      if (action.previousUp) {
        const observed = await deps.devices.observe(entry.interfaceId);
        if (!observed) fail('previous_device_missing', entry.interfaceId);
        verifyManagedInterfaceState(
          entry.interfaceId,
          entry.previous.config!,
          observed
        );
      } else if (await deps.devices.observe(entry.interfaceId))
        fail('unknown_device', entry.interfaceId);
      for (const which of ['previous', 'target'] as const)
        if (entry[which].config !== null)
          await deps.devices.validate(entry.interfaceId, entry[which].config!);
      if (action.hooksChanged) {
        if (action.previousHooksApplied)
          movingOld.push(...transition.rules(entry, 'previous'));
        if (action.targetHooksApplied)
          movingTarget.push(...transition.rules(entry, 'target'));
      } else if (action.previousHooksApplied) {
        if (
          !sameRules(
            transition.rules(entry, 'previous'),
            transition.rules(entry, 'target')
          )
        )
          fail('restart_required', entry.interfaceId);
        retained.push(...transition.rules(entry, 'previous'));
      }
    }
    transition.intent.hooks = await deps.hooks.capture(
      movingOld,
      movingTarget,
      retained
    );
    await deps.hooks.prepare(transition.intent.hooks);
    return transition;
  }

  static async reopen(
    deps: Dependencies,
    reference: string,
    previous: AppliedRoutingPolicyPlan,
    target: AppliedRoutingPolicyPlan
  ) {
    await this.checkRoot(deps.configDirectory);
    const saved = await deps.backups.readPrivateConfigurations(reference),
      rawIntent = await deps.backups.readPrivateLifecycleIntent(reference);
    if (!rawIntent || saved.some((e) => e.candidate === undefined))
      fail('lifecycle_intent_missing');
    const intent = parseManagedLifecycleIntent(rawIntent),
      all = ids(previous, target);
    if (
      all.length !== saved.length ||
      saved.some((e) => !all.includes(e.interfaceId))
    )
      fail('invalid_lifecycle_intent');
    const entries = saved.map((entry) => ({
        interfaceId: entry.interfaceId,
        previous: generation(entry.interfaceId, entry.config),
        target: generation(entry.interfaceId, entry.candidate!),
      })),
      result = new ManagedInterfaceTransition(deps, entries, intent),
      old: ManagedHookRule[] = [],
      next: ManagedHookRule[] = [];
    verifyConfigPeers(previous, entries, 'previous');
    verifyConfigPeers(target, entries, 'target');
    for (const entry of entries) {
      const action = result.action(entry.interfaceId),
        expectedOldUp = previous.interfaces.some(
          (i) => i.interfaceId === entry.interfaceId && i.observedUp
        ),
        expectedTargetUp = target.interfaces.some(
          (i) => i.interfaceId === entry.interfaceId && i.observedUp
        );
      const expectedOldHooks =
          previous.interfaces.find((i) => i.interfaceId === entry.interfaceId)
            ?.hooksApplied ?? expectedOldUp,
        expectedTargetHooks =
          target.interfaces.find((i) => i.interfaceId === entry.interfaceId)
            ?.hooksApplied ?? expectedTargetUp;
      if (action.previousHooksApplied && entry.previous.hookError)
        throw entry.previous.hookError;
      if (action.targetHooksApplied && entry.target.hookError)
        throw entry.target.hookError;
      if (
        action.previousUp !== expectedOldUp ||
        action.targetUp !== expectedTargetUp ||
        action.previousHooksApplied !== expectedOldHooks ||
        action.targetHooksApplied !== expectedTargetHooks ||
        (action.previousHooksApplied &&
          !!entry.previous.hooks?.dynamic !== !!action.previousDefaultEgress) ||
        (action.targetHooksApplied &&
          !!entry.target.hooks?.dynamic !== !!action.targetDefaultEgress) ||
        (action.previousHooksApplied &&
          entry.previous.defaultEgress &&
          entry.previous.defaultEgress !== action.previousDefaultEgress) ||
        (action.targetHooksApplied &&
          entry.target.defaultEgress &&
          entry.target.defaultEgress !== action.targetDefaultEgress) ||
        (!action.restart &&
          entry.previous.parsed &&
          entry.target.parsed &&
          managedInterfaceRequiresRestart(
            entry.previous.parsed,
            entry.target.parsed
          ))
      )
        fail('invalid_lifecycle_intent', entry.interfaceId);
      if (action.hooksChanged) {
        if (action.previousHooksApplied)
          old.push(...result.rules(entry, 'previous'));
        if (action.targetHooksApplied)
          next.push(...result.rules(entry, 'target'));
      } else if (
        action.previousHooksApplied &&
        !sameRules(
          result.rules(entry, 'previous'),
          result.rules(entry, 'target')
        )
      )
        fail('invalid_lifecycle_intent', entry.interfaceId);
    }
    const oldCounts = ruleCounts(old),
      nextCounts = ruleCounts(next),
      known = new Set(intent.hooks.map((e) => managedHookRuleKey(e.rule)));
    if (
      [...oldCounts.keys(), ...nextCounts.keys()].some(
        (key) => !known.has(key)
      ) ||
      intent.hooks.some(
        (entry) =>
          entry.previous - entry.base !==
            (oldCounts.get(managedHookRuleKey(entry.rule)) ?? 0) ||
          entry.target - entry.base !==
            (nextCounts.get(managedHookRuleKey(entry.rule)) ?? 0)
      )
    )
      fail('invalid_lifecycle_intent');
    return result;
  }

  private async verifyFiles(which: 'previous' | 'target' | 'either') {
    for (const entry of this.entries) {
      const actual = await readConfig(
        this.deps.configDirectory,
        entry.interfaceId
      );
      if (
        which === 'either'
          ? actual !== entry.previous.config && actual !== entry.target.config
          : actual !== entry[which].config
      )
        fail('unknown_configuration', entry.interfaceId);
    }
  }
  private cursor(which: 'previous' | 'target') {
    return ruleCounts(
      this.entries.flatMap((entry) => {
        const action = this.action(entry.interfaceId);
        return action.hooksChanged &&
          (which === 'previous'
            ? action.previousHooksApplied
            : action.targetHooksApplied)
          ? this.rules(entry, which)
          : [];
      })
    );
  }
  private async phase(
    cursor: Map<string, number>,
    entry: Entry,
    which: 'previous' | 'target',
    phase: ManagedHookPhase,
    verifyGuard: () => Promise<void>
  ) {
    const rules = this.rules(entry, which, phase);
    if (rules.length === 0) {
      await verifyGuard();
      return;
    }
    for (const rule of rules) {
      const key = managedHookRuleKey(rule),
        next = (cursor.get(key) ?? 0) + (phase.endsWith('up') ? 1 : -1);
      if (next < 0) fail('invalid_hook_phase', entry.interfaceId);
      cursor.set(key, next);
    }
    const projection = this.intent.hooks.map((effect) => ({
      ...effect,
      previous: Math.max(effect.previous, effect.target),
      target: effect.base + (cursor.get(managedHookRuleKey(effect.rule)) ?? 0),
    }));
    if (
      projection.some(
        (effect, i) =>
          effect.target >
          Math.max(this.intent.hooks[i]!.previous, this.intent.hooks[i]!.target)
      )
    )
      fail('invalid_hook_phase', entry.interfaceId);
    await this.deps.hooks.reconcile(projection, 'target', verifyGuard);
  }
  private async mutate(
    verifyGuard: () => Promise<void>,
    work: () => Promise<void>
  ) {
    await verifyGuard();
    await work();
    await verifyGuard();
  }

  async apply(verifyGuard: () => Promise<void>) {
    await this.verify('previous');
    const cursor = this.cursor('previous');
    // Old quick settings remain on disk until every required old stop finishes.
    for (const entry of this.entries) {
      const action = this.action(entry.interfaceId);
      if (!action.hooksChanged || !action.previousHooksApplied) continue;
      await this.phase(cursor, entry, 'previous', 'predown', verifyGuard);
      if (action.previousUp)
        await this.mutate(verifyGuard, () =>
          this.deps.devices.down(entry.interfaceId, entry.previous.config!)
        );
      await this.phase(cursor, entry, 'previous', 'postdown', verifyGuard);
    }
    await this.deps.hooks.verify(this.intent.hooks, 'base');
    for (const entry of this.entries) {
      if (entry.previous.config === entry.target.config) continue;
      await this.mutate(verifyGuard, async () => {
        const file = path.join(
          this.deps.configDirectory,
          `${entry.interfaceId}.conf`
        );
        if (entry.target.config === null) {
          await fs.unlink(file).catch((error: NodeJS.ErrnoException) => {
            if (error.code !== 'ENOENT') throw error;
          });
          const directory = await fs.open(this.deps.configDirectory, 'r');
          try {
            await directory.sync();
          } finally {
            await directory.close();
          }
        } else await atomicWriteFile(file, entry.target.config);
      });
    }
    for (const entry of this.entries) {
      const action = this.action(entry.interfaceId);
      if (!action.targetUp && !action.targetHooksApplied) continue;
      if (action.hooksChanged) {
        if (action.targetHooksApplied)
          await this.phase(cursor, entry, 'target', 'preup', verifyGuard);
        if (action.targetUp && action.restart)
          await this.mutate(verifyGuard, () =>
            this.deps.devices.up(entry.interfaceId, entry.target.config!)
          );
        if (action.targetHooksApplied)
          await this.phase(cursor, entry, 'target', 'postup', verifyGuard);
      } else if (action.targetUp && !sameConfig(entry.previous, entry.target))
        await this.mutate(verifyGuard, () =>
          this.deps.devices.sync(entry.interfaceId, entry.target.config!)
        );
    }
    await this.verify('target');
  }

  /** Runs under the guard BEFORE RoutingPolicyBackups restores any old file. */
  async beforeRestore(verifyGuard: () => Promise<void>) {
    await this.verifyFiles('either');
    await this.deps.hooks.verifyRecoverable(this.intent.hooks);
    // Complete read-only recovery preflight; no first-device cleanup on a later
    // unknown file, interface, peer, address, credential or hook manifest.
    for (const entry of this.entries) {
      const action = this.action(entry.interfaceId),
        observed = await this.deps.devices.observe(entry.interfaceId);
      if (observed && !action.previousUp && !action.targetUp)
        fail('unknown_device', entry.interfaceId);
      const configs = [entry.previous.config, entry.target.config].filter(
        (c): c is string => c !== null
      );
      await this.deps.devices.verifyRecoverable(
        entry.interfaceId,
        configs,
        action.restart && (action.previousUp || action.targetUp)
      );
      const current = await readConfig(
        this.deps.configDirectory,
        entry.interfaceId
      );
      if (
        current === null &&
        (await this.deps.devices.observe(entry.interfaceId))
      )
        fail('unknown_device', entry.interfaceId);
    }
    for (const entry of this.entries) {
      if (
        !this.action(entry.interfaceId).restart ||
        !(await this.deps.devices.observe(entry.interfaceId))
      )
        continue;
      const current = await readConfig(
        this.deps.configDirectory,
        entry.interfaceId
      );
      if (!current) fail('unknown_configuration', entry.interfaceId);
      await this.mutate(verifyGuard, () =>
        this.deps.devices.down(entry.interfaceId, current)
      );
    }
    // A vanished device does not prove its PostDown effects completed.
    await this.deps.hooks.reconcile(this.intent.hooks, 'base', verifyGuard);
  }

  async restorePrevious(verifyGuard: () => Promise<void>) {
    await this.verifyFiles('previous');
    const cursor = new Map<string, number>();
    for (const entry of this.entries) {
      const action = this.action(entry.interfaceId);
      if (!action.previousUp && !action.previousHooksApplied) continue;
      if (action.hooksChanged) {
        if (action.previousHooksApplied)
          await this.phase(cursor, entry, 'previous', 'preup', verifyGuard);
        if (action.previousUp && action.restart)
          await this.mutate(verifyGuard, () =>
            this.deps.devices.up(entry.interfaceId, entry.previous.config!)
          );
        if (action.previousHooksApplied)
          await this.phase(cursor, entry, 'previous', 'postup', verifyGuard);
      } else if (action.previousUp && !sameConfig(entry.previous, entry.target))
        await this.mutate(verifyGuard, () =>
          this.deps.devices.sync(entry.interfaceId, entry.previous.config!)
        );
    }
    await this.verify('previous');
  }
  async verify(which: 'previous' | 'target') {
    await this.verifyFiles(which);
    for (const entry of this.entries) {
      const action = this.action(entry.interfaceId),
        expectedUp = which === 'previous' ? action.previousUp : action.targetUp,
        observed = await this.deps.devices.observe(entry.interfaceId);
      if (expectedUp) {
        if (!observed || entry[which].config === null)
          fail('device_unverified', entry.interfaceId);
        verifyManagedInterfaceState(
          entry.interfaceId,
          entry[which].config!,
          observed
        );
      } else if (observed) fail('device_unverified', entry.interfaceId);
    }
    await this.deps.hooks.verify(this.intent.hooks, which);
  }
}
