import { execFile } from '#server/utils/cmd';
import {
  ROUTING_MARK_CHAIN,
  ROUTING_NAT_CHAIN,
  ROUTING_OWNER_COMMENT,
  ROUTING_PROGRAM_CHAIN_PREFIX,
  WG_EASY_ROUTE_PROTOCOL,
  formatMark,
  isOwnedRoutingRoute,
  isOwnedRoutingRule,
  preflightRoutingOwnership,
  type ObservedMarkUse,
  type ObservedPolicyRule,
  type ObservedRoute,
  type ObservedRoutingChain,
  type ObservedRoutingState,
  type PlannedPolicyRule,
  type RoutingPlan,
} from '#server/utils/routing';
import {
  RoutingGuard,
  type RoutingGuardPlan,
} from '#server/utils/routingGuard';
import {
  assertRoutingPolicyChains,
  canonicalRoutingRule,
  routingRestoreRule,
} from '#server/utils/routingPolicyOwnership';

export type RoutingApplyPhase =
  | 'preflight'
  | 'routes'
  | 'rules'
  | 'transition_nat'
  | 'mark_activation'
  | 'final_nat'
  | 'cleanup'
  | 'verify';

type RunCommand = (
  executable: string,
  args?: readonly string[],
  options?: { input?: string; log?: boolean | string }
) => Promise<string>;

type ApplyOptions = {
  previousPlan?: RoutingPlan;
  afterPhase?: (phase: RoutingApplyPhase) => void | Promise<void>;
  guardedTransition?: {
    guard: RoutingGuardPlan;
    knownPlans: readonly RoutingPlan[];
  };
};

const OWNER_MARKER = `${ROUTING_OWNER_COMMENT} owner`;

function numeric(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && /^\d+$/.test(value)) return Number(value);
  return undefined;
}

function parseProtocol(value: unknown): number | undefined {
  const parsed = numeric(value);
  if (parsed !== undefined) return parsed;
  // iproute2 renders protocol 186 by its registered name in JSON output.
  if (value === 'bgp') return WG_EASY_ROUTE_PROTOCOL;
  return undefined;
}

function parseMark(value: unknown): { value: number; mask: number } | null {
  if (typeof value === 'number') {
    return { value: value >>> 0, mask: 0xffffffff };
  }
  if (typeof value !== 'string') return null;
  const match = value.match(/^(0x[0-9a-f]+|\d+)(?:\/(0x[0-9a-f]+|\d+))?$/i);
  if (!match?.[1]) return null;
  return {
    value: Number(match[1]) >>> 0,
    mask: match[2] ? Number(match[2]) >>> 0 : 0xffffffff,
  };
}

function parseJsonArray(output: string): Record<string, unknown>[] {
  if (!output.trim()) return [];
  const parsed: unknown = JSON.parse(output);
  if (!Array.isArray(parsed)) throw new Error('Expected command JSON array');
  return parsed.filter(
    (item): item is Record<string, unknown> =>
      typeof item === 'object' && item !== null
  );
}

function parseRules(output: string, family: 4 | 6): ObservedPolicyRule[] {
  return parseJsonArray(output).flatMap((item) => {
    const priority = numeric(item.priority ?? item.pref);
    const table = numeric(item.table);
    if (priority === undefined || table === undefined) return [];
    const mark = parseMark(
      item.fwmark !== undefined && item.fwmask !== undefined
        ? `${String(item.fwmark)}/${String(item.fwmask)}`
        : item.fwmark
    );
    return [
      {
        family,
        priority,
        table,
        protocol: parseProtocol(item.protocol),
        ...(mark ? { fwmark: mark.value, mask: mark.mask } : {}),
      },
    ];
  });
}

function parseRoutes(output: string, family: 4 | 6): ObservedRoute[] {
  return parseJsonArray(output).flatMap((item) => {
    const table = numeric(item.table);
    if (table === undefined) return [];
    const rawPrefix = typeof item.dst === 'string' ? item.dst : 'default';
    const prefix =
      rawPrefix === 'default'
        ? family === 4
          ? '0.0.0.0/0'
          : '::/0'
        : rawPrefix.includes('/')
          ? rawPrefix
          : `${rawPrefix}/${family === 4 ? 32 : 128}`;
    return [
      {
        family,
        table,
        protocol: parseProtocol(item.protocol),
        prefix,
        type: item.type === 'unreachable' ? 'unreachable' : 'unicast',
        ...(typeof item.dev === 'string' ? { device: item.dev } : {}),
      },
    ];
  });
}

function hasOwnerComment(line: string) {
  return line.includes(`--comment "${ROUTING_OWNER_COMMENT}`);
}

function parseIptablesState(
  mangle: string,
  nat: string
): Pick<
  ObservedRoutingState,
  'chains' | 'markUses' | 'ownedParentJumps' | 'ownedChainRules'
> {
  const tables = [
    { table: 'mangle' as const, output: mangle },
    { table: 'nat' as const, output: nat },
  ];
  const chains: ObservedRoutingChain[] = [];
  const markUses: ObservedMarkUse[] = [];
  const ownedParentJumps: NonNullable<
    ObservedRoutingState['ownedParentJumps']
  >[number][] = [];
  const ownedChainRules: NonNullable<
    ObservedRoutingState['ownedChainRules']
  >[number][] = [];

  for (const { table, output } of tables) {
    const lines = output.split('\n').map((line) => line.trim());
    const byChain = new Map<string, string[]>();
    for (const line of lines) {
      const name = line.match(/^-A (\S+) /)?.[1];
      if (!name) continue;
      const rules = byChain.get(name) ?? [];
      rules.push(line);
      byChain.set(name, rules);
    }
    const reservedChain =
      table === 'mangle' ? ROUTING_MARK_CHAIN : ROUTING_NAT_CHAIN;
    const exists = lines.some((line) => line.startsWith(`:${reservedChain} `));
    const owned = lines.some(
      (line) =>
        line.startsWith(`-A ${reservedChain} `) &&
        line.includes(`--comment "${OWNER_MARKER}"`)
    );
    const nonOwnedJump = lines.some(
      (line) =>
        line.includes(`-j ${reservedChain}`) &&
        !line.startsWith(`-A ${reservedChain} `) &&
        !hasOwnerComment(line)
    );
    if (exists || nonOwnedJump) {
      chains.push({
        table,
        name: reservedChain,
        owner: exists && owned && !nonOwnedJump ? 'wg-easy' : 'other',
      });
    }
    if (table === 'mangle') {
      for (const line of lines) {
        const name = line.match(/^:([^ ]+) /)?.[1];
        if (!name?.startsWith(ROUTING_PROGRAM_CHAIN_PREFIX)) continue;
        const rules = byChain.get(name) ?? [];
        chains.push({
          table,
          name,
          owner: rules.some((l) =>
            l.includes(`--comment "${ROUTING_OWNER_COMMENT} program `)
          )
            ? 'wg-easy'
            : 'other',
        });
        ownedChainRules.push(...rules.map((line) => ({ table, line })));
      }
    }

    for (const line of lines) {
      if (
        line.startsWith(`-A ${reservedChain} `) &&
        !line.includes(`--comment "${OWNER_MARKER}"`)
      ) {
        ownedChainRules.push({ table, line });
      }
    }

    for (const line of lines) {
      if (
        line.startsWith('-A ') &&
        line.includes(`-j ${reservedChain}`) &&
        !line.startsWith(`-A ${reservedChain} `) &&
        hasOwnerComment(line)
      ) {
        ownedParentJumps.push({ table, line });
      }
      const markMatch = line.match(
        /--(?:set-xmark|set-mark|mark) (0x[0-9a-f]+|\d+)(?:\/(0x[0-9a-f]+|\d+))?/i
      );
      if (!markMatch?.[1]) continue;
      markUses.push({
        value: Number(markMatch[1]) >>> 0,
        mask: markMatch[2] ? Number(markMatch[2]) >>> 0 : 0xffffffff,
        owner: hasOwnerComment(line) ? 'wg-easy' : 'other',
      });
    }
  }

  return { chains, markUses, ownedParentJumps, ownedChainRules };
}

function replaceAppendWithInsert(args: readonly string[]) {
  if (args[0] !== '-A' || !args[1]) return [...args];
  return ['-I', args[1], '1', ...args.slice(2)];
}

const restoreRule = routingRestoreRule;
const canonicalizeIptablesRule = canonicalRoutingRule;

function renderRestoreDocument({
  table,
  chain,
  rules,
  jumps,
  observed,
  children = [],
}: {
  table: 'mangle' | 'nat';
  chain: string;
  rules: readonly string[][];
  jumps: readonly string[][];
  observed: ObservedRoutingState;
  children?: NonNullable<RoutingPlan['classifier']>['children'];
}) {
  const lines = [
    `*${table}`,
    `:${chain} - [0:0]`,
    ...children.map((c) => `:${c.name} - [0:0]`),
    `-F ${chain}`,
    ...children.map((c) => `-F ${c.name}`),
    ...(observed.ownedParentJumps ?? [])
      .filter((jump) => jump.table === table)
      .map(({ line }) => line.replace(/^-A /, '-D ')),
    `-A ${chain} -m comment --comment "${OWNER_MARKER}"`,
    ...rules.map(restoreRule),
    ...children.flatMap((c) => c.rules.map(restoreRule)),
    ...jumps.map((args) => restoreRule(replaceAppendWithInsert(args))),
    'COMMIT',
    '',
  ];
  return lines.join('\n');
}

function routeKey(route: {
  family: 4 | 6;
  table: number;
  protocol: number;
  prefix: string;
  type?: 'unicast' | 'unreachable';
  device?: string;
}) {
  return [
    route.family,
    route.table,
    route.protocol,
    route.prefix,
    route.type ?? 'unicast',
    route.device ?? '',
  ].join(':');
}

function ruleKey(
  rule: Pick<
    PlannedPolicyRule,
    'family' | 'priority' | 'table' | 'protocol' | 'fwmark' | 'mask'
  >
) {
  return [
    rule.family,
    rule.priority,
    rule.table,
    rule.protocol,
    rule.fwmark ?? '',
    rule.mask ?? '',
  ].join(':');
}

function deleteRouteArgs(route: ObservedRoute) {
  return [
    `-${route.family}`,
    'route',
    'del',
    ...(route.type === 'unreachable' ? ['unreachable'] : []),
    route.prefix,
    'table',
    String(route.table),
    'proto',
    String(WG_EASY_ROUTE_PROTOCOL),
  ];
}

function deleteRuleArgs(rule: ObservedPolicyRule) {
  return [
    `-${rule.family}`,
    'rule',
    'del',
    ...(rule.fwmark !== undefined && rule.mask !== undefined
      ? ['fwmark', `${formatMark(rule.fwmark)}/${formatMark(rule.mask)}`]
      : []),
    'priority',
    String(rule.priority),
    'table',
    String(rule.table),
    'protocol',
    String(WG_EASY_ROUTE_PROTOCOL),
  ];
}

function deduplicateRules(rules: readonly string[][]) {
  const byRule = new Map(rules.map((rule) => [rule.join('\u0000'), rule]));
  return [...byRule.values()];
}

function setMismatch(
  label: string,
  observed: Set<string>,
  desired: Set<string>
) {
  const missing = [...desired]
    .filter((item) => !observed.has(item))
    .slice(0, 3);
  const unexpected = [...observed]
    .filter((item) => !desired.has(item))
    .slice(0, 3);
  return missing.length > 0 || unexpected.length > 0
    ? `${label} mismatch (missing: ${missing.join(', ') || 'none'}; unexpected: ${unexpected.join(', ') || 'none'})`
    : null;
}

export class RoutingOwnershipConflictError extends Error {}

export class RoutingExecutor {
  readonly #run: RunCommand;

  constructor(run: RunCommand = execFile) {
    this.#run = run;
  }

  async observe(): Promise<ObservedRoutingState> {
    const [rules4, rules6, routes4, routes6, mangle, nat] = await Promise.all([
      this.#run('ip', ['-j', '-4', 'rule', 'show']),
      this.#run('ip', ['-j', '-6', 'rule', 'show']),
      this.#run('ip', ['-j', '-4', 'route', 'show', 'table', 'all']),
      this.#run('ip', ['-j', '-6', 'route', 'show', 'table', 'all']),
      this.#run('iptables-save', ['-t', 'mangle']),
      this.#run('iptables-save', ['-t', 'nat']),
    ]);
    const iptables = parseIptablesState(mangle, nat);
    return {
      policyRules: [...parseRules(rules4, 4), ...parseRules(rules6, 6)],
      routes: [...parseRoutes(routes4, 4), ...parseRoutes(routes6, 6)],
      ...iptables,
      rawIptables: { mangle, nat },
    };
  }

  async capabilityPreflight() {
    await Promise.all([
      this.#run('ip', ['-Version']),
      this.#run('iptables', ['--version']),
      this.#run('iptables-restore', ['--version']),
    ]);
  }

  async apply(plan: RoutingPlan, options: ApplyOptions = {}) {
    if (plan.classifier && !options.guardedTransition) {
      throw new Error('Guarded policy classifier execution is unavailable');
    }
    let mutationStarted = false;
    try {
      await this.#applyOnce(plan, {
        afterPhase: options.afterPhase,
        guardedTransition: options.guardedTransition,
        previousNatRules: options.previousPlan?.natChainRules,
        previousNatJump: options.previousPlan?.parentNatJump,
        onMutation: () => {
          mutationStarted = true;
        },
      });
    } catch (error) {
      if (
        !mutationStarted ||
        !options.previousPlan ||
        options.guardedTransition
      )
        throw error;
      try {
        await this.#applyOnce(options.previousPlan, {
          previousNatRules: [],
          previousNatJump: null,
          onMutation: () => {},
        });
      } catch (rollbackError) {
        throw new AggregateError(
          [error, rollbackError],
          'Routing apply failed and the last safe plan could not be restored',
          { cause: rollbackError }
        );
      }
      throw error;
    }
  }

  /** Validate complete replacement documents before any guard or peer mutation. */
  async prepare(
    plan: RoutingPlan,
    {
      previousPlan,
      knownPlans = [],
    }: {
      previousPlan?: RoutingPlan;
      knownPlans?: readonly RoutingPlan[];
    } = {}
  ) {
    await this.#preparePlan(plan, {
      previousNatRules: previousPlan?.natChainRules,
      previousNatJump: previousPlan?.parentNatJump,
      knownPlans,
    });
  }

  async #preparePlan(
    plan: RoutingPlan,
    {
      previousNatRules = [],
      previousNatJump = null,
      knownPlans,
    }: {
      previousNatRules?: readonly string[][];
      previousNatJump?: string[] | null;
      knownPlans?: readonly RoutingPlan[];
    }
  ) {
    const strict = knownPlans !== undefined;
    await this.capabilityPreflight();
    const before = await this.observe();
    if (
      !strict &&
      before.chains.some((c) => c.name.startsWith(ROUTING_PROGRAM_CHAIN_PREFIX))
    )
      throw new RoutingOwnershipConflictError(
        'Guarded classifier recovery is required'
      );
    const preflight = preflightRoutingOwnership(before);
    if (!preflight.ok) {
      throw new RoutingOwnershipConflictError(
        preflight.conflicts.map(({ description }) => description).join('; ')
      );
    }

    const transitionNatRules = deduplicateRules([
      ...previousNatRules,
      ...plan.natChainRules,
    ]);
    const transitionNatJumps =
      transitionNatRules.length > 0
        ? [plan.parentNatJump ?? previousNatJump!]
        : [];
    const plans = [plan, ...(knownPlans ?? [])];
    const assertKnown = (state: ObservedRoutingState) => {
      if (strict) {
        if (!state.rawIptables)
          throw new Error('Routing policy observation is unavailable');
        assertRoutingPolicyChains(state.rawIptables, plans, {
          transitionNatRules,
          transitionNatJumps,
        });
      }
    };
    assertKnown(before);
    const transitionNatDocument = renderRestoreDocument({
      table: 'nat',
      chain: ROUTING_NAT_CHAIN,
      rules: transitionNatRules,
      jumps:
        transitionNatRules.length > 0
          ? [plan.parentNatJump ?? previousNatJump!]
          : [],
      observed: before,
    });
    await this.#testRestore(transitionNatDocument);
    await this.#testRestore(
      renderRestoreDocument({
        table: 'mangle',
        chain: ROUTING_MARK_CHAIN,
        rules: plan.markChainRules,
        jumps: plan.parentMarkJumps.map(({ args }) => args),
        observed: before,
        children: plan.classifier?.children,
      })
    );
    await this.#testRestore(
      renderRestoreDocument({
        table: 'nat',
        chain: ROUTING_NAT_CHAIN,
        rules: plan.natChainRules,
        jumps: plan.parentNatJump ? [plan.parentNatJump] : [],
        observed: before,
      })
    );
    return { before, transitionNatDocument, assertKnown };
  }

  async #applyOnce(
    plan: RoutingPlan,
    {
      afterPhase,
      previousNatRules = [],
      previousNatJump = null,
      onMutation,
      guardedTransition,
    }: {
      afterPhase?: ApplyOptions['afterPhase'];
      previousNatRules?: readonly string[][];
      previousNatJump?: string[] | null;
      onMutation: () => void;
      guardedTransition?: ApplyOptions['guardedTransition'];
    }
  ) {
    const { before, transitionNatDocument, assertKnown } =
      await this.#preparePlan(plan, {
        previousNatRules,
        previousNatJump,
        knownPlans: guardedTransition?.knownPlans,
      });
    const checkpoint = async (phase: RoutingApplyPhase) => {
      await afterPhase?.(phase);
      if (guardedTransition)
        await new RoutingGuard(this.#run).verify(guardedTransition.guard);
    };
    if (guardedTransition)
      await new RoutingGuard(this.#run).verify(guardedTransition.guard);
    await checkpoint('preflight');

    for (const route of plan.routes) {
      onMutation();
      await this.#run(route.command.executable, route.command.args);
    }
    await checkpoint('routes');

    const existingRuleKeys = new Set(
      before.policyRules
        .filter(({ protocol }) => protocol === WG_EASY_ROUTE_PROTOCOL)
        .map((rule) => ruleKey({ ...rule, protocol: WG_EASY_ROUTE_PROTOCOL }))
    );
    for (const rule of plan.policyRules) {
      if (existingRuleKeys.has(ruleKey(rule))) continue;
      onMutation();
      await this.#run(rule.command.executable, rule.command.args);
    }
    await checkpoint('rules');

    onMutation();
    await this.#restore(transitionNatDocument);
    await checkpoint('transition_nat');

    const afterNat = await this.observe();
    assertKnown(afterNat);
    await this.#restore(
      renderRestoreDocument({
        table: 'mangle',
        chain: ROUTING_MARK_CHAIN,
        rules: plan.markChainRules,
        jumps: plan.parentMarkJumps.map(({ args }) => args),
        observed: afterNat,
        children: plan.classifier?.children,
      })
    );
    await checkpoint('mark_activation');

    const afterMark = await this.observe();
    assertKnown(afterMark);
    await this.#restore(
      renderRestoreDocument({
        table: 'nat',
        chain: ROUTING_NAT_CHAIN,
        rules: plan.natChainRules,
        jumps: plan.parentNatJump ? [plan.parentNatJump] : [],
        observed: afterMark,
      })
    );
    await checkpoint('final_nat');

    const desiredRoutes = new Set(plan.routes.map(routeKey));
    const desiredRules = new Set(plan.policyRules.map(ruleKey));
    const afterActivation = await this.observe();
    assertKnown(afterActivation);
    const retainedChildren = new Set(
      plan.classifier?.children.map((c) => c.name) ?? []
    );
    const staleChildren = afterActivation.chains.filter(
      (c) =>
        c.table === 'mangle' &&
        c.name.startsWith(ROUTING_PROGRAM_CHAIN_PREFIX) &&
        !retainedChildren.has(c.name)
    );
    if (staleChildren.length)
      await this.#restore(
        [
          '*mangle',
          ...staleChildren.flatMap((c) => [`-F ${c.name}`, `-X ${c.name}`]),
          'COMMIT',
          '',
        ].join('\n')
      );
    for (const route of afterActivation.routes) {
      if (
        isOwnedRoutingRoute(route) &&
        !desiredRoutes.has(
          routeKey({
            ...route,
            protocol: WG_EASY_ROUTE_PROTOCOL,
          })
        )
      ) {
        await this.#run('ip', deleteRouteArgs(route));
      }
    }
    const retainedRuleKeys = new Set<string>();
    for (const rule of afterActivation.policyRules) {
      if (!isOwnedRoutingRule(rule)) continue;
      const key = ruleKey({
        ...rule,
        protocol: WG_EASY_ROUTE_PROTOCOL,
      });
      if (!desiredRules.has(key) || retainedRuleKeys.has(key)) {
        await this.#run('ip', deleteRuleArgs(rule));
      } else {
        retainedRuleKeys.add(key);
      }
    }
    await checkpoint('cleanup');

    await this.verify(plan, guardedTransition?.guard);
    await checkpoint('verify');
  }

  /** Read-only whole Linux verification; an explicit null requires guard absence. */
  async verify(plan: RoutingPlan, guard?: RoutingGuardPlan | null) {
    if (plan.classifier && guard === undefined)
      throw new Error('Routing policy guard observation is required');
    if (guard !== undefined) await new RoutingGuard(this.#run).verify(guard);
    const verified = await this.observe();
    if (guard !== undefined) {
      if (!verified.rawIptables)
        throw new Error('Routing policy observation is unavailable');
      assertRoutingPolicyChains(verified.rawIptables, [plan], { final: true });
    }
    const desiredRoutes = new Set(plan.routes.map(routeKey));
    const desiredRules = new Set(plan.policyRules.map(ruleKey));
    const verifiedOwnership = preflightRoutingOwnership(verified);
    if (!verifiedOwnership.ok) {
      throw new RoutingOwnershipConflictError(
        verifiedOwnership.conflicts
          .map(({ description }) => description)
          .join('; ')
      );
    }
    const ownedRoutes = verified.routes.filter(isOwnedRoutingRoute);
    const observedRouteKeys = new Set(
      ownedRoutes.map((route) =>
        routeKey({ ...route, protocol: WG_EASY_ROUTE_PROTOCOL })
      )
    );
    const ownedRules = verified.policyRules.filter(isOwnedRoutingRule);
    const observedRuleKeys = new Set(
      ownedRules.map((rule) =>
        ruleKey({ ...rule, protocol: WG_EASY_ROUTE_PROTOCOL })
      )
    );
    const ownedChainRules = verified.ownedChainRules ?? [];
    const observedChainRules = new Set(
      ownedChainRules.map(
        ({ table, line }) => `${table}:${canonicalizeIptablesRule(line)}`
      )
    );
    const desiredChainRules = new Set([
      ...plan.markChainRules.map(
        (args) => `mangle:${canonicalizeIptablesRule(restoreRule(args))}`
      ),
      ...(plan.classifier?.children.flatMap((c) => c.rules) ?? []).map(
        (args) => `mangle:${canonicalizeIptablesRule(restoreRule(args))}`
      ),
      ...plan.natChainRules.map(
        (args) => `nat:${canonicalizeIptablesRule(restoreRule(args))}`
      ),
    ]);
    const ownedParentJumps = verified.ownedParentJumps ?? [];
    const observedParentJumps = new Set(
      ownedParentJumps.map(({ table, line }) => `${table}:${line}`)
    );
    const desiredParentJumps = new Set([
      ...plan.parentMarkJumps.map(({ args }) => `mangle:${restoreRule(args)}`),
      ...(plan.parentNatJump ? [`nat:${restoreRule(plan.parentNatJump)}`] : []),
    ]);
    const verifiedChains = new Set(
      verified.chains
        .filter(({ owner }) => owner === 'wg-easy')
        .map(({ table, name }) => `${table}:${name}`)
    );
    const verificationIssues = [
      ownedRoutes.length !== desiredRoutes.size
        ? `route count mismatch (observed ${ownedRoutes.length}; desired ${desiredRoutes.size})`
        : null,
      ownedRules.length !== desiredRules.size
        ? `rule count mismatch (observed ${ownedRules.length}; desired ${desiredRules.size})`
        : null,
      ownedChainRules.length !== desiredChainRules.size
        ? `chain-rule count mismatch (observed ${ownedChainRules.length}; desired ${desiredChainRules.size})`
        : null,
      ownedParentJumps.length !== desiredParentJumps.size
        ? `parent-jump count mismatch (observed ${ownedParentJumps.length}; desired ${desiredParentJumps.size})`
        : null,
      setMismatch('routes', observedRouteKeys, desiredRoutes),
      setMismatch('rules', observedRuleKeys, desiredRules),
      setMismatch('chain rules', observedChainRules, desiredChainRules),
      setMismatch('parent jumps', observedParentJumps, desiredParentJumps),
      !verifiedChains.has(`mangle:${ROUTING_MARK_CHAIN}`)
        ? `missing owned mangle chain ${ROUTING_MARK_CHAIN}`
        : null,
      !verifiedChains.has(`nat:${ROUTING_NAT_CHAIN}`)
        ? `missing owned nat chain ${ROUTING_NAT_CHAIN}`
        : null,
    ].filter((issue): issue is string => issue !== null);
    if (verificationIssues.length > 0) {
      throw new Error(
        `Routing verification did not observe the complete plan: ${verificationIssues.join('; ')}`
      );
    }
  }

  async #restore(document: string) {
    await this.#testRestore(document);
    await this.#run('iptables-restore', ['--noflush'], {
      input: document,
      log: 'iptables-restore --noflush <generated-rules>',
    });
  }

  async #testRestore(document: string) {
    await this.#run('iptables-restore', ['--test', '--noflush'], {
      input: document,
      log: 'iptables-restore --test --noflush <generated-rules>',
    });
  }
}

export const routingExecutorTestExports = {
  parseProtocol,
  parseRules,
  parseRoutes,
  parseIptablesState,
  renderRestoreDocument,
};
