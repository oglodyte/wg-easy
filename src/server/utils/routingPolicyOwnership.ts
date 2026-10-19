import {
  ROUTING_MARK_CHAIN,
  ROUTING_NAT_CHAIN,
  ROUTING_OWNER_COMMENT,
  ROUTING_PROGRAM_CHAIN_PREFIX,
  type RoutingPlan,
} from '#server/utils/routing';

export const ROUTING_OWNER_MARKER = `${ROUTING_OWNER_COMMENT} owner`;
export function routingRestoreArgument(value: string) {
  return /^[A-Za-z0-9_./:=+-]+$/.test(value)
    ? value
    : `"${value.replaceAll('\\', '\\\\').replaceAll('"', '\\"')}"`;
}
export function routingRestoreRule(args: readonly string[]) {
  return args.map(routingRestoreArgument).join(' ');
}
export function canonicalRoutingRule(rule: string) {
  return rule
    .replace(/ -[sd] 0\.0\.0\.0\/0(?= |$)/g, '')
    .replace(/ --goto /g, ' -g ')
    .replace(/ --jump /g, ' -j ')
    .replace(
      /(--(?:set-xmark|set-mark|mark) )(0x[0-9a-f]+|\d+)(?:\/(0x[0-9a-f]+|\d+))?/gi,
      (_, flag: string, bits: string, mask?: string) =>
        `${flag}0x${(Number(bits) >>> 0).toString(16)}${mask ? `/0x${(Number(mask) >>> 0).toString(16)}` : ''}`
    );
}
function body(plan: RoutingPlan, table: 'mangle' | 'nat') {
  const name = table === 'mangle' ? ROUTING_MARK_CHAIN : ROUTING_NAT_CHAIN;
  return [
    `-A ${name} -m comment --comment "${ROUTING_OWNER_MARKER}"`,
    ...(table === 'mangle' ? plan.markChainRules : plan.natChainRules).map(
      routingRestoreRule
    ),
  ].map(canonicalRoutingRule);
}
function jumps(plan: RoutingPlan, table: 'mangle' | 'nat') {
  return (
    table === 'mangle'
      ? plan.parentMarkJumps.map((p) => p.args)
      : plan.parentNatJump
        ? [plan.parentNatJump]
        : []
  )
    .map(routingRestoreRule)
    .map(canonicalRoutingRule)
    .sort();
}
function same(a: readonly string[], b: readonly string[]) {
  return JSON.stringify(a) === JSON.stringify(b);
}
function fail(): never {
  throw new Error('Routing policy chain ownership is unknown');
}

/** Compare full known manifests; an owner-looking comment alone grants nothing. */
export function assertRoutingPolicyChains(
  tables: { mangle: string; nat: string },
  knownPlans: readonly RoutingPlan[],
  {
    transitionNatRules,
    transitionNatJumps,
    final = false,
  }: {
    transitionNatRules?: readonly string[][];
    transitionNatJumps?: readonly string[][];
    final?: boolean;
  } = {}
) {
  if (!knownPlans.length || knownPlans.length > 4) fail();
  const knownChildren = new Map<
    string,
    { fingerprint: string; rules: string[][] }
  >();
  for (const plan of knownPlans)
    for (const child of plan.classifier?.children ?? []) {
      if (
        !/^WG_RP_[a-f0-9]{16}$/.test(child.name) ||
        !/^[a-f0-9]{64}$/.test(child.fingerprint) ||
        child.name !==
          `${ROUTING_PROGRAM_CHAIN_PREFIX}${child.fingerprint.slice(0, 16)}`
      )
        fail();
      const before = knownChildren.get(child.name);
      if (
        before &&
        (before.fingerprint !== child.fingerprint ||
          !same(
            before.rules.map(routingRestoreRule),
            child.rules.map(routingRestoreRule)
          ))
      )
        fail();
      knownChildren.set(child.name, child);
    }
  for (const table of ['mangle', 'nat'] as const) {
    const lines = tables[table]
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean);
    const byChain = new Map<string, string[]>();
    for (const line of lines) {
      const name = line.match(/^-A (\S+) /)?.[1];
      if (!name) continue;
      const rules = byChain.get(name) ?? [];
      rules.push(canonicalRoutingRule(line));
      byChain.set(name, rules);
    }
    const root = table === 'mangle' ? ROUTING_MARK_CHAIN : ROUTING_NAT_CHAIN;
    const reserved = (name: string) =>
      name === root ||
      name.startsWith(ROUTING_PROGRAM_CHAIN_PREFIX) ||
      name === ROUTING_MARK_CHAIN ||
      name === ROUTING_NAT_CHAIN;
    const declarations = lines
      .flatMap((l) => l.match(/^:([^ ]+) /)?.[1] ?? [])
      .filter(reserved);
    if (new Set(declarations).size !== declarations.length) fail();
    const rootRules = byChain.get(root) ?? [];
    const rootRuleSet = new Set(rootRules);
    const references: string[] = [],
      childReferences: string[] = [];
    for (const line of lines) {
      const target = line.match(
        /(?: -j | --jump | -g | --goto )(\S+)(?: |$)/
      )?.[1];
      if (!target || !reserved(target)) continue;
      if (target === root) references.push(canonicalRoutingRule(line));
      else if (
        target.startsWith(ROUTING_PROGRAM_CHAIN_PREFIX) &&
        table === 'mangle'
      )
        childReferences.push(canonicalRoutingRule(line));
      else fail();
    }
    const knownRoots = knownPlans.map((p) => ({
      rules: body(p, table),
      jumps: jumps(p, table),
    }));
    // Crash recovery can observe the union prepared in either transition
    // direction. Only complete manifests from the last/pending plans qualify.
    if (table === 'nat')
      for (const before of knownPlans)
        for (const after of knownPlans) {
          const rules = [
            ...new Map(
              [...before.natChainRules, ...after.natChainRules].map((r) => [
                r.join('\u0000'),
                r,
              ])
            ).values(),
          ];
          const jump = after.parentNatJump ?? before.parentNatJump;
          knownRoots.push({
            rules: [
              `-A ${root} -m comment --comment "${ROUTING_OWNER_MARKER}"`,
              ...rules.map(routingRestoreRule),
            ].map(canonicalRoutingRule),
            jumps:
              rules.length && jump
                ? [canonicalRoutingRule(routingRestoreRule(jump))]
                : [],
          });
        }
    if (table === 'nat' && transitionNatRules && transitionNatJumps)
      knownRoots.push({
        rules: [
          `-A ${root} -m comment --comment "${ROUTING_OWNER_MARKER}"`,
          ...transitionNatRules.map(routingRestoreRule),
        ].map(canonicalRoutingRule),
        jumps: transitionNatJumps
          .map(routingRestoreRule)
          .map(canonicalRoutingRule)
          .sort(),
      });
    if (declarations.includes(root)) {
      if (
        !knownRoots.some(
          (r) =>
            same(r.rules, rootRules) && same(r.jumps, [...references].sort())
        )
      )
        fail();
    } else if (final || rootRules.length || references.length) fail();
    for (const name of declarations.filter((n) => n !== root)) {
      if (table !== 'mangle' || !name.startsWith(ROUTING_PROGRAM_CHAIN_PREFIX))
        fail();
      const expected = knownChildren.get(name);
      const actual = byChain.get(name) ?? [];
      if (
        !expected ||
        !same(
          actual,
          expected.rules.map(routingRestoreRule).map(canonicalRoutingRule)
        )
      )
        fail();
    }
    // A reserved child may only be referenced by the exact known root program.
    if (childReferences.some((l) => !rootRuleSet.has(l))) fail();
    for (const line of childReferences) {
      const name = line.match(/ -g (\S+)(?: |$)/)?.[1];
      if (!name || !declarations.includes(name) || !knownChildren.has(name))
        fail();
    }
    if (
      final &&
      table === 'mangle' &&
      knownPlans[0]!.classifier?.children.some(
        (c) => !declarations.includes(c.name)
      )
    )
      fail();
  }
}
