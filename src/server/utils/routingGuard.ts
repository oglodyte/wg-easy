import { createHash } from 'node:crypto';

import { normalizeCidr, parseCidr } from 'cidr-tools';

import { execFile } from '#server/utils/cmd';
import { POLICY_LIMITS } from '#server/utils/routingPolicy';
import { InterfaceNameSchema } from '#shared/utils/schemas';
import type { RoutingPolicyGuardScope } from '#shared/types/routingPolicy';

export const ROUTING_GUARD_CHAIN = 'WG_ROUTE_GUARD';
const OWNER = 'wg-easy routing guard';
const HOOKS = ['INPUT', 'FORWARD', 'OUTPUT'] as const;
type Hook = (typeof HOOKS)[number];

/** Matches are on the directional hook, never on a shared directionless body. */
export type RoutingGuardScope = RoutingPolicyGuardScope;
export type RoutingGuardPlan = {
  fingerprint: string;
  scopes: RoutingGuardScope[];
};
type Runner = typeof execFile;

export class RoutingGuardError extends Error {
  constructor(
    readonly code: string,
    readonly detail: { actual?: number; limit?: number } = {}
  ) {
    super(`Routing guard: ${code}`);
    this.name = 'RoutingGuardError';
  }
}

function cidr(value: string) {
  try {
    const parsed = parseCidr(value);
    if (!parsed.prefixPresent) throw new Error();
    return normalizeCidr(value);
  } catch {
    throw new RoutingGuardError('invalid_scope');
  }
}
function normalized(scope: RoutingGuardScope): RoutingGuardScope {
  const source = cidr(scope.source);
  const destination = cidr(scope.destination);
  const sourceRange = parseCidr(source),
    destinationRange = parseCidr(destination);
  if (
    sourceRange.version !== destinationRange.version ||
    !['input', 'forward', 'output'].includes(scope.direction) ||
    (!scope.inputInterface &&
      !scope.outputInterface &&
      sourceRange.prefix === '0' &&
      destinationRange.prefix === '0') ||
    (scope.direction === 'input' && scope.outputInterface) ||
    (scope.direction === 'output' && scope.inputInterface)
  )
    throw new RoutingGuardError('invalid_scope');
  const input = scope.inputInterface
    ? InterfaceNameSchema.safeParse(scope.inputInterface)
    : undefined;
  const output = scope.outputInterface
    ? InterfaceNameSchema.safeParse(scope.outputInterface)
    : undefined;
  if (input?.success === false || output?.success === false)
    throw new RoutingGuardError('invalid_scope');
  return {
    direction: scope.direction,
    ...(input?.success ? { inputInterface: input.data } : {}),
    ...(output?.success ? { outputInterface: output.data } : {}),
    source,
    destination,
  };
}
function intersects(left: string, right: string) {
  const a = parseCidr(left);
  const b = parseCidr(right);
  return a.version === b.version && a.start <= b.end && b.start <= a.end;
}
function scopesIntersect(a: RoutingGuardScope, b: RoutingGuardScope) {
  return (
    a.direction === b.direction &&
    (!a.inputInterface ||
      !b.inputInterface ||
      a.inputInterface === b.inputInterface) &&
    (!a.outputInterface ||
      !b.outputInterface ||
      a.outputInterface === b.outputInterface) &&
    intersects(a.source, b.source) &&
    intersects(a.destination, b.destination)
  );
}

/** Callers supply the observed independent management/control paths explicitly. */
export function buildRoutingGuard(
  scopes: readonly RoutingGuardScope[],
  { protectedPaths }: { protectedPaths: readonly RoutingGuardScope[] }
): RoutingGuardPlan {
  const protectedScopes = protectedPaths.map(normalized);
  const unique = new Map<string, RoutingGuardScope>();
  for (const raw of scopes) {
    const scope = normalized(raw);
    if (protectedScopes.some((path) => scopesIntersect(scope, path)))
      throw new RoutingGuardError('management_collision');
    unique.set(JSON.stringify(scope), scope);
    if (unique.size > POLICY_LIMITS.guardRules)
      throw new RoutingGuardError('rule_budget_exceeded', {
        actual: unique.size,
        limit: POLICY_LIMITS.guardRules,
      });
  }
  const ordered = [...unique.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([, scope]) => scope);
  return {
    fingerprint: createHash('sha256')
      .update(JSON.stringify(ordered))
      .digest('hex'),
    scopes: ordered,
  };
}
function checked(plan: RoutingGuardPlan) {
  const canonical = buildRoutingGuard(plan.scopes, { protectedPaths: [] });
  if (
    plan.fingerprint !== canonical.fingerprint ||
    JSON.stringify(plan.scopes) !== JSON.stringify(canonical.scopes)
  )
    throw new RoutingGuardError('invalid_manifest');
  return canonical;
}
function hook(scope: RoutingGuardScope): Hook {
  return scope.direction.toUpperCase() as Hook;
}
export function routingGuardHasFamily(
  plan: RoutingGuardPlan | null,
  family: 4 | 6
) {
  return (
    plan !== null &&
    (family === 4 ||
      plan.scopes.some((s) => parseCidr(s.source).version === family))
  );
}
function hookRules(plan: RoutingGuardPlan, family: 4 | 6) {
  return plan.scopes
    .filter((s) => parseCidr(s.source).version === family)
    .map((scope) => {
      const args = [
        '-A',
        hook(scope),
        ...(parseCidr(scope.source).prefix === '0' ? [] : ['-s', scope.source]),
        ...(parseCidr(scope.destination).prefix === '0'
          ? []
          : ['-d', scope.destination]),
        ...(scope.inputInterface ? ['-i', scope.inputInterface] : []),
        ...(scope.outputInterface ? ['-o', scope.outputInterface] : []),
      ];
      return `${args.join(' ')} -m comment --comment "${OWNER} scope" -j ${ROUTING_GUARD_CHAIN}`;
    });
}
function bodyRules(plan: RoutingGuardPlan) {
  return [
    `-A ${ROUTING_GUARD_CHAIN} -m comment --comment "${OWNER} owner ${plan.fingerprint}"`,
    `-A ${ROUTING_GUARD_CHAIN} -m comment --comment "${OWNER} drop" -j DROP`,
  ];
}
function lines(save: string) {
  return save
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean);
}
function references(save: string) {
  return lines(save).filter((line) =>
    new RegExp(`(?:^|\\s)-(?:j|g) ${ROUTING_GUARD_CHAIN}(?:\\s|$)`).test(line)
  );
}

/** Refuse every unrecognized rule/reference, duplicate, or bypassing hook. */
export function assertRoutingGuardState(
  save: string,
  expected: RoutingGuardPlan | null,
  family: 4 | 6 = 4
) {
  if (!routingGuardHasFamily(expected, family)) expected = null;
  const saved = lines(save);
  const declarations = saved.filter((line) =>
    line.startsWith(`:${ROUTING_GUARD_CHAIN} `)
  );
  const body = saved.filter((line) =>
    line.startsWith(`-A ${ROUTING_GUARD_CHAIN} `)
  );
  const refs = references(save);
  if (!expected) {
    if (declarations.length || body.length || refs.length)
      throw new RoutingGuardError('unowned_or_residual_guard');
    return;
  }
  checked(expected);
  const desired = hookRules(expected, family);
  if (
    declarations.length !== 1 ||
    !declarations[0]!.startsWith(`:${ROUTING_GUARD_CHAIN} - `) ||
    JSON.stringify(body) !== JSON.stringify(bodyRules(expected)) ||
    refs.length !== desired.length ||
    [...refs].sort().join('\n') !== [...desired].sort().join('\n')
  )
    throw new RoutingGuardError('ownership_or_manifest_mismatch');
  for (const parent of HOOKS) {
    const wanted = desired.filter((line) => line.startsWith(`-A ${parent} `));
    const actual = saved.filter((line) => line.startsWith(`-A ${parent} `));
    if (
      JSON.stringify(actual.slice(0, wanted.length)) !== JSON.stringify(wanted)
    )
      throw new RoutingGuardError('hook_bypassed');
  }
}

/** Append after other owned insertions within the same filter transaction. */
export function routingGuardRepositionRules(
  save: string,
  expected: RoutingGuardPlan | null,
  family: 4 | 6 = 4
) {
  assertRoutingGuardState(save, expected, family);
  if (!expected || !routingGuardHasFamily(expected, family)) return [];
  const rules = hookRules(expected, family);
  return [
    ...rules.map((line) => line.replace(/^-A /, '-D ')),
    ...[...rules]
      .reverse()
      .map((line) => line.replace(/^-A (INPUT|FORWARD|OUTPUT) /, '-I $1 1 ')),
  ];
}

export function routingGuardRestoreDocument(
  save: string,
  target: RoutingGuardPlan | null,
  previous: RoutingGuardPlan | null,
  family: 4 | 6 = 4
) {
  assertRoutingGuardState(save, previous, family);
  if (target) checked(target);
  if (!routingGuardHasFamily(target, family)) target = null;
  if (!routingGuardHasFamily(previous, family)) previous = null;
  if (!target && !previous) return null;
  return [
    '*filter',
    ...(target ? [`:${ROUTING_GUARD_CHAIN} - [0:0]`] : []),
    ...(previous
      ? hookRules(previous, family).map((line) => line.replace(/^-A /, '-D '))
      : []),
    `-F ${ROUTING_GUARD_CHAIN}`,
    ...(target
      ? [
          ...bodyRules(target),
          ...hookRules(target, family)
            .reverse()
            .map((line) =>
              line.replace(/^-A (INPUT|FORWARD|OUTPUT) /, '-I $1 1 ')
            ),
        ]
      : [`-X ${ROUTING_GUARD_CHAIN}`]),
    'COMMIT',
    '',
  ].join('\n');
}

/** Inactive until the Phase 2 coordinator owns the whole guarded transition. */
export class RoutingGuard {
  constructor(private readonly run: Runner = execFile) {}

  async observe(family: 4 | 6 = 4) {
    return this.run(family === 4 ? 'iptables-save' : 'ip6tables-save', [
      '-t',
      'filter',
    ]);
  }

  async verify(
    plan: RoutingGuardPlan | null,
    { families = this.families(plan) }: { families?: readonly (4 | 6)[] } = {}
  ) {
    for (const family of families)
      assertRoutingGuardState(await this.observe(family), plan, family);
  }

  private families(...plans: (RoutingGuardPlan | null)[]): (4 | 6)[] {
    return plans.some((p) => routingGuardHasFamily(p, 6)) ? [4, 6] : [4];
  }

  private async prepareAll(
    target: RoutingGuardPlan | null,
    previous: RoutingGuardPlan | null,
    repairMissing = false
  ) {
    if (target) checked(target);
    if (previous) checked(previous);
    const documents: { family: 4 | 6; document: string }[] = [];
    for (const family of this.families(target, previous)) {
      const save = await this.observe(family);
      let observedPrevious = previous;
      if (repairMissing) {
        try {
          assertRoutingGuardState(save, target, family);
          continue;
        } catch {
          /* Only exact absence permits restoration of a missing family. */
        }
        // A namespace rebase may have committed either family's old or new
        // guard. Only an exact persisted previous body or absence is admitted.
        try {
          if (!previous) throw new Error();
          assertRoutingGuardState(save, previous, family);
        } catch {
          assertRoutingGuardState(save, null, family);
          observedPrevious = null;
        }
      }
      const document = routingGuardRestoreDocument(
        save,
        target,
        observedPrevious,
        family
      );
      if (document) documents.push({ family, document });
    }
    // Read/validate every family before testing or writing either table.
    for (const { family, document } of documents)
      await this.run(
        family === 4 ? 'iptables-restore' : 'ip6tables-restore',
        ['--test', '--noflush'],
        {
          input: document,
          log: '<routing-guard-preflight>',
        }
      );
    return documents;
  }

  async prepare(
    target: RoutingGuardPlan | null,
    previous: RoutingGuardPlan | null
  ) {
    const documents = await this.prepareAll(target, previous);
    return documents.find((d) => d.family === 4)?.document ?? null;
  }

  async install(
    target: RoutingGuardPlan,
    previous: RoutingGuardPlan | null = null
  ) {
    await this.replace(target, previous);
  }

  async remove(previous: RoutingGuardPlan) {
    await this.replace(null, previous);
  }

  /** A crash may leave only one of the two exact known family guards. */
  async ensure(
    target: RoutingGuardPlan,
    previous: RoutingGuardPlan | null = null
  ) {
    const documents = await this.prepareAll(target, previous, true);
    await this.write(documents);
    await this.verify(target, { families: this.families(target, previous) });
  }

  private async write(
    documents: readonly { family: 4 | 6; document: string }[]
  ) {
    for (const { family, document } of documents)
      await this.run(
        family === 4 ? 'iptables-restore' : 'ip6tables-restore',
        ['--noflush'],
        {
          input: document,
          log: '<routing-guard-replacement>',
        }
      );
  }

  private async replace(
    target: RoutingGuardPlan | null,
    previous: RoutingGuardPlan | null
  ) {
    const documents = await this.prepareAll(target, previous);
    await this.write(documents);
    // Failed observation keeps the guard in place; never silently undo it.
    await this.verify(target, { families: this.families(target, previous) });
  }
}
