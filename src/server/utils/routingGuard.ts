import { createHash } from 'node:crypto';

import { normalizeCidr, parseCidr } from 'cidr-tools';

import { execFile } from '#server/utils/cmd';
import { POLICY_LIMITS } from '#server/utils/routingPolicy';
import { InterfaceNameSchema } from '#shared/utils/schemas';

export const ROUTING_GUARD_CHAIN = 'WG_ROUTE_GUARD';
const OWNER = 'wg-easy routing guard';
const HOOKS = ['INPUT', 'FORWARD', 'OUTPUT'] as const;
type Hook = (typeof HOOKS)[number];

/** Matches are on the directional hook, never on a shared directionless body. */
export type RoutingGuardScope = {
  direction: 'input' | 'forward' | 'output';
  inputInterface?: string;
  outputInterface?: string;
  source: string;
  destination: string;
};
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
    if (parsed.version !== 4 || !parsed.prefixPresent) throw new Error();
    return normalizeCidr(value);
  } catch {
    throw new RoutingGuardError('invalid_scope');
  }
}
function normalized(scope: RoutingGuardScope): RoutingGuardScope {
  const source = cidr(scope.source);
  const destination = cidr(scope.destination);
  if (
    !['input', 'forward', 'output'].includes(scope.direction) ||
    (!scope.inputInterface &&
      !scope.outputInterface &&
      source === '0.0.0.0/0' &&
      destination === '0.0.0.0/0') ||
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
  return a.start <= b.end && b.start <= a.end;
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
function hookRules(plan: RoutingGuardPlan) {
  return plan.scopes.map((scope) => {
    const args = [
      '-A',
      hook(scope),
      ...(scope.source === '0.0.0.0/0' ? [] : ['-s', scope.source]),
      ...(scope.destination === '0.0.0.0/0' ? [] : ['-d', scope.destination]),
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
  expected: RoutingGuardPlan | null
) {
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
  const desired = hookRules(expected);
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
  expected: RoutingGuardPlan | null
) {
  assertRoutingGuardState(save, expected);
  if (!expected) return [];
  const rules = hookRules(expected);
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
  previous: RoutingGuardPlan | null
) {
  assertRoutingGuardState(save, previous);
  if (target) checked(target);
  if (!target && !previous) return null;
  return [
    '*filter',
    ...(target ? [`:${ROUTING_GUARD_CHAIN} - [0:0]`] : []),
    ...(previous
      ? hookRules(previous).map((line) => line.replace(/^-A /, '-D '))
      : []),
    `-F ${ROUTING_GUARD_CHAIN}`,
    ...(target
      ? [
          ...bodyRules(target),
          ...hookRules(target)
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

  async observe() {
    return this.run('iptables-save', ['-t', 'filter']);
  }

  async verify(plan: RoutingGuardPlan | null) {
    assertRoutingGuardState(await this.observe(), plan);
  }

  async prepare(
    target: RoutingGuardPlan | null,
    previous: RoutingGuardPlan | null
  ) {
    const document = routingGuardRestoreDocument(
      await this.observe(),
      target,
      previous
    );
    if (document)
      await this.run('iptables-restore', ['--test', '--noflush'], {
        input: document,
        log: 'iptables-restore --test --noflush <routing-guard>',
      });
    return document;
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

  private async replace(
    target: RoutingGuardPlan | null,
    previous: RoutingGuardPlan | null
  ) {
    const document = await this.prepare(target, previous);
    if (document)
      await this.run('iptables-restore', ['--noflush'], {
        input: document,
        log: 'iptables-restore --noflush <routing-guard>',
      });
    // Failed observation keeps the guard in place; never silently undo it.
    await this.verify(target);
  }
}
