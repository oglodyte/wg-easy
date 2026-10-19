import {
  canonicalClientFirewallRule,
  clientFirewallRuleArguments,
  validateClientFirewallPolicy,
} from '#server/utils/clientFirewallPolicy';
import { execFile } from '#server/utils/cmd';
import {
  buildClientFirewallManifest,
  buildClientFirewallRestore,
} from '#server/utils/firewall';
import {
  routingGuardRepositionRules,
  type RoutingGuardPlan,
} from '#server/utils/routingGuard';
import type { PolicyClientFirewall } from '#shared/types/routingPolicy';

const CHAIN = 'WG_CLIENTS';
export class RoutingPolicyFirewallError extends Error {
  constructor(
    readonly code: string,
    readonly family?: 4 | 6
  ) {
    super(`Routing client firewall: ${code}`);
    this.name = 'RoutingPolicyFirewallError';
  }
}
function same(a: readonly string[], b: readonly string[]) {
  return JSON.stringify(a) === JSON.stringify(b);
}
function observe(save: string) {
  const lines = save
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean);
  const declarations = lines.filter((l) => l.startsWith(`:${CHAIN} `));
  const body = lines
    .filter((l) => l.startsWith(`-A ${CHAIN} `))
    .map(canonicalClientFirewallRule);
  const references = lines
    .filter((l) => {
      if (!l.startsWith('-A ')) return false;
      const args = clientFirewallRuleArguments(l);
      for (let i = 0; i < args.length; i++) {
        if (args[i] === '--comment') i++;
        else if (
          ['-j', '-g', '--jump', '--goto'].includes(args[i]!) &&
          args[i + 1] === CHAIN
        )
          return true;
      }
      return false;
    })
    .map(canonicalClientFirewallRule);
  if (
    declarations.length > 1 ||
    (declarations.length === 1 &&
      !declarations[0]!.startsWith(`:${CHAIN} - `)) ||
    (!declarations.length && (body.length || references.length))
  )
    throw new RoutingPolicyFirewallError('ownership_unknown');
  return { lines, exists: declarations.length === 1, body, references };
}
function assertKnown(
  save: string,
  known: readonly PolicyClientFirewall[],
  family: 4 | 6,
  allowAbsent: boolean
) {
  const observed = observe(save);
  if (!observed.exists && allowAbsent) return;
  const matched = known.find((p) => {
    const manifest = buildClientFirewallManifest(p, family);
    return (
      same(observed.body, manifest.body.map(canonicalClientFirewallRule)) &&
      same(observed.references, manifest.jumps.map(canonicalClientFirewallRule))
    );
  });
  if (!observed.exists || !matched)
    throw new RoutingPolicyFirewallError('ownership_unknown', family);
  assertHookOrder(save, matched, family);
}
function assertHookOrder(
  save: string,
  plan: PolicyClientFirewall,
  family: 4 | 6
) {
  const desired = buildClientFirewallManifest(plan, family).jumps.map(
    canonicalClientFirewallRule
  );
  if (!desired.length) return;
  const forward = save
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l.startsWith('-A FORWARD '));
  // Guard placement is independently checked against its full exact manifest.
  const withoutGuards = forward
    .filter((l) => family !== 4 || !l.endsWith('-j WG_ROUTE_GUARD'))
    .map(canonicalClientFirewallRule);
  if (!same(withoutGuards.slice(0, desired.length), desired))
    throw new RoutingPolicyFirewallError('filter_hook_unverified', family);
}

/** Runs only within the existing coordinator's guarded transaction. */
export class RoutingPolicyFirewall {
  constructor(private readonly run: typeof execFile = execFile) {}

  private async safe<T>(code: string, work: () => Promise<T>): Promise<T> {
    try {
      return await work();
    } catch (error) {
      if (error instanceof RoutingPolicyFirewallError) throw error;
      throw new RoutingPolicyFirewallError(code);
    }
  }

  private async documents(
    target: PolicyClientFirewall,
    known: readonly PolicyClientFirewall[],
    guard: RoutingGuardPlan | null,
    allowAbsent: boolean
  ) {
    const plans = [target, ...known].map(validateClientFirewallPolicy);
    if (known.length > 4)
      throw new RoutingPolicyFirewallError('ownership_unknown');
    const families: (4 | 6)[] = plans.some((p) => p.enableIpv6) ? [4, 6] : [4];
    const documents = [];
    for (const family of families) {
      const binary = family === 4 ? 'iptables' : 'ip6tables';
      const save = await this.run(`${binary}-save`, ['-t', 'filter'], {
        log: false,
      });
      assertKnown(save, plans, family, allowAbsent);
      const hooks =
        family === 4 ? routingGuardRepositionRules(save, guard) : [];
      documents.push({
        family,
        binary,
        document: buildClientFirewallRestore(
          buildClientFirewallManifest(target, family),
          save,
          hooks
        ),
      });
    }
    for (const { binary, document } of documents)
      await this.run(`${binary}-restore`, ['--test', '--noflush'], {
        input: document,
        log: false,
      });
    return documents;
  }

  async prepare(
    target: PolicyClientFirewall,
    known: readonly PolicyClientFirewall[],
    guard: RoutingGuardPlan | null,
    { allowAbsent = false } = {}
  ) {
    await this.safe('preflight_failed', () =>
      this.documents(target, known, guard, allowAbsent)
    );
  }

  async apply(
    target: PolicyClientFirewall,
    known: readonly PolicyClientFirewall[],
    guard: RoutingGuardPlan,
    { allowAbsent = false } = {}
  ) {
    await this.safe('application_failed', async () => {
      const documents = await this.documents(target, known, guard, allowAbsent);
      for (const { binary, document } of documents)
        await this.run(`${binary}-restore`, ['--noflush'], {
          input: document,
          log: false,
        });
      await this.verify(target, guard, { inspectIpv6: documents.length === 2 });
    });
  }

  async verify(
    target: PolicyClientFirewall,
    guard: RoutingGuardPlan | null,
    { inspectIpv6 = target.enableIpv6 } = {}
  ) {
    await this.safe('verification_failed', async () => {
      validateClientFirewallPolicy(target);
      for (const family of (inspectIpv6 ? [4, 6] : [4]) as (4 | 6)[]) {
        const save = await this.run(
          family === 4 ? 'iptables-save' : 'ip6tables-save',
          ['-t', 'filter'],
          { log: false }
        );
        assertKnown(save, [target], family, false);
        if (family === 4) routingGuardRepositionRules(save, guard);
      }
    });
  }
}
