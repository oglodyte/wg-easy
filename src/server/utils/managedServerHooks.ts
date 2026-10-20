import { normalizeCidr, parseCidr } from 'cidr-tools';
import z from 'zod';

import { execFile } from '#server/utils/cmd';
import { LEGACY_IMPORT_DEFAULT_EGRESS } from '#shared/utils/importHooks';
import {
  InterfaceNameSchema,
  NetworkDeviceSchema,
} from '#shared/utils/schemas';

const phases = ['preup', 'postup', 'predown', 'postdown'] as const;
export type ManagedHookPhase = (typeof phases)[number];
const DEFAULT_DEVICE = '$OUT_IF';
// This is the exact read-only lookup recorded in the accepted staging baseline.
const dynamicLookup =
  'OUT_IF=$(ip -4 route show default | awk "NR == 1 {print \\$5}"); test -n "$OUT_IF" || exit 1;';
const MAX_RULES = 128;
const MAX_TOTAL_RULES = 4096;
const MAX_COUNT = 4096;

export class ManagedServerHookError extends Error {
  constructor(
    readonly code: string,
    readonly interfaceId?: string
  ) {
    super(`Managed server hooks: ${code}`);
    this.name = 'ManagedServerHookError';
  }
}

export type ManagedHookRule = {
  family: 4 | 6;
  table: 'filter' | 'nat';
  chain: 'INPUT' | 'FORWARD' | 'POSTROUTING';
  args: string[];
};
export type ManagedServerHooks = {
  interfaceId: string;
  dynamic: boolean;
  phases: Record<ManagedHookPhase, ManagedHookRule[]>;
};
export type ManagedHookCounts = {
  rule: ManagedHookRule;
  base: number;
  previous: number;
  target: number;
}[];

function fail(code = 'unsupported_script'): never {
  throw new ManagedServerHookError(code);
}
function device(value: string, dynamic: boolean) {
  if (dynamic && value === '"$OUT_IF"') return DEFAULT_DEVICE;
  const parsed = NetworkDeviceSchema.safeParse(value);
  if (!parsed.success || value.includes('+')) fail();
  return parsed.data;
}
export function managedHookRuleKey(rule: ManagedHookRule) {
  return JSON.stringify([rule.family, rule.table, rule.chain, rule.args]);
}
const ruleKey = managedHookRuleKey;
function parseRule(
  words: string[],
  up: boolean,
  dynamic: boolean
): ManagedHookRule {
  const command = words.shift();
  if (command !== 'iptables' && command !== 'ip6tables') fail();
  const family = command === 'iptables' ? 4 : 6;
  let table: 'nat' | 'filter' = 'filter';
  if (words[0] === '-t') {
    if (words[1] !== 'nat') fail();
    table = 'nat';
    words.splice(0, 2);
  }
  if (words.shift() !== (up ? '-A' : '-D')) fail();
  const chain = words.shift();
  if (table === 'nat') {
    if (
      chain !== 'POSTROUTING' ||
      words.length !== 6 ||
      words[0] !== '-s' ||
      words[2] !== '-o' ||
      words[4] !== '-j' ||
      words[5] !== 'MASQUERADE'
    )
      fail();
    const parsed = parseCidr(words[1]!);
    // The kernel elides an all-address source in -S output. Keep the admitted
    // grammar and its exact-count recovery identity unambiguous.
    if (
      !parsed.prefixPresent ||
      parsed.version !== family ||
      parsed.prefix === '0'
    )
      fail();
    return {
      family,
      table,
      chain,
      args: [
        '-s',
        normalizeCidr(words[1]!),
        '-o',
        device(words[3]!, dynamic),
        '-j',
        'MASQUERADE',
      ],
    };
  }
  if (
    chain === 'INPUT' &&
    words.length === 8 &&
    words[0] === '-p' &&
    words[1] === 'udp' &&
    words[2] === '-m' &&
    words[3] === 'udp' &&
    words[4] === '--dport' &&
    /^\d+$/.test(words[5]!) &&
    Number(words[5]) >= 1 &&
    Number(words[5]) <= 65535 &&
    words[6] === '-j' &&
    words[7] === 'ACCEPT'
  )
    return {
      family,
      table,
      chain,
      args: [...words.slice(0, 5), String(Number(words[5])), '-j', 'ACCEPT'],
    };
  if (
    chain === 'FORWARD' &&
    words.length === 4 &&
    (words[0] === '-i' || words[0] === '-o') &&
    words[2] === '-j' &&
    words[3] === 'ACCEPT'
  )
    return {
      family,
      table,
      chain,
      args: [words[0], device(words[1]!, false), '-j', 'ACCEPT'],
    };
  fail();
}
function multiplicities(rules: readonly ManagedHookRule[]) {
  const counts = new Map<string, { rule: ManagedHookRule; count: number }>();
  for (const rule of rules) {
    const key = ruleKey(rule),
      prior = counts.get(key);
    counts.set(key, { rule, count: (prior?.count ?? 0) + 1 });
  }
  return counts;
}

/** Closed grammar, not a shell-safety heuristic. Input is already templated. */
export function admitManagedServerHooks(
  interfaceId: string,
  fields: ReadonlyMap<string, string>
): ManagedServerHooks {
  try {
    InterfaceNameSchema.parse(interfaceId);
    const result: ManagedServerHooks = {
      interfaceId,
      dynamic: false,
      phases: { preup: [], postup: [], predown: [], postdown: [] },
    };
    let count = 0;
    for (const phase of phases) {
      let script = fields.get(phase) ?? '';
      if (script.length > 8192 || /[\r\n\0]/.test(script)) fail();
      const assignment = script.startsWith(dynamicLookup);
      if (assignment) {
        script = script.slice(dynamicLookup.length);
      }
      // Recognize the accepted import helper byte-for-byte, before splitting
      // its fixed awk program's semicolons. Never execute the substitution.
      const inline = script.includes(LEGACY_IMPORT_DEFAULT_EGRESS);
      if (inline && !assignment && script.includes('$OUT_IF')) fail();
      if (inline)
        script = script.replaceAll(LEGACY_IMPORT_DEFAULT_EGRESS, '"$OUT_IF"');
      const dynamic = assignment || inline;
      result.dynamic ||= dynamic;
      for (const statement of script.split(';')) {
        const text = statement.trim();
        if (!text) continue;
        if (++count > MAX_RULES) fail('rule_budget_exceeded');
        // Literal no-op markers preserve the golden baseline's PreUp marker.
        if (/^:(?:\s+[A-Za-z0-9_.:-]+)*$/.test(text)) continue;
        result.phases[phase].push(
          parseRule(text.split(/\s+/), phase.endsWith('up'), dynamic)
        );
      }
    }
    const up = multiplicities([
        ...result.phases.preup,
        ...result.phases.postup,
      ]),
      down = multiplicities([
        ...result.phases.predown,
        ...result.phases.postdown,
      ]);
    if (
      up.size !== down.size ||
      [...up].some(([key, entry]) => down.get(key)?.count !== entry.count)
    )
      fail('non_reversible_script');
    return result;
  } catch (error) {
    throw new ManagedServerHookError(
      error instanceof ManagedServerHookError
        ? error.code
        : 'unsupported_script',
      InterfaceNameSchema.safeParse(interfaceId).success
        ? interfaceId
        : undefined
    );
  }
}

/** Freeze dynamic egress once; recovery must not resolve it from a new route. */
export function resolveManagedServerHooks(
  hooks: ManagedServerHooks,
  defaultDevice?: string
): ManagedHookRule[] {
  return [
    ...resolveManagedServerHookPhase(hooks, 'preup', defaultDevice),
    ...resolveManagedServerHookPhase(hooks, 'postup', defaultDevice),
  ];
}
export function resolveManagedServerHookPhase(
  hooks: ManagedServerHooks,
  phase: ManagedHookPhase,
  defaultDevice?: string
): ManagedHookRule[] {
  if (hooks.dynamic && !NetworkDeviceSchema.safeParse(defaultDevice).success)
    throw new ManagedServerHookError(
      'default_egress_unavailable',
      hooks.interfaceId
    );
  return hooks.phases[phase].map((rule) => ({
    ...rule,
    args: rule.args.map((arg) =>
      arg === DEFAULT_DEVICE ? defaultDevice! : arg
    ),
  }));
}

const ruleSchema = z
  .object({
    family: z.union([z.literal(4), z.literal(6)]),
    table: z.enum(['filter', 'nat']),
    chain: z.enum(['INPUT', 'FORWARD', 'POSTROUTING']),
    args: z.array(z.string().max(128)).max(8),
  })
  .strict();
const countsSchema = z
  .array(
    z
      .object({
        rule: ruleSchema,
        base: z.number().int().min(0).max(MAX_COUNT),
        previous: z.number().int().min(0).max(MAX_COUNT),
        target: z.number().int().min(0).max(MAX_COUNT),
      })
      .strict()
  )
  .max(MAX_TOTAL_RULES * 2);

/** Private recovery input is strictly re-admitted, never executable argv from JSON. */
export function parseManagedHookCounts(value: unknown): ManagedHookCounts {
  try {
    const entries = countsSchema.parse(value),
      seen = new Set<string>();
    for (const entry of entries) {
      const rule = entry.rule,
        key = ruleKey(rule),
        checked = parseRule(
          [
            rule.family === 4 ? 'iptables' : 'ip6tables',
            ...(rule.table === 'nat' ? ['-t', 'nat'] : []),
            '-A',
            rule.chain,
            ...rule.args,
          ],
          true,
          false
        );
      if (
        seen.has(key) ||
        key !== ruleKey(checked) ||
        entry.base > Math.min(entry.previous, entry.target) ||
        Math.max(entry.previous, entry.target) - entry.base > MAX_TOTAL_RULES
      )
        fail('invalid_recovery_manifest');
      seen.add(key);
    }
    return entries;
  } catch {
    fail('invalid_recovery_manifest');
  }
}

type Runner = typeof execFile;
/** Only admitted effects; atomic chain replacement retains every foreign line. */
export class ManagedServerHookEffects {
  constructor(private readonly run: Runner = execFile) {}

  async defaultEgress() {
    try {
      const routes = JSON.parse(
        await this.run('ip', ['-j', '-4', 'route', 'show', 'default'], {
          log: false,
        })
      ) as { dev?: unknown }[];
      if (!Array.isArray(routes)) fail();
      const parsed = NetworkDeviceSchema.safeParse(routes[0]?.dev);
      if (!parsed.success) fail();
      return parsed.data;
    } catch {
      fail('default_egress_unavailable');
    }
  }

  private async chainRules(rule: ManagedHookRule) {
    try {
      const output = await this.run(
        rule.family === 4 ? 'iptables' : 'ip6tables',
        ['-w', '5', '-t', rule.table, '-S', rule.chain],
        { log: false }
      );
      const rules: string[] = [];
      for (const line of output.split('\n')) {
        if (!line) continue;
        if (line.startsWith(`-A ${rule.chain} `)) rules.push(line);
        else if (
          line !== `-N ${rule.chain}` &&
          line !== `-P ${rule.chain} ACCEPT` &&
          line !== `-P ${rule.chain} DROP`
        )
          fail('inspection_failed');
      }
      return rules;
    } catch {
      fail('inspection_failed');
    }
  }

  private async counts(rules: readonly ManagedHookRule[]) {
    const tables = new Map<string, Set<string>>();
    for (const rule of rules) {
      const key = `${rule.family}:${rule.table}`;
      if (!tables.has(key)) tables.set(key, new Set());
      tables.get(key)!.add(rule.chain);
    }
    const found = new Map<string, number>();
    try {
      for (const [key, chains] of tables) {
        const [family, table] = key.split(':');
        for (const chain of chains) {
          const lines = await this.chainRules({
            family: family === '4' ? 4 : 6,
            table: table as 'filter' | 'nat',
            chain: chain as ManagedHookRule['chain'],
            args: [],
          });
          for (const line of lines) {
            const words = line.trim().split(/\s+/);
            if (words[0] !== '-A' || words[1] !== chain) continue;
            // Foreign syntax is not interpreted or modified. Admitted rules
            // contain no whitespace/quotes in tokens and match exact -S output.
            const id = ruleKey({
              family: family === '4' ? 4 : 6,
              table: table as 'filter' | 'nat',
              chain: chain as ManagedHookRule['chain'],
              args: words.slice(2),
            });
            found.set(id, (found.get(id) ?? 0) + 1);
          }
        }
      }
    } catch {
      fail('inspection_failed');
    }
    return found;
  }

  async capture(
    previous: readonly ManagedHookRule[],
    target: readonly ManagedHookRule[],
    retained: readonly ManagedHookRule[] = []
  ): Promise<ManagedHookCounts> {
    if (
      previous.length + retained.length > MAX_TOTAL_RULES ||
      target.length + retained.length > MAX_TOTAL_RULES
    )
      fail('rule_budget_exceeded');
    const old = multiplicities(previous),
      next = multiplicities(target),
      stable = multiplicities(retained),
      all = new Map([...old, ...next, ...stable]);
    parseManagedHookCounts(
      [...all.values()].map(({ rule }) => ({
        rule,
        base: 0,
        previous: 0,
        target: 0,
      }))
    );
    const actual = await this.counts([...all.values()].map((r) => r.rule));
    return parseManagedHookCounts(
      [...all]
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([key, entry]) => {
          const count = actual.get(key) ?? 0,
            base = count - (old.get(key)?.count ?? 0);
          if (base < (stable.get(key)?.count ?? 0))
            fail('previous_effects_unverified');
          return {
            rule: entry.rule,
            base,
            previous: count,
            target: base + (next.get(key)?.count ?? 0),
          };
        })
    );
  }

  async verify(
    value: ManagedHookCounts,
    generation: 'previous' | 'target' | 'base'
  ) {
    const entries = parseManagedHookCounts(value),
      actual = await this.counts(entries.map((e) => e.rule));
    if (
      entries.some((e) => (actual.get(ruleKey(e.rule)) ?? 0) !== e[generation])
    )
      fail('effects_unverified');
  }

  /** Test every admitted old/base/target document before any managed mutation. */
  async prepare(value: ManagedHookCounts) {
    const entries = parseManagedHookCounts(value);
    for (const entry of entries) {
      const fresh = await this.chainRules(entry.rule),
        exact = `-A ${entry.rule.chain} ${entry.rule.args.join(' ')}`,
        indexes = fresh.flatMap((line, i) => (line === exact ? [i] : []));
      if (indexes.length !== entry.previous)
        fail('previous_effects_unverified');
      for (const wanted of new Set([
        entry.base,
        entry.previous,
        entry.target,
      ])) {
        const removed = new Set(indexes.slice(wanted)),
          replacement = fresh.filter((_, i) => !removed.has(i));
        for (let i = indexes.length; i < wanted; i++) replacement.push(exact);
        const document = [
          `*${entry.rule.table}`,
          `-F ${entry.rule.chain}`,
          ...replacement,
          'COMMIT',
          '',
        ].join('\n');
        try {
          await this.run(
            entry.rule.family === 4 ? 'iptables-restore' : 'ip6tables-restore',
            ['--test', '--noflush', '-w', '5'],
            { input: document, log: false }
          );
        } catch {
          fail('preflight_failed');
        }
      }
    }
  }

  async verifyRecoverable(value: ManagedHookCounts) {
    const entries = parseManagedHookCounts(value),
      actual = await this.counts(entries.map((e) => e.rule));
    for (const entry of entries) {
      const count = actual.get(ruleKey(entry.rule)) ?? 0;
      if (count < entry.base || count > Math.max(entry.previous, entry.target))
        fail('unknown_effects');
    }
  }

  async reconcile(
    value: ManagedHookCounts,
    generation: 'previous' | 'target' | 'base',
    verifyGuard: () => Promise<void>
  ) {
    const entries = parseManagedHookCounts(value),
      actual = await this.counts(entries.map((e) => e.rule));
    // Inspect all counts before changing any rule. Unknown edits are not cleanup.
    for (const entry of entries) {
      const count = actual.get(ruleKey(entry.rule)) ?? 0;
      if (count < entry.base || count > Math.max(entry.previous, entry.target))
        fail('unknown_effects');
    }
    for (const entry of entries) {
      const current = actual.get(ruleKey(entry.rule)) ?? 0;
      if (current !== entry[generation]) {
        await verifyGuard();
        // Detect concurrent changes before each exact mutation. A single
        // serialized coordinator owns admitted hooks; other edits cause refusal.
        const { rule } = entry,
          exact = `-A ${rule.chain} ${rule.args.join(' ')}`,
          fresh = await this.chainRules(rule),
          indexes = fresh.flatMap((line, index) =>
            line === exact ? [index] : []
          );
        if (indexes.length !== current) fail('effects_changed');
        // Preserve the baseline's first equal rules and every unrelated line
        // in place. Ordinary -D would remove the first equal foreign rule.
        const removed = new Set(indexes.slice(entry[generation])),
          replacement = fresh.filter((_, index) => !removed.has(index));
        for (let i = current; i < entry[generation]; i++)
          replacement.push(exact);
        const document = [
            `*${rule.table}`,
            `-F ${rule.chain}`,
            ...replacement,
            'COMMIT',
            '',
          ].join('\n'),
          binary = rule.family === 4 ? 'iptables-restore' : 'ip6tables-restore';
        try {
          await this.run(binary, ['--test', '--noflush', '-w', '5'], {
            input: document,
            log: false,
          });
          await verifyGuard();
          if (
            JSON.stringify(await this.chainRules(rule)) !==
            JSON.stringify(fresh)
          )
            fail('effects_changed');
          await this.run(binary, ['--noflush', '-w', '5'], {
            input: document,
            log: false,
          });
        } catch {
          fail('effect_repair_failed');
        }
        await verifyGuard();
      }
    }
    await this.verify(entries, generation);
  }
}
