import { describe, expect, test } from 'vitest';

import {
  FWMARK_MASK,
  WG_EASY_ROUTE_PROTOCOL,
  buildRoutingPlan,
  buildSafetyRoutingPlan,
  formatMark,
  type RoutingPlan,
} from '#server/utils/routing';
import {
  RoutingExecutor,
  RoutingOwnershipConflictError,
  routingExecutorTestExports,
  type RoutingApplyPhase,
} from '#server/utils/routingExecutor';

type RecordedCommand = {
  executable: string;
  args: string[];
  input?: string;
};

class FakeLinuxRouting {
  readonly commands: RecordedCommand[] = [];
  readonly rules = new Map<string, Record<string, unknown>>();
  readonly routes = new Map<string, Record<string, unknown>>();
  tables = { mangle: '', nat: '' };

  run = async (
    executable: string,
    args: readonly string[] = [],
    options: { input?: string } = {}
  ) => {
    this.commands.push({ executable, args: [...args], input: options.input });
    if (args.includes('--version') || args.includes('-Version')) return 'ok';
    if (executable === 'iptables-save') {
      return args.at(-1) === 'mangle' ? this.tables.mangle : this.tables.nat;
    }
    if (executable === 'iptables-restore') {
      if (args.includes('--test')) return '';
      this.installRestore(options.input ?? '');
      return '';
    }
    if (executable !== 'ip') return '';
    if (args.includes('show')) return this.show(args);
    if (args[1] === 'route') this.mutateRoute(args);
    if (args[1] === 'rule') this.mutateRule(args);
    return '';
  };

  private show(args: readonly string[]) {
    const family = Number(args[1] === '-4' ? 4 : 6);
    if (args.includes('rule')) {
      return JSON.stringify(
        [...this.rules.values()].filter((rule) => rule.family === family)
      );
    }
    return JSON.stringify(
      [...this.routes.values()].filter((route) => route.family === family)
    );
  }

  private mutateRoute(args: readonly string[]) {
    const family = args[0] === '-4' ? 4 : 6;
    const operation = args[2];
    const unreachable = args[3] === 'unreachable';
    const prefixIndex = unreachable ? 4 : 3;
    const prefix = args[prefixIndex]!;
    const table = Number(args[args.indexOf('table') + 1]);
    const protocol = Number(args[args.indexOf('proto') + 1]);
    const key = `${family}:${table}:${protocol}:${prefix}`;
    if (operation === 'del') {
      this.routes.delete(key);
      return;
    }
    const deviceIndex = args.indexOf('dev');
    this.routes.set(key, {
      family,
      table,
      protocol,
      dst: prefix,
      type: unreachable ? 'unreachable' : 'unicast',
      ...(deviceIndex >= 0 ? { dev: args[deviceIndex + 1] } : {}),
    });
  }

  private mutateRule(args: readonly string[]) {
    const family = args[0] === '-4' ? 4 : 6;
    const operation = args[2];
    const priority = Number(args[args.indexOf('priority') + 1]);
    const table = Number(args[args.indexOf('table') + 1]);
    const protocol = Number(args[args.indexOf('protocol') + 1]);
    const fwmarkIndex = args.indexOf('fwmark');
    const fwmark = fwmarkIndex >= 0 ? args[fwmarkIndex + 1] : undefined;
    const key = `${family}:${priority}`;
    if (operation === 'del') {
      this.rules.delete(key);
      return;
    }
    this.rules.set(key, {
      family,
      priority,
      table,
      protocol,
      ...(fwmark ? { fwmark } : {}),
    });
  }

  private installRestore(document: string) {
    const table = document.startsWith('*mangle') ? 'mangle' : 'nat';
    this.tables[table] = document
      .split('\n')
      .filter(
        (line) =>
          line.startsWith(':') ||
          line.startsWith('-A ') ||
          line.startsWith('-I ')
      )
      .map((line) => line.replace(/^-I (\S+) 1 /, '-A $1 '))
      .join('\n');
  }
}

const interfaces = [
  {
    interfaceId: 'wg0',
    ipv4Cidr: '10.8.0.0/24',
    enabled: true,
    observedUp: true,
  },
  {
    interfaceId: 'awg1',
    ipv4Cidr: '10.9.0.0/24',
    enabled: true,
    observedUp: true,
  },
  {
    interfaceId: 'awg2',
    ipv4Cidr: '10.10.0.0/24',
    enabled: true,
    observedUp: true,
  },
];

const clients = [
  {
    id: 1,
    interfaceId: 'wg0',
    ipv4Address: '10.8.0.2',
    enabled: true,
    serverAllowedIps: [],
  },
  {
    id: 2,
    interfaceId: 'awg1',
    ipv4Address: '10.9.0.2',
    enabled: true,
    serverAllowedIps: [],
  },
  {
    id: 3,
    interfaceId: 'awg2',
    ipv4Address: '10.10.0.2',
    enabled: true,
    serverAllowedIps: [],
  },
];

function plan(selectedExitClientId: number | null): RoutingPlan {
  return buildRoutingPlan({
    interfaces,
    clients,
    groups: [
      {
        id: 1,
        routingSlot: 1,
        enabled: true,
        natEnabled: true,
        allExitsDownPolicy: 'block',
        routedIpv4Prefixes: ['203.0.113.0/24'],
        memberClientIds: [1],
        selectedExitClientId,
      },
    ],
  });
}

describe('Phase 6 routing execution', () => {
  test('keeps prior peer ownership while installing transition block policy', () => {
    const previous = plan(2);
    const bootstrap = plan(null);
    const safety = buildSafetyRoutingPlan({
      previous,
      bootstrap,
      blockGroupIds: new Set([1]),
    });

    expect(safety.groups).toContainEqual(
      expect.objectContaining({ outcome: 'block', selectedExitClientId: null })
    );
    expect(safety.routes).toContainEqual(
      expect.objectContaining({ type: 'unreachable' })
    );
    expect(safety.peerAllowedIps).toEqual(previous.peerAllowedIps);
    expect(safety.natChainRules).toEqual([]);
  });

  test('parses exact owned chains and masked marks', () => {
    const parsed = routingExecutorTestExports.parseIptablesState(
      `:WG_ROUTE_MARK - [0:0]\n-A WG_ROUTE_MARK -m comment --comment "wg-easy common routing owner"\n-A WG_ROUTE_MARK -s 10.8.0.2/32 -m comment --comment "wg-easy common routing group 1" -j MARK --set-xmark 0x54010000/0xffff0000\n-A PREROUTING -i wg0 -m comment --comment "wg-easy common routing" -j WG_ROUTE_MARK`,
      ''
    );

    expect(parsed.chains).toEqual([
      { table: 'mangle', name: 'WG_ROUTE_MARK', owner: 'wg-easy' },
    ]);
    expect(parsed.markUses).toContainEqual({
      value: 0x54010000,
      mask: FWMARK_MASK,
      owner: 'wg-easy',
    });
    expect(parsed.ownedParentJumps).toHaveLength(1);
  });

  test('normalizes iproute2 protocol names, split masks, and host prefixes', () => {
    expect(
      routingExecutorTestExports.parseRules(
        '[{"priority":22001,"fwmark":"0x54010000","fwmask":"0xffff0000","table":"52001","protocol":"bgp"}]',
        4
      )
    ).toEqual([
      {
        family: 4,
        priority: 22001,
        table: 52001,
        protocol: WG_EASY_ROUTE_PROTOCOL,
        fwmark: 0x54010000,
        mask: FWMARK_MASK,
      },
    ]);
    expect(
      routingExecutorTestExports.parseRoutes(
        '[{"dst":"172.31.0.100","dev":"awg1","table":"52001","protocol":"bgp","flags":[]}]',
        4
      )
    ).toEqual([
      {
        family: 4,
        table: 52001,
        protocol: WG_EASY_ROUTE_PROTOCOL,
        prefix: '172.31.0.100/32',
        type: 'unicast',
        device: 'awg1',
      },
    ]);
  });

  test('prepares routes and rules before atomically activating marks', async () => {
    const linux = new FakeLinuxRouting();
    const phases: RoutingApplyPhase[] = [];
    const desired = plan(2);

    await new RoutingExecutor(linux.run).apply(desired, {
      afterPhase: (phase) => phases.push(phase),
    });

    expect(phases).toEqual([
      'preflight',
      'routes',
      'rules',
      'transition_nat',
      'mark_activation',
      'final_nat',
      'cleanup',
      'verify',
    ]);
    const routeIndex = linux.commands.findIndex(
      ({ executable, args }) => executable === 'ip' && args[1] === 'route'
    );
    const ruleIndex = linux.commands.findIndex(
      ({ executable, args }) => executable === 'ip' && args[1] === 'rule'
    );
    const markIndex = linux.commands.findIndex(
      ({ executable, args, input }) =>
        executable === 'iptables-restore' &&
        !args.includes('--test') &&
        input?.startsWith('*mangle')
    );
    expect(routeIndex).toBeLessThan(ruleIndex);
    expect(ruleIndex).toBeLessThan(markIndex);
    expect(linux.tables.mangle).toContain('WG_ROUTE_MARK');
    expect(linux.tables.nat).toContain('-o awg1');
  });

  test('reuses an exact owned policy rule without unsupported replacement or duplication', async () => {
    const linux = new FakeLinuxRouting();
    const executor = new RoutingExecutor(linux.run);
    const desired = plan(2);
    await executor.apply(desired);
    linux.commands.length = 0;

    await executor.apply(desired, { previousPlan: desired });

    expect(
      linux.commands.filter(
        ({ executable, args }) =>
          executable === 'ip' &&
          args[1] === 'rule' &&
          (args[2] === 'add' || args[2] === 'replace')
      )
    ).toEqual([]);
  });

  test('keeps old and replacement NAT coverage until mark activation', async () => {
    const linux = new FakeLinuxRouting();
    const previous = plan(2);
    await new RoutingExecutor(linux.run).apply(previous);
    linux.commands.length = 0;

    await new RoutingExecutor(linux.run).apply(plan(3), {
      previousPlan: previous,
    });

    const transition = linux.commands.find(
      ({ executable, args, input }) =>
        executable === 'iptables-restore' &&
        !args.includes('--test') &&
        input?.startsWith('*nat')
    )?.input;
    expect(transition).toContain('-o awg1');
    expect(transition).toContain('-o awg2');
    expect(linux.tables.nat).not.toContain('-o awg1');
    expect(linux.tables.nat).toContain('-o awg2');
  });

  test('restores the last safe plan after an injected apply failure', async () => {
    const linux = new FakeLinuxRouting();
    const executor = new RoutingExecutor(linux.run);
    const previous = plan(2);
    await executor.apply(previous);

    await expect(
      executor.apply(plan(3), {
        previousPlan: previous,
        afterPhase: (phase) => {
          if (phase === 'mark_activation') {
            throw new Error('injected mark activation failure');
          }
        },
      })
    ).rejects.toThrow('injected mark activation failure');

    expect([...linux.routes.values()]).toContainEqual(
      expect.objectContaining({ dev: 'awg1' })
    );
    expect(linux.tables.nat).toContain('-o awg1');
    expect(linux.tables.nat).not.toContain('-o awg2');
  });

  test('refuses non-owned reserved state before mutation', async () => {
    const linux = new FakeLinuxRouting();
    linux.rules.set('4:22001', {
      family: 4,
      priority: 22001,
      table: 52001,
      protocol: 99,
      fwmark: `${formatMark(0x54010000)}/${formatMark(FWMARK_MASK)}`,
    });

    await expect(
      new RoutingExecutor(linux.run).apply(plan(null))
    ).rejects.toBeInstanceOf(RoutingOwnershipConflictError);
    expect(
      linux.commands.some(
        ({ executable, args }) =>
          executable === 'ip' &&
          (args.includes('add') ||
            args.includes('replace') ||
            args.includes('del'))
      )
    ).toBe(false);
    expect(linux.rules.get('4:22001')).toMatchObject({ protocol: 99 });
  });

  test('tests generated netfilter transactions before route mutation', async () => {
    const linux = new FakeLinuxRouting();
    const run = async (...args: Parameters<typeof linux.run>) => {
      if (args[0] === 'iptables-restore' && args[1]?.includes('--test')) {
        throw new Error('netfilter test rejected');
      }
      return linux.run(...args);
    };

    await expect(new RoutingExecutor(run).apply(plan(2))).rejects.toThrow(
      'netfilter test rejected'
    );
    expect(
      linux.commands.some(
        ({ executable, args }) =>
          executable === 'ip' &&
          (args[1] === 'route' || args[1] === 'rule') &&
          !args.includes('show')
      )
    ).toBe(false);
  });

  test('cleans only stale protocol-owned objects and preserves unrelated state', async () => {
    const linux = new FakeLinuxRouting();
    linux.routes.set('4:52002:186:198.51.100.0/24', {
      family: 4,
      table: 52002,
      protocol: WG_EASY_ROUTE_PROTOCOL,
      dst: '198.51.100.0/24',
      type: 'unreachable',
    });
    linux.routes.set('4:100:99:192.0.2.0/24', {
      family: 4,
      table: 100,
      protocol: 99,
      dst: '192.0.2.0/24',
      dev: 'eth0',
    });
    linux.routes.set('4:100:186:203.0.113.0/24', {
      family: 4,
      table: 100,
      protocol: WG_EASY_ROUTE_PROTOCOL,
      dst: '203.0.113.0/24',
      dev: 'eth0',
    });
    linux.rules.set('4:21000', {
      family: 4,
      priority: 21000,
      table: 51000,
      protocol: WG_EASY_ROUTE_PROTOCOL,
    });

    await new RoutingExecutor(linux.run).apply(plan(null));

    expect(linux.routes.has('4:52002:186:198.51.100.0/24')).toBe(false);
    expect(linux.routes.has('4:100:99:192.0.2.0/24')).toBe(true);
    expect(linux.routes.has('4:100:186:203.0.113.0/24')).toBe(true);
    expect(linux.rules.has('4:21000')).toBe(true);
  });

  test('verification rejects a stale owned route that survives cleanup', async () => {
    const linux = new FakeLinuxRouting();
    linux.routes.set('4:52002:186:198.51.100.0/24', {
      family: 4,
      table: 52002,
      protocol: WG_EASY_ROUTE_PROTOCOL,
      dst: '198.51.100.0/24',
      type: 'unreachable',
    });
    const run = async (...args: Parameters<typeof linux.run>) => {
      if (
        args[0] === 'ip' &&
        args[1]?.[1] === 'route' &&
        args[1]?.[2] === 'del'
      ) {
        return '';
      }
      return linux.run(...args);
    };

    await expect(new RoutingExecutor(run).apply(plan(null))).rejects.toThrow(
      'Routing verification did not observe the complete plan'
    );
  });

  test('verification rejects a desired prefix installed on the wrong device', async () => {
    const linux = new FakeLinuxRouting();
    const run = async (...args: Parameters<typeof linux.run>) => {
      if (
        args[0] === 'ip' &&
        args[1]?.[1] === 'route' &&
        args[1]?.[2] === 'replace' &&
        args[1].includes('awg1')
      ) {
        const changed = [...args[1]];
        changed[changed.indexOf('awg1')] = 'awg2';
        return linux.run(args[0], changed, args[2]);
      }
      return linux.run(...args);
    };

    await expect(new RoutingExecutor(run).apply(plan(2))).rejects.toThrow(
      'Routing verification did not observe the complete plan'
    );
  });
});
