import { afterAll, beforeAll, describe, expect, test } from 'vitest';

import { execFile } from '#server/utils/cmd';
import { buildRoutingPlan, type RoutingPlan } from '#server/utils/routing';
import {
  RoutingExecutor,
  RoutingOwnershipConflictError,
  type RoutingApplyPhase,
} from '#server/utils/routingExecutor';
import type { AllExitsDownPolicy } from '#shared/types/runtime';

const privileged =
  process.platform === 'linux' &&
  process.getuid?.() === 0 &&
  process.env.WG_EASY_RUN_PRIVILEGED_TESTS === '1';
const suite = privileged ? describe : describe.skip;
const suffix = process.pid.toString(36).slice(-5);
const namespaces = {
  server: `w6s${suffix}`,
  member: `w6m${suffix}`,
  sameExit: `w6x${suffix}`,
  primary: `w6p${suffix}`,
  backup: `w6b${suffix}`,
  lan: `w6l${suffix}`,
  sink: `w6k${suffix}`,
};
const allNamespaces = Object.values(namespaces);
let pairIndex = 0;

async function host(executable: string, args: readonly string[] = []) {
  return execFile(executable, args, { log: false });
}

async function inside(namespace: string, args: readonly string[]) {
  return host('ip', ['netns', 'exec', namespace, ...args]);
}

async function createPair(
  leftNamespace: string,
  leftName: string,
  rightNamespace: string,
  rightName: string
) {
  pairIndex += 1;
  const left = `w6${suffix}${pairIndex}a`.slice(0, 15);
  const right = `w6${suffix}${pairIndex}b`.slice(0, 15);
  await host('ip', [
    'link',
    'add',
    left,
    'type',
    'veth',
    'peer',
    'name',
    right,
  ]);
  await host('ip', ['link', 'set', left, 'netns', leftNamespace]);
  await host('ip', ['link', 'set', right, 'netns', rightNamespace]);
  await inside(leftNamespace, ['ip', 'link', 'set', left, 'name', leftName]);
  await inside(rightNamespace, ['ip', 'link', 'set', right, 'name', rightName]);
}

async function configureTopology() {
  for (const namespace of allNamespaces) {
    await host('ip', ['netns', 'add', namespace]);
    await inside(namespace, ['ip', 'link', 'set', 'lo', 'up']);
  }

  await createPair(namespaces.member, 'wg0', namespaces.server, 'member0');
  await createPair(namespaces.sameExit, 'tun0', namespaces.server, 'same0');
  await createPair(namespaces.primary, 'tun0', namespaces.server, 'awg1');
  await createPair(namespaces.backup, 'tun0', namespaces.server, 'awg2');
  await createPair(namespaces.sameExit, 'wan0', namespaces.lan, 'lan0');
  await createPair(namespaces.primary, 'wan0', namespaces.lan, 'lan1');
  await createPair(namespaces.backup, 'wan0', namespaces.lan, 'lan2');
  await createPair(namespaces.sink, 'eth0', namespaces.lan, 'sink0');

  await inside(namespaces.server, [
    'ip',
    'link',
    'add',
    'wg0',
    'type',
    'bridge',
  ]);
  for (const port of ['member0', 'same0']) {
    await inside(namespaces.server, [
      'ip',
      'link',
      'set',
      port,
      'master',
      'wg0',
    ]);
    await inside(namespaces.server, ['ip', 'link', 'set', port, 'up']);
  }
  await inside(namespaces.server, [
    'ip',
    'addr',
    'add',
    '10.8.0.1/24',
    'dev',
    'wg0',
  ]);
  await inside(namespaces.server, ['ip', 'link', 'set', 'wg0', 'up']);

  await inside(namespaces.member, [
    'ip',
    'addr',
    'add',
    '10.8.0.2/24',
    'dev',
    'wg0',
  ]);
  await inside(namespaces.member, ['ip', 'link', 'set', 'wg0', 'up']);
  await inside(namespaces.member, [
    'ip',
    'route',
    'add',
    'default',
    'via',
    '10.8.0.1',
  ]);
  await inside(namespaces.sameExit, [
    'ip',
    'addr',
    'add',
    '10.8.0.3/24',
    'dev',
    'tun0',
  ]);
  await inside(namespaces.sameExit, ['ip', 'link', 'set', 'tun0', 'up']);

  for (const [namespace, serverDevice, serverAddress, exitAddress] of [
    [namespaces.primary, 'awg1', '10.9.0.1/24', '10.9.0.2/24'],
    [namespaces.backup, 'awg2', '10.10.0.1/24', '10.10.0.2/24'],
  ] as const) {
    await inside(namespaces.server, [
      'ip',
      'addr',
      'add',
      serverAddress,
      'dev',
      serverDevice,
    ]);
    await inside(namespaces.server, ['ip', 'link', 'set', serverDevice, 'up']);
    await inside(namespace, ['ip', 'addr', 'add', exitAddress, 'dev', 'tun0']);
    await inside(namespace, ['ip', 'link', 'set', 'tun0', 'up']);
  }

  await inside(namespaces.lan, ['ip', 'link', 'add', 'br0', 'type', 'bridge']);
  for (const port of ['lan0', 'lan1', 'lan2', 'sink0']) {
    await inside(namespaces.lan, ['ip', 'link', 'set', port, 'master', 'br0']);
    await inside(namespaces.lan, ['ip', 'link', 'set', port, 'up']);
  }
  await inside(namespaces.lan, ['ip', 'link', 'set', 'br0', 'up']);

  for (const [namespace, address] of [
    [namespaces.sameExit, '172.31.0.10/24'],
    [namespaces.primary, '172.31.0.11/24'],
    [namespaces.backup, '172.31.0.12/24'],
  ] as const) {
    await inside(namespace, ['ip', 'addr', 'add', address, 'dev', 'wan0']);
    await inside(namespace, ['ip', 'link', 'set', 'wan0', 'up']);
  }
  await inside(namespaces.sink, [
    'ip',
    'addr',
    'add',
    '172.31.0.100/24',
    'dev',
    'eth0',
  ]);
  await inside(namespaces.sink, ['ip', 'link', 'set', 'eth0', 'up']);

  for (const namespace of [
    namespaces.server,
    namespaces.sameExit,
    namespaces.primary,
    namespaces.backup,
  ]) {
    await inside(namespace, ['sysctl', '-q', '-w', 'net.ipv4.ip_forward=1']);
    await inside(namespace, [
      'sysctl',
      '-q',
      '-w',
      'net.ipv4.conf.all.rp_filter=0',
    ]);
  }
  for (const namespace of [
    namespaces.sameExit,
    namespaces.primary,
    namespaces.backup,
  ]) {
    await inside(namespace, [
      'sysctl',
      '-q',
      '-w',
      'net.ipv4.conf.tun0.proxy_arp=1',
    ]);
  }

  await inside(namespaces.primary, [
    'ip',
    'route',
    'add',
    '10.8.0.0/24',
    'via',
    '10.9.0.1',
  ]);
  await inside(namespaces.backup, [
    'ip',
    'route',
    'add',
    '10.8.0.0/24',
    'via',
    '10.10.0.1',
  ]);
  await inside(namespaces.sink, [
    'ip',
    'route',
    'add',
    '10.9.0.0/24',
    'via',
    '172.31.0.11',
  ]);
  await inside(namespaces.sink, [
    'ip',
    'route',
    'add',
    '10.10.0.0/24',
    'via',
    '172.31.0.12',
  ]);
  await inside(namespaces.sink, [
    'ip',
    'route',
    'add',
    '10.8.0.0/24',
    'via',
    '172.31.0.10',
  ]);
  await inside(namespaces.server, [
    'ip',
    'route',
    'add',
    '172.31.0.100/32',
    'via',
    '10.9.0.2',
    'dev',
    'awg1',
  ]);
}

async function cleanupTopology() {
  for (const namespace of [...allNamespaces].reverse()) {
    await host('ip', ['netns', 'delete', namespace]).catch(() => {});
  }
}

function buildPlan({
  selectedExitClientId,
  natEnabled = true,
  policy = 'block',
  includeBackup = true,
}: {
  selectedExitClientId: number | null;
  natEnabled?: boolean;
  policy?: AllExitsDownPolicy;
  includeBackup?: boolean;
}): RoutingPlan {
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
    ...(includeBackup
      ? [
          {
            interfaceId: 'awg2',
            ipv4Cidr: '10.10.0.0/24',
            enabled: true,
            observedUp: true,
          },
        ]
      : []),
  ];
  return buildRoutingPlan({
    interfaces,
    clients: [
      {
        id: 1,
        interfaceId: 'wg0',
        ipv4Address: '10.8.0.2',
        enabled: true,
        serverAllowedIps: [],
      },
      {
        id: 2,
        interfaceId: 'wg0',
        ipv4Address: '10.8.0.3',
        enabled: true,
        serverAllowedIps: [],
      },
      {
        id: 3,
        interfaceId: 'awg1',
        ipv4Address: '10.9.0.2',
        enabled: true,
        serverAllowedIps: [],
      },
      ...(includeBackup
        ? [
            {
              id: 4,
              interfaceId: 'awg2',
              ipv4Address: '10.10.0.2',
              enabled: true,
              serverAllowedIps: [],
            },
          ]
        : []),
    ],
    groups: [
      {
        id: 1,
        routingSlot: 1,
        enabled: true,
        natEnabled,
        allExitsDownPolicy: policy,
        routedIpv4Prefixes: ['172.31.0.100/32'],
        memberClientIds: [1],
        selectedExitClientId,
      },
    ],
  });
}

function namespaceRunner(namespace: string) {
  return (
    executable: string,
    args: readonly string[] = [],
    options: { input?: string; log?: boolean | string } = {}
  ) =>
    execFile('ip', ['netns', 'exec', namespace, executable, ...args], {
      ...options,
      log: false,
    });
}

async function pingSucceeds() {
  await inside(namespaces.member, [
    'ping',
    '-c',
    '1',
    '-W',
    '2',
    '172.31.0.100',
  ]);
}

async function pingFails() {
  await expect(
    inside(namespaces.member, ['ping', '-c', '1', '-W', '1', '172.31.0.100'])
  ).rejects.toThrow();
}

async function observedSource() {
  const capture = inside(namespaces.sink, [
    'timeout',
    '5',
    'tcpdump',
    '-nn',
    '-l',
    '-i',
    'eth0',
    '-c',
    '1',
    'icmp',
    'and',
    'dst',
    'host',
    '172.31.0.100',
  ]);
  await new Promise((resolve) => setTimeout(resolve, 200));
  await pingSucceeds();
  return capture;
}

suite('Phase 6 privileged routing namespaces', () => {
  beforeAll(async () => {
    await cleanupTopology();
    await configureTopology();
  });

  afterAll(cleanupTopology);

  test('proves same/cross-interface routing, NAT modes, failover, fail-closed replacement, ownership, and cleanup', async () => {
    const executor = new RoutingExecutor(namespaceRunner(namespaces.server));
    const primary = buildPlan({ selectedExitClientId: 3 });
    await executor.apply(primary);
    expect(await observedSource()).toContain('10.9.0.1 > 172.31.0.100');

    await inside(namespaces.sink, [
      'ip',
      'route',
      'replace',
      '10.8.0.0/24',
      'via',
      '172.31.0.11',
    ]);
    const natOff = buildPlan({ selectedExitClientId: 3, natEnabled: false });
    await executor.apply(natOff, { previousPlan: primary });
    expect(await observedSource()).toContain('10.8.0.2 > 172.31.0.100');

    await inside(namespaces.sink, [
      'ip',
      'route',
      'replace',
      '10.8.0.0/24',
      'via',
      '172.31.0.10',
    ]);
    const sameInterface = buildPlan({ selectedExitClientId: 2 });
    await executor.apply(sameInterface, { previousPlan: natOff });
    expect(await observedSource()).toContain('10.8.0.1 > 172.31.0.100');

    const backup = buildPlan({ selectedExitClientId: 4 });
    await executor.apply(backup, { previousPlan: sameInterface });
    expect(await observedSource()).toContain('10.10.0.1 > 172.31.0.100');
    await executor.apply(primary, { previousPlan: backup });
    expect(await observedSource()).toContain('10.9.0.1 > 172.31.0.100');

    const block = buildPlan({ selectedExitClientId: null });
    await executor.apply(block, { previousPlan: primary });
    await pingFails();
    const hostFallback = buildPlan({
      selectedExitClientId: null,
      policy: 'host',
    });
    await inside(namespaces.sink, [
      'ip',
      'route',
      'replace',
      '10.8.0.0/24',
      'via',
      '172.31.0.11',
    ]);
    await executor.apply(hostFallback, { previousPlan: block });
    await pingSucceeds();

    await executor.apply(block, { previousPlan: hostFallback });
    for (const phase of [
      'preflight',
      'routes',
      'rules',
      'transition_nat',
      'mark_activation',
      'final_nat',
      'cleanup',
      'verify',
    ] satisfies RoutingApplyPhase[]) {
      await expect(
        executor.apply(hostFallback, {
          previousPlan: block,
          afterPhase: (current) => {
            if (current === phase) throw new Error(`injected ${phase}`);
          },
        })
      ).rejects.toThrow(`injected ${phase}`);
      await pingFails();
    }

    await inside(namespaces.server, [
      'ip',
      'rule',
      'add',
      'fwmark',
      '0x00001234/0x0000ffff',
      'priority',
      '21000',
      'table',
      '51000',
      'protocol',
      '99',
    ]);
    await inside(namespaces.server, [
      'iptables',
      '-t',
      'mangle',
      '-A',
      'OUTPUT',
      '-j',
      'MARK',
      '--set-xmark',
      '0x00001234/0x0000ffff',
    ]);
    await inside(namespaces.server, [
      'ip',
      'route',
      'add',
      'unreachable',
      '198.51.100.0/24',
      'table',
      '52002',
      'proto',
      '186',
    ]);
    await inside(namespaces.server, [
      'ip',
      'route',
      'add',
      'unreachable',
      '203.0.113.0/24',
      'table',
      '51000',
      'proto',
      '186',
    ]);
    await inside(namespaces.server, [
      'ip',
      'rule',
      'add',
      'priority',
      '21001',
      'table',
      '51000',
      'protocol',
      '186',
    ]);
    await new RoutingExecutor(namespaceRunner(namespaces.server)).apply(block, {
      previousPlan: block,
    });
    expect(
      await inside(namespaces.server, [
        'ip',
        '-4',
        'rule',
        'show',
        'priority',
        '21000',
      ])
    ).toContain('21000:');
    expect(
      await inside(namespaces.server, ['iptables-save', '-t', 'mangle'])
    ).toContain('0x1234/0xffff');
    expect(
      await inside(namespaces.server, ['ip', 'route', 'show', 'table', '52002'])
    ).not.toContain('198.51.100.0/24');
    expect(
      await inside(namespaces.server, ['ip', 'route', 'show', 'table', '51000'])
    ).toContain('203.0.113.0/24');
    expect(
      await inside(namespaces.server, [
        'ip',
        '-4',
        'rule',
        'show',
        'priority',
        '21001',
      ])
    ).toContain('21001:');

    await inside(namespaces.server, [
      'ip',
      'rule',
      'add',
      'fwmark',
      '0x54320000/0xffff0000',
      'priority',
      '22050',
      'table',
      '52050',
      'protocol',
      '99',
    ]);
    await expect(
      executor.apply(block, { previousPlan: block })
    ).rejects.toBeInstanceOf(RoutingOwnershipConflictError);
    expect(
      await inside(namespaces.server, [
        'ip',
        '-4',
        'rule',
        'show',
        'priority',
        '22050',
      ])
    ).toContain('22050:');
    await inside(namespaces.server, ['ip', 'rule', 'del', 'priority', '22050']);

    const withoutBackup = buildPlan({
      selectedExitClientId: null,
      includeBackup: false,
    });
    await new RoutingExecutor(namespaceRunner(namespaces.server)).apply(
      withoutBackup,
      { previousPlan: block }
    );
    const mangle = await inside(namespaces.server, [
      'iptables-save',
      '-t',
      'mangle',
    ]);
    expect(mangle).not.toContain('-i awg2');
    expect(mangle).toContain('0x1234/0xffff');
  });
});
