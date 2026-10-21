import { describe, expect, test } from 'vitest';

import type { execFile } from '#server/utils/cmd';
import { buildRoutingGuard } from '#server/utils/routingGuard';
import {
  observeRoutingManagementPaths,
  assertRoutingManagementDestinations,
} from '#server/utils/routingManagementPaths';
import type { AppliedRoutingPolicyPlan } from '#shared/types/routingPolicy';

const address = JSON.stringify([
  {
    ifname: 'eth0',
    addr_info: [{ family: 'inet', local: '192.0.2.2', prefixlen: 24 }],
  },
  {
    ifname: 'wg0',
    addr_info: [{ family: 'inet', local: '10.8.0.1', prefixlen: 24 }],
  },
]);
const runner =
  (sockets = '0 0 192.0.2.2:51821 198.51.100.9:40000'): typeof execFile =>
  async (command, args) =>
    command === 'ip'
      ? args.includes('route')
        ? JSON.stringify([{ dev: 'eth0' }])
        : address
      : sockets;
describe('management/control observation', () => {
  test('protects the actual control reply device without blocking unrelated managed output', async () => {
    const paths = await observeRoutingManagementPaths(
      new Set(['wg0']),
      runner()
    );
    const scope = {
      direction: 'output' as const,
      source: '0.0.0.0/0',
      destination: '0.0.0.0/0',
    };
    expect(() =>
      buildRoutingGuard([{ ...scope, outputInterface: 'wg0' }], {
        protectedPaths: paths,
      })
    ).not.toThrow();
    expect(() =>
      buildRoutingGuard(
        [{ ...scope, direction: 'input', inputInterface: 'wg0' }],
        { protectedPaths: paths }
      )
    ).not.toThrow();
    expect(() =>
      buildRoutingGuard([{ ...scope, outputInterface: 'eth0' }], {
        protectedPaths: paths,
      })
    ).toThrowError('management_collision');
  });

  test('protects asymmetric independent ingress and refuses managed or unknown control endpoints', async () => {
    const paths = await observeRoutingManagementPaths(
      new Set(['wg0']),
      async (command, args, options) =>
        command === 'ip' && args.includes('address')
          ? JSON.stringify([
              ...JSON.parse(address),
              {
                ifname: 'eth1',
                addr_info: [
                  { family: 'inet', local: '198.18.0.2', prefixlen: 24 },
                ],
              },
            ])
          : runner()(command, args, options)
    );
    expect(
      paths
        .filter(
          (p) => p.direction === 'input' && p.source === '198.51.100.9/32'
        )
        .map((p) => p.inputInterface)
        .sort()
    ).toEqual(['eth0', 'eth1']);
    for (const [local, replyDevice] of [
      ['10.8.0.1', 'eth0'],
      ['203.0.113.8', 'eth0'],
      ['192.0.2.2', 'wg0'],
    ]) {
      const guarded = await observeRoutingManagementPaths(
        new Set(['wg0']),
        async (command, args, options) =>
          command === 'ip' && args.includes('route')
            ? JSON.stringify([{ dev: replyDevice }])
            : runner(`0 0 ${local}:51821 198.51.100.9:40000`)(
                command,
                args,
                options
              )
      );
      expect(() =>
        buildRoutingGuard(
          [
            {
              direction: 'input',
              inputInterface: 'wg0',
              source: '0.0.0.0/0',
              destination: '0.0.0.0/0',
            },
          ],
          { protectedPaths: guarded }
        )
      ).toThrowError('management_collision');
    }
  });

  test('normalizes mapped IPv4 sockets and refuses missing or ambiguous reply devices', async () => {
    const calls: string[][] = [];
    const paths = await observeRoutingManagementPaths(
      new Set(['wg0']),
      async (command, args) => {
        if (command === 'ip' && args.includes('route')) {
          calls.push([...args]);
          return JSON.stringify([{ dev: 'lo' }]);
        }
        return command === 'ip'
          ? address
          : '0 0 [::ffff:127.0.0.1]:51821 [::ffff:127.0.0.1]:40000';
      }
    );
    expect(calls).toEqual([
      ['-j', '-4', 'route', 'get', '127.0.0.1', 'from', '127.0.0.1'],
    ]);
    expect(paths.at(-1)).toEqual({
      direction: 'output',
      outputInterface: 'lo',
      source: '127.0.0.1/32',
      destination: '127.0.0.1/32',
    });
    for (const routes of [[], [{}], [{ dev: 'eth0' }, { dev: 'eth1' }]])
      await expect(
        observeRoutingManagementPaths(
          new Set(['wg0']),
          async (command, args) =>
            command === 'ip'
              ? args.includes('route')
                ? JSON.stringify(routes)
                : address
              : '0 0 192.0.2.2:51821 198.51.100.9:40000'
        )
      ).rejects.toMatchObject({ code: 'management_observation_unavailable' });
  });

  test('protects non-managed connected networks and remote established TCP endpoints', async () => {
    const paths = await observeRoutingManagementPaths(
      new Set(['wg0']),
      runner()
    );
    expect(paths).toHaveLength(4);
    expect(paths.some((p) => p.destination === '192.0.2.0/24')).toBe(true);
    expect(paths.some((p) => p.destination === '198.51.100.9/32')).toBe(true);
    expect(() =>
      buildRoutingGuard(
        [
          {
            direction: 'output',
            source: '0.0.0.0/0',
            destination: '198.51.100.0/24',
          },
        ],
        { protectedPaths: paths }
      )
    ).toThrowError('management_collision');
    expect(() =>
      assertRoutingManagementDestinations(
        {
          siteRoutes: [{ interfaceId: 'wg0', prefixes: ['192.0.2.0/25'] }],
        } as AppliedRoutingPolicyPlan,
        paths
      )
    ).toThrowError('management_collision');
    expect(() =>
      buildRoutingGuard(
        [
          {
            direction: 'forward',
            inputInterface: 'wg0',
            source: '10.8.0.2/32',
            destination: '0.0.0.0/0',
          },
        ],
        { protectedPaths: paths }
      )
    ).not.toThrow();
  });
  test('handles bracketed IPv6 endpoints and refuses malformed or absent observations', async () => {
    const paths = await observeRoutingManagementPaths(
      new Set(['wg0']),
      runner('0 0 [2001:db8::1]:51821 [2001:db8::2]:1234')
    );
    expect(paths.some((p) => p.destination === '2001:db8::2/128')).toBe(true);
    await expect(
      observeRoutingManagementPaths(new Set(), runner('unknown raw output'))
    ).rejects.toMatchObject({ code: 'management_observation_unavailable' });
    await expect(
      observeRoutingManagementPaths(new Set(), async () => '[]')
    ).rejects.toMatchObject({ code: 'management_observation_unavailable' });
  });
});
