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
  async (command) =>
    command === 'ip' ? address : sockets;
describe('management/control observation', () => {
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
