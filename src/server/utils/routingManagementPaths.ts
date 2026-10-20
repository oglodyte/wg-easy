import { isIP } from 'node:net';

import { normalizeCidr, parseCidr } from 'cidr-tools';

import { execFile } from '#server/utils/cmd';
import { RoutingPolicyJournalError } from '#server/utils/routingPolicyJournal';
import type { RoutingGuardScope } from '#server/utils/routingGuard';
import type { AppliedRoutingPolicyPlan } from '#shared/types/routingPolicy';
import { NetworkDeviceSchema } from '#shared/utils/schemas';

function host(address: string) {
  const family = isIP(address);
  if (!family) throw new Error();
  return `${address}/${family === 4 ? 32 : 128}`;
}
function endpoint(value: string) {
  const match =
    value.match(/^\[([^\]]+)\]:([0-9]+)$/) ?? value.match(/^(.+):([0-9]+)$/);
  if (!match || Number(match[2]) < 1 || Number(match[2]) > 65535)
    throw new Error();
  return match[1]!.split('%')[0]!;
}

/** A read-only observation in the command runner's actual network namespace. */
export async function observeRoutingManagementPaths(
  managed: ReadonlySet<string>,
  run: typeof execFile = execFile
): Promise<RoutingGuardScope[]> {
  try {
    const addresses: unknown = JSON.parse(
        await run('ip', ['-j', 'address', 'show'], { log: false })
      ),
      sockets = await run('ss', ['-H', '-tn', 'state', 'established'], {
        log: false,
      }),
      scopes: RoutingGuardScope[] = [];
    if (!Array.isArray(addresses)) throw new Error();
    const pair = (local: string, remote: string, device?: string) => {
      const family = parseCidr(local).version;
      if (parseCidr(remote).version !== family) throw new Error();
      scopes.push(
        {
          direction: 'input',
          ...(device ? { inputInterface: device } : {}),
          source: remote,
          destination: local,
        },
        {
          direction: 'output',
          ...(device ? { outputInterface: device } : {}),
          source: local,
          destination: remote,
        }
      );
    };
    for (const link of addresses) {
      const device = NetworkDeviceSchema.parse(link.ifname);
      if (!Array.isArray(link.addr_info)) throw new Error();
      if (managed.has(device)) continue;
      for (const addr of link.addr_info) {
        if (!['inet', 'inet6'].includes(addr.family)) continue;
        const local = host(addr.local),
          maximum = isIP(addr.local) === 4 ? 32 : 128;
        if (
          !Number.isInteger(addr.prefixlen) ||
          addr.prefixlen < 1 ||
          addr.prefixlen > maximum
        )
          throw new Error();
        pair(local, normalizeCidr(`${addr.local}/${addr.prefixlen}`), device);
      }
    }
    for (const line of sockets.split('\n').filter((l) => l.trim())) {
      const fields = line.trim().split(/\s+/);
      if (
        fields.length !== 4 ||
        !fields.slice(0, 2).every((n) => /^[0-9]+$/.test(n))
      )
        throw new Error();
      pair(host(endpoint(fields[2]!)), host(endpoint(fields[3]!)));
    }
    if (!scopes.length) throw new Error();
    return scopes;
  } catch {
    throw new RoutingPolicyJournalError('management_observation_unavailable');
  }
}

export function assertRoutingManagementDestinations(
  plan: AppliedRoutingPolicyPlan,
  paths: readonly RoutingGuardScope[]
) {
  const destinations = paths
    .filter((p) => p.direction === 'output')
    .map((p) => parseCidr(p.destination));
  for (const route of plan.siteRoutes)
    for (const prefix of route.prefixes) {
      const range = parseCidr(prefix);
      if (
        destinations.some(
          (p) =>
            p.version === range.version &&
            p.start <= range.end &&
            range.start <= p.end
        )
      )
        throw new RoutingPolicyJournalError('management_collision');
    }
}
