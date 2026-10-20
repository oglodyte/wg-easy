import { parseCidr } from 'cidr-tools';
import { isIPv4 } from 'is-ip';
import { stringifyIp } from 'ip-bigint';

import { PolicyValidationError } from '#server/utils/routingPolicy';
import type { CompiledPolicy } from '#shared/types/routingPolicy';

/** Read the compiler's proven cells; never re-rank or reinterpret CIDR fragments. */
export function explainCompiledRoutingPolicy(
  compiled: CompiledPolicy,
  memberClientId: number,
  destinationIpv4: string
) {
  if (!isIPv4(destinationIpv4))
    throw new PolicyValidationError('invalid_destination');
  const address = Number(parseCidr(`${destinationIpv4}/32`).start);
  const bypass = compiled.bypassPrefixes.some((prefix) => {
    const range = parseCidr(prefix);
    return address >= Number(range.start) && address <= Number(range.end);
  });
  if (bypass)
    return {
      memberClientId,
      destinationIpv4,
      outcome: 'managed_network_bypass' as const,
      winner: null,
    };
  const program = compiled.programs.find((p) =>
      p.sources.some((s) => s.clientId === memberClientId)
    ),
    cell = program?.cells.find((c) => c.start <= address && address < c.end);
  return {
    memberClientId,
    destinationIpv4,
    outcome: cell ? ('policy' as const) : ('host' as const),
    winner: cell
      ? {
          groupId: cell.groupId,
          originalPrefix: cell.originalPrefix,
          specificity: cell.specificity,
        }
      : null,
  };
}

/** Bound response work/output independently from the larger compiler work cap. */
export function compiledRoutingWinnerExamples(compiled: CompiledPolicy) {
  const examples: ReturnType<typeof explainCompiledRoutingPolicy>[] = [];
  for (const program of compiled.programs)
    for (const cell of program.cells) {
      if (examples.length === 32) return examples;
      examples.push({
        memberClientId: program.sources[0]!.clientId,
        destinationIpv4: stringifyIp({
          number: BigInt(cell.start),
          version: 4,
        }),
        outcome: 'policy',
        winner: {
          groupId: cell.groupId,
          originalPrefix: cell.originalPrefix,
          specificity: cell.specificity,
        },
      });
    }
  return examples;
}
