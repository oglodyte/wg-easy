import { compileRoutingPolicy, PolicyValidationError } from './routingPolicy';
import {
  findRoutingPrefixConflicts,
  findServerAllowedIpConflicts,
  RoutingValidationError,
} from './routing';

import type { PolicySnapshot } from '#shared/types/routingPolicy';

/** Temporary schema bridge: only v1 may execute in the Phase 1 image. */
export function assertRoutingPolicyVersion1(version: number) {
  if (version !== 1)
    throw new RoutingValidationError([
      {
        code: 'routing_policy_unavailable',
        message:
          'This image cannot activate the stored routing policy version.',
      },
    ]);
}

/** Shared final-state proof prepared for Phase 2 transaction boundaries. */
export function validateProposedRoutingState(
  version: number,
  state: PolicySnapshot
) {
  if (version === 2) return compileRoutingPolicy(state);
  assertRoutingPolicyVersion1(version);
  const assigned = new Map<number, number>();
  for (const group of state.groups) {
    if (group.excludedIpv4Prefixes?.length)
      throw new PolicyValidationError('policy_version_required', {
        groupIds: [group.id],
      });
    for (const clientId of group.memberClientIds) {
      const previous = assigned.get(clientId);
      if (previous !== undefined && previous !== group.id)
        throw new PolicyValidationError('policy_version_required', {
          clientIds: [clientId],
          groupIds: [previous, group.id],
        });
      assigned.set(clientId, group.id);
    }
  }
  const issues = [
    ...findServerAllowedIpConflicts(state.clients),
    ...findRoutingPrefixConflicts({
      clients: state.clients,
      groups: state.groups,
    }),
  ];
  if (issues.length) throw new RoutingValidationError(issues);
  return null;
}
