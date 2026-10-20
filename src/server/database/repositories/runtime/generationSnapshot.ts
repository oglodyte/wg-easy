import { readRoutingPolicyStateInTransaction } from './policyService';
import { readProposedRoutingState } from './policySnapshot';

import type { DBType } from '#db/sqlite';
import { RoutingPolicyJournalError } from '#server/utils/routingPolicyJournal';

export class RoutingGenerationSnapshotError extends Error {
  readonly code = 'snapshot_unavailable';
  constructor() {
    super('Routing generation snapshot: unavailable');
    this.name = 'RoutingGenerationSnapshotError';
  }
}

/**
 * Internal private input, never an API response or diagnostic object. Server
 * identity, peer PSKs and server hooks are required; client private keys,
 * client-export hooks and unrelated authentication/metrics secrets are not.
 * Call between coordinator operations, never inside final publication's lock.
 */
export class RoutingGenerationSnapshotService {
  constructor(private readonly db: DBType) {}

  async readPrivateDesiredGeneration() {
    try {
      return await this.db.transaction(async (tx) => {
        const [
          policy,
          proposed,
          settings,
          interfaces,
          clients,
          hooks,
          defaults,
          interfaceRuntime,
          groupRuntime,
        ] = await Promise.all([
          readRoutingPolicyStateInTransaction(tx),
          readProposedRoutingState(tx),
          tx.query.general
            .findFirst({
              columns: {
                routingPolicyVersion: true,
                defaultInterfaceId: true,
                routingExitHealthCheckIntervalSeconds: true,
                routingExitHealthTimeoutSeconds: true,
                routingExitMinHoldSeconds: true,
                routingExitFailbackDelaySeconds: true,
              },
            })
            .execute(),
          tx.query.wgInterface
            .findMany({ orderBy: (table, { asc }) => asc(table.name) })
            .execute(),
          tx.query.client
            .findMany({
              columns: {
                id: true,
                name: true,
                interfaceId: true,
                publicKey: true,
                preSharedKey: true,
                ipv4Address: true,
                ipv6Address: true,
                enabled: true,
                serverAllowedIps: true,
                serverEndpoint: true,
                persistentKeepalive: true,
                allowedIps: true,
                firewallIps: true,
              },
              orderBy: (table, { asc }) => asc(table.id),
            })
            .execute(),
          tx.query.hooks
            .findMany({ orderBy: (table, { asc }) => asc(table.id) })
            .execute(),
          tx.query.userConfig
            .findMany({
              columns: { id: true, defaultAllowedIps: true },
              orderBy: (table, { asc }) => asc(table.id),
            })
            .execute(),
          tx.query.interfaceRuntimeState
            .findMany({ orderBy: (table, { asc }) => asc(table.interfaceId) })
            .execute(),
          tx.query.routingGroupRuntimeState
            .findMany({ orderBy: (table, { asc }) => asc(table.groupId) })
            .execute(),
        ]);
        if (
          !settings ||
          policy.version !== proposed.version ||
          policy.version !== settings.routingPolicyVersion
        )
          throw new RoutingGenerationSnapshotError();
        return {
          policy,
          snapshot: proposed.snapshot,
          settings,
          interfaces,
          clients,
          hooks,
          defaults,
          interfaceRuntime,
          groupRuntime,
        };
      });
    } catch (error) {
      if (error instanceof RoutingPolicyJournalError) throw error;
      // Driver errors can include SQL binds, raw JSON or private config text.
      throw new RoutingGenerationSnapshotError();
    }
  }
}

export type PrivateDesiredRoutingGeneration = Awaited<
  ReturnType<RoutingGenerationSnapshotService['readPrivateDesiredGeneration']>
>;
