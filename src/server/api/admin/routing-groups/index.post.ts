import { readValidatedBody } from 'h3';

import Database from '#server/utils/Database';
import WireGuard from '#server/utils/WireGuard';
import { definePermissionEventHandler } from '#server/utils/handler';
import { validateZod } from '#server/utils/types';
import { RoutingGroupSaveSchema } from '#db/repositories/routingGroup/types';
import { routingMutationHttpError } from '#server/utils/routingMutationRequest';

export default definePermissionEventHandler(
  'admin',
  'any',
  async ({ event }) => {
    const { expectedDesiredRevision, expectedDesiredFingerprint, ...input } =
      await readValidatedBody(
        event,
        validateZod(RoutingGroupSaveSchema, event)
      );
    try {
      const { group, revision } = await Database.routingGroups.createAggregate(
        input,
        { expectedDesiredRevision, expectedDesiredFingerprint }
      );
      const reconciled = await WireGuard.requestReconcile(
        'routing-group-create'
      );
      return {
        success: true,
        revision,
        runtime: reconciled.runtime,
        executionAvailable: true,
        group: await Database.routingGroups.get(group.id),
      };
    } catch (error) {
      return routingMutationHttpError(event, error);
    }
  }
);
