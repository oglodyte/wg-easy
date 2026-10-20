import { getValidatedRouterParams, readValidatedBody } from 'h3';

import Database from '#server/utils/Database';
import WireGuard from '#server/utils/WireGuard';
import { definePermissionEventHandler } from '#server/utils/handler';
import { validateZod } from '#server/utils/types';
import {
  RoutingGroupGetSchema,
  RoutingGroupSaveSchema,
} from '#db/repositories/routingGroup/types';
import { routingMutationHttpError } from '#server/utils/routingMutationRequest';

export default definePermissionEventHandler(
  'admin',
  'any',
  async ({ event }) => {
    const { groupId } = await getValidatedRouterParams(
      event,
      validateZod(RoutingGroupGetSchema, event)
    );
    const { expectedDesiredRevision, expectedDesiredFingerprint, ...input } =
      await readValidatedBody(
        event,
        validateZod(RoutingGroupSaveSchema, event)
      );
    try {
      const { group, revision } = await Database.routingGroups.updateAggregate(
        groupId,
        input,
        { expectedDesiredRevision, expectedDesiredFingerprint }
      );
      const reconciled = await WireGuard.requestReconcile(
        'routing-group-update'
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
