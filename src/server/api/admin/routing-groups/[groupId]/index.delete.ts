import { getValidatedRouterParams } from 'h3';

import Database from '#server/utils/Database';
import WireGuard from '#server/utils/WireGuard';
import { definePermissionEventHandler } from '#server/utils/handler';
import { validateZod } from '#server/utils/types';
import { routingMutationHttpError } from '#server/utils/routingMutationRequest';
import { RoutingGroupGetSchema } from '#db/repositories/routingGroup/types';

export default definePermissionEventHandler(
  'admin',
  'any',
  async ({ event }) => {
    const { groupId } = await getValidatedRouterParams(
      event,
      validateZod(RoutingGroupGetSchema, event)
    );
    try {
      const { revision, routingSlot } =
        await Database.routingGroups.delete(groupId);
      const reconciled = await WireGuard.requestReconcile(
        'routing-group-delete'
      );
      return {
        success: true,
        revision,
        runtime: reconciled.runtime,
        executionAvailable: true,
        routingSlotTombstone: routingSlot,
      };
    } catch (error) {
      return routingMutationHttpError(event, error);
    }
  }
);
