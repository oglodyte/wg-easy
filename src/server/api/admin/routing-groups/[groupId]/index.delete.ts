import { createError, getValidatedRouterParams } from 'h3';

import Database from '#server/utils/Database';
import { definePermissionEventHandler } from '#server/utils/handler';
import { validateZod } from '#server/utils/types';
import { RoutingGroupNotFoundError } from '#db/repositories/routingGroup/service';
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
      const runtime = await Database.runtime.getGlobal();
      return {
        success: true,
        revision,
        runtime: {
          status: 'pending' as const,
          appliedRevision: runtime.appliedRevision,
        },
        executionAvailable: false,
        routingSlotTombstone: routingSlot,
        warning:
          'The routing slot remains reserved until Phase 6 verifies Linux-state cleanup.',
      };
    } catch (error) {
      if (error instanceof RoutingGroupNotFoundError) {
        throw createError({ statusCode: 404, statusMessage: error.message });
      }
      throw error;
    }
  }
);
