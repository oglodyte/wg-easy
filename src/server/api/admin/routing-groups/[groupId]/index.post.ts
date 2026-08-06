import { createError, getValidatedRouterParams, readValidatedBody } from 'h3';

import Database from '#server/utils/Database';
import WireGuard from '#server/utils/WireGuard';
import { definePermissionEventHandler } from '#server/utils/handler';
import { RoutingValidationError } from '#server/utils/routing';
import { validateZod } from '#server/utils/types';
import { RoutingGroupNotFoundError } from '#db/repositories/routingGroup/service';
import { RoutingGroupGetSchema } from '#db/repositories/routingGroup/types';
import { RoutingGroupSchema } from '#shared/utils/schemas';

export default definePermissionEventHandler(
  'admin',
  'any',
  async ({ event }) => {
    const { groupId } = await getValidatedRouterParams(
      event,
      validateZod(RoutingGroupGetSchema, event)
    );
    const input = await readValidatedBody(
      event,
      validateZod(RoutingGroupSchema, event)
    );
    try {
      const { group, revision } = await Database.routingGroups.updateAggregate(
        groupId,
        input
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
      if (error instanceof RoutingGroupNotFoundError) {
        throw createError({ statusCode: 404, statusMessage: error.message });
      }
      if (error instanceof RoutingValidationError) {
        throw createError({
          statusCode: 409,
          statusMessage: error.message,
          data: { issues: error.issues },
        });
      }
      throw error;
    }
  }
);
