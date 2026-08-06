import { createError, readValidatedBody } from 'h3';

import Database from '#server/utils/Database';
import WireGuard from '#server/utils/WireGuard';
import { definePermissionEventHandler } from '#server/utils/handler';
import { RoutingValidationError } from '#server/utils/routing';
import { validateZod } from '#server/utils/types';
import { RoutingGroupSchema } from '#shared/utils/schemas';

export default definePermissionEventHandler(
  'admin',
  'any',
  async ({ event }) => {
    const input = await readValidatedBody(
      event,
      validateZod(RoutingGroupSchema, event)
    );
    try {
      const { group, revision } =
        await Database.routingGroups.createAggregate(input);
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
