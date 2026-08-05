import { createError, readValidatedBody } from 'h3';

import Database from '#server/utils/Database';
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
      const runtime = await Database.runtime.getGlobal();
      return {
        success: true,
        revision,
        runtime: {
          status: 'pending' as const,
          appliedRevision: runtime.appliedRevision,
        },
        executionAvailable: false,
        warning: 'The group is saved, but routing execution waits for Phase 6.',
        group,
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
