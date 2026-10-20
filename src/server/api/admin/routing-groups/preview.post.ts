import { readValidatedBody, setHeader } from 'h3';

import { RoutingGroupPreviewSchema } from '#db/repositories/routingGroup/types';
import Database from '#server/utils/Database';
import { definePermissionEventHandler } from '#server/utils/handler';
import { routingMutationHttpError } from '#server/utils/routingMutationRequest';
import { validateZod } from '#server/utils/types';

export default definePermissionEventHandler(
  'admin',
  'any',
  async ({ event }) => {
    setHeader(event, 'Cache-Control', 'no-store');
    const input = await readValidatedBody(
      event,
      validateZod(RoutingGroupPreviewSchema, event)
    );
    try {
      return await Database.routingGroups.previewAggregate(input);
    } catch (error) {
      return routingMutationHttpError(event, error);
    }
  }
);
