import { createError, getValidatedRouterParams, readValidatedBody } from 'h3';

import Database from '#server/utils/Database';
import WireGuard from '#server/utils/WireGuard';
import { definePermissionEventHandler } from '#server/utils/handler';
import { validateZod } from '#server/utils/types';
import { RoutingValidationError } from '#server/utils/routing';
import {
  ClientGetSchema,
  ClientUpdateSchema,
} from '#db/repositories/client/types';

export default definePermissionEventHandler(
  'clients',
  'update',
  async ({ event, checkPermissions }) => {
    const { clientId } = await getValidatedRouterParams(
      event,
      validateZod(ClientGetSchema, event)
    );

    const data = await readValidatedBody(
      event,
      validateZod(ClientUpdateSchema, event)
    );

    const client = await Database.clients.get(clientId);
    checkPermissions(client);

    try {
      await Database.clients.update(clientId, data);
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
    return WireGuard.requestReconcile('update-client', [
      { interfaceId: client!.interfaceId, action: 'sync' },
    ]);
  }
);
