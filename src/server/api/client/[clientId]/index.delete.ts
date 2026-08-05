import { createError, getValidatedQuery, getValidatedRouterParams } from 'h3';

import Database from '#server/utils/Database';
import WireGuard from '#server/utils/WireGuard';
import { definePermissionEventHandler } from '#server/utils/handler';
import { validateZod } from '#server/utils/types';
import { ClientRoutingReferenceError } from '#db/repositories/client/service';
import {
  ClientDeleteQuerySchema,
  ClientGetSchema,
} from '#db/repositories/client/types';

export default definePermissionEventHandler(
  'clients',
  'delete',
  async ({ event, checkPermissions }) => {
    const { clientId } = await getValidatedRouterParams(
      event,
      validateZod(ClientGetSchema, event)
    );

    const client = await Database.clients.get(clientId);
    checkPermissions(client);

    const { removeRoutingMembership } = await getValidatedQuery(
      event,
      validateZod(ClientDeleteQuerySchema, event)
    );

    try {
      await Database.clients.delete(clientId, { removeRoutingMembership });
    } catch (error) {
      if (error instanceof ClientRoutingReferenceError) {
        throw createError({
          statusCode: 409,
          statusMessage: error.message,
          data: { kind: error.kind, groupIds: error.groupIds },
        });
      }
      throw error;
    }
    return WireGuard.requestReconcile('delete-client', [
      { interfaceId: client!.interfaceId, action: 'sync' },
    ]);
  }
);
