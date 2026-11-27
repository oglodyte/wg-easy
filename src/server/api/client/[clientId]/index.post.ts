import { createError, getValidatedRouterParams } from 'h3';

import Database from '#server/utils/Database';
import WireGuard from '#server/utils/WireGuard';
import { definePermissionEventHandler } from '#server/utils/handler';
import { validateZod } from '#server/utils/types';
import {
  clientMutationHttpError,
  readClientConfigurationBody,
} from '#server/utils/clientMutationRequest';
import {
  ClientGetSchema,
  ClientConfigurationUpdateSchema,
} from '#db/repositories/client/types';

export default definePermissionEventHandler(
  'clients',
  'update',
  async ({ event, checkPermissions }) => {
    const { clientId } = await getValidatedRouterParams(
      event,
      validateZod(ClientGetSchema, event)
    );

    const data = await readClientConfigurationBody(
      event,
      ClientConfigurationUpdateSchema
    );

    const client = await Database.clients.get(clientId);
    checkPermissions(client);
    if (!client)
      throw createError({ statusCode: 404, statusMessage: 'Client not found' });

    try {
      await Database.clients.update(clientId, data);
    } catch (error) {
      return clientMutationHttpError(event, error);
    }
    return WireGuard.requestReconcile('update-client', [
      { interfaceId: client!.interfaceId, action: 'sync' },
    ]);
  }
);
