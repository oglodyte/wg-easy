import { useTranslation } from '@intlify/h3';
import { ClientConflictError } from '#db/repositories/client/service';
import { createError, getValidatedRouterParams } from 'h3';

import Database from '#server/utils/Database';
import WireGuard from '#server/utils/WireGuard';
import { definePermissionEventHandler } from '#server/utils/handler';
import { validateZod } from '#server/utils/types';
import { ClientGetSchema } from '#db/repositories/client/types';

export default definePermissionEventHandler(
  'clients',
  'update',
  async ({ event, checkPermissions }) => {
    const { clientId } = await getValidatedRouterParams(
      event,
      validateZod(ClientGetSchema, event)
    );

    const client = await Database.clients.get(clientId);
    checkPermissions(client);

    if (
      client &&
      client.expiresAt !== null &&
      new Date() > new Date(client.expiresAt)
    ) {
      throw createError({
        statusCode: 422,
        statusMessage:
          'Client is expired. Please update the expiration date first.',
        message: 'Client is expired. Please update the expiration date first.',
      });
    }

    try {
      await Database.clients.toggle(clientId, true);
    } catch (error) {
      if (error instanceof ClientConflictError) {
        const t = await useTranslation(event);
        throw createError({
          statusCode: 409,
          message: t('client.enabledConflict'),
        });
      }
      throw error;
    }
    return WireGuard.requestReconcile('enable-client', [
      { interfaceId: client!.interfaceId, action: 'sync' },
    ]);
  }
);
