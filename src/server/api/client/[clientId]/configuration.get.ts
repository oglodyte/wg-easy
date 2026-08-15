import {
  createError,
  getValidatedQuery,
  getValidatedRouterParams,
  setHeader,
} from 'h3';
import { z } from 'zod';

import Database from '#server/utils/Database';
import WireGuard from '#server/utils/WireGuard';
import { definePermissionEventHandler } from '#server/utils/handler';
import { validateZod } from '#server/utils/types';
import { ConfigFormatUnavailableError } from '#server/utils/wgHelper';
import { ClientGetSchema } from '#db/repositories/client/types';
import { ConfigFormatSchema } from '#shared/utils/schemas';

export default definePermissionEventHandler(
  'clients',
  'view',
  async ({ event, checkPermissions }) => {
    const { clientId } = await getValidatedRouterParams(
      event,
      validateZod(ClientGetSchema, event)
    );
    const client = await Database.clients.get(clientId);
    checkPermissions(client);

    if (!client) {
      throw createError({
        statusCode: 404,
        statusMessage: 'Client not found',
      });
    }

    const { format } = await getValidatedQuery(
      event,
      validateZod(
        z.object({ format: ConfigFormatSchema.default('auto') }),
        event
      )
    );
    let config: string;
    try {
      config = await WireGuard.getClientConfiguration({ clientId, format });
    } catch (error) {
      if (error instanceof ConfigFormatUnavailableError) {
        throw createError({ statusCode: 409, statusMessage: error.message });
      }
      throw error;
    }

    setHeader(
      event,
      'Content-Disposition',
      `attachment; filename="${WireGuard.cleanClientFilename(client.name) || clientId}.conf"`
    );

    setHeader(event, 'Content-Type', 'application/octet-stream');
    return config;
  }
);
