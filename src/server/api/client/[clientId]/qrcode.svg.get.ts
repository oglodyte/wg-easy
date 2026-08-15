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

    const { format } = await getValidatedQuery(
      event,
      validateZod(
        z.object({ format: ConfigFormatSchema.default('auto') }),
        event
      )
    );
    let svg: string;
    try {
      svg = await WireGuard.getClientQRCodeSVG({ clientId, format });
    } catch (error) {
      if (error instanceof ConfigFormatUnavailableError) {
        throw createError({ statusCode: 409, statusMessage: error.message });
      }
      throw error;
    }
    setHeader(event, 'Content-Type', 'image/svg+xml');
    return svg;
  }
);
