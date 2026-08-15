import {
  createError,
  defineEventHandler,
  getValidatedRouterParams,
  setHeader,
} from 'h3';

import Database from '#server/utils/Database';
import WireGuard from '#server/utils/WireGuard';
import { validateZod } from '#server/utils/types';
import { ConfigFormatUnavailableError } from '#server/utils/wgHelper';
import { OneTimeLinkGetSchema } from '#db/repositories/oneTimeLink/types';

export default defineEventHandler(async (event) => {
  const { oneTimeLink } = await getValidatedRouterParams(
    event,
    validateZod(OneTimeLinkGetSchema, event)
  );

  const otl = await Database.oneTimeLinks.getByOtl(oneTimeLink);
  if (!otl) {
    throw createError({
      statusCode: 404,
      statusMessage: 'Invalid One Time Link',
    });
  }

  if (new Date() > new Date(otl.expiresAt)) {
    throw createError({
      statusCode: 410,
      statusMessage: 'One Time Link has expired',
    });
  }
  if (otl.configFormat === 'migration_pending') {
    throw createError({
      statusCode: 409,
      statusMessage: 'Interface compatibility migration is unresolved',
    });
  }

  const client = await Database.clients.get(otl.id);
  if (!client) {
    throw createError({
      statusCode: 404,
      statusMessage: 'Invalid One Time Link',
    });
  }

  let config: string;
  try {
    config = await WireGuard.getClientConfiguration({
      clientId: client.id,
      format: otl.configFormat,
    });
  } catch (error) {
    if (error instanceof ConfigFormatUnavailableError) {
      throw createError({ statusCode: 409, statusMessage: error.message });
    }
    throw error;
  }
  await Database.oneTimeLinks.erase(otl.id);

  setHeader(
    event,
    'Content-Disposition',
    `attachment; filename="${WireGuard.cleanClientFilename(client.name) || client.id}.conf"`
  );
  setHeader(event, 'Content-Type', 'application/octet-stream');
  return config;
});
