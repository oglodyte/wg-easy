import { createError, getValidatedRouterParams, readValidatedBody } from 'h3';

import Database from '#server/utils/Database';
import { definePermissionEventHandler } from '#server/utils/handler';
import { validateZod } from '#server/utils/types';
import {
  InterfaceGetSchema,
  InterfaceUpdateSchema,
} from '#db/repositories/interface/types';

export default definePermissionEventHandler(
  'admin',
  'any',
  async ({ event }) => {
    const { interfaceId } = await getValidatedRouterParams(
      event,
      validateZod(InterfaceGetSchema, event)
    );
    const data = await readValidatedBody(
      event,
      validateZod(InterfaceUpdateSchema, event)
    );
    const current = await Database.interfaces.getByName(interfaceId);
    if (!current.enabled && data.enabled) {
      throw createError({
        statusCode: 409,
        statusMessage:
          'Additional interface startup is unavailable until Phase 3.',
      });
    }
    await Database.interfaces.update(interfaceId, data);
    return {
      success: true,
      runtime: {
        status: current.enabled ? 'unavailable' : 'disabled',
        observedUp: false,
      },
    };
  }
);
