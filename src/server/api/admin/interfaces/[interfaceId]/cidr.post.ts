import { createError, getValidatedRouterParams, readValidatedBody } from 'h3';

import Database from '#server/utils/Database';
import WireGuard from '#server/utils/WireGuard';
import { definePermissionEventHandler } from '#server/utils/handler';
import { validateZod } from '#server/utils/types';
import {
  InterfaceCidrUpdateSchema,
  InterfaceGetSchema,
} from '#db/repositories/interface/types';
import { InterfaceReservationConflictError } from '#db/repositories/interface/service';

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
      validateZod(InterfaceCidrUpdateSchema, event)
    );
    try {
      await Database.interfaces.updateCidr(interfaceId, data);
    } catch (error) {
      if (error instanceof InterfaceReservationConflictError) {
        throw createError({ statusCode: 409, statusMessage: error.message });
      }
      throw error;
    }
    return WireGuard.requestReconcile('update-interface-cidr', [
      { interfaceId, action: 'restart' },
    ]);
  }
);
