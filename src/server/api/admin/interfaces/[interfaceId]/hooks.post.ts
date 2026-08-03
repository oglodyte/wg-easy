import { getValidatedRouterParams, readValidatedBody } from 'h3';

import Database from '#server/utils/Database';
import { definePermissionEventHandler } from '#server/utils/handler';
import { validateZod } from '#server/utils/types';
import { HooksUpdateSchema } from '#db/repositories/hooks/types';
import { InterfaceGetSchema } from '#db/repositories/interface/types';

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
      validateZod(HooksUpdateSchema, event)
    );
    await Database.hooks.update(interfaceId, data);
    return { success: true, runtime: { status: 'unavailable' } };
  }
);
