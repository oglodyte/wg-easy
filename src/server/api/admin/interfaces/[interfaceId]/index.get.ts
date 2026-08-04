import { getValidatedRouterParams } from 'h3';

import Database from '#server/utils/Database';
import { definePermissionEventHandler } from '#server/utils/handler';
import { validateZod } from '#server/utils/types';
import { InterfaceGetSchema } from '#db/repositories/interface/types';

export default definePermissionEventHandler(
  'admin',
  'any',
  async ({ event }) => {
    const { interfaceId } = await getValidatedRouterParams(
      event,
      validateZod(InterfaceGetSchema, event)
    );
    const [wgInterface, runtime] = await Promise.all([
      Database.interfaces.getByName(interfaceId),
      Database.runtime.getInterface(interfaceId),
    ]);
    const { privateKey: _privateKey, ...safeInterface } = wgInterface;
    return {
      ...safeInterface,
      runtime,
    };
  }
);
