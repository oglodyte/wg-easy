import { getValidatedRouterParams, readValidatedBody } from 'h3';

import Database from '#server/utils/Database';
import WireGuard from '#server/utils/WireGuard';
import { definePermissionEventHandler } from '#server/utils/handler';
import { validateZod } from '#server/utils/types';
import { InterfaceGetSchema } from '#db/repositories/interface/types';
import { UserConfigUpdateSchema } from '#db/repositories/userConfig/types';

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
      validateZod(UserConfigUpdateSchema, event)
    );
    await Database.userConfigs.update(interfaceId, data);
    return WireGuard.requestReconcile('update-interface-client-defaults', [
      { interfaceId, action: 'none' },
    ]);
  }
);
