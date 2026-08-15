import { readValidatedBody } from 'h3';

import Database from '#server/utils/Database';
import WireGuard from '#server/utils/WireGuard';
import { definePermissionEventHandler } from '#server/utils/handler';
import { validateZod } from '#server/utils/types';
import { UserConfigUpdateSchema } from '#db/repositories/userConfig/types';

export default definePermissionEventHandler(
  'admin',
  'any',
  async ({ event }) => {
    const data = await readValidatedBody(
      event,
      validateZod(UserConfigUpdateSchema, event)
    );
    const defaultInterface = await Database.interfaces.getDefault();
    await Database.userConfigs.update(defaultInterface.name, data);
    return WireGuard.requestReconcile(
      'update-default-interface-client-defaults',
      [{ interfaceId: defaultInterface.name, action: 'none' }]
    );
  }
);
