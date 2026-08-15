import { readValidatedBody } from 'h3';

import Database from '#server/utils/Database';
import WireGuard from '#server/utils/WireGuard';
import { definePermissionEventHandler } from '#server/utils/handler';
import { validateZod } from '#server/utils/types';
import { HooksUpdateSchema } from '#db/repositories/hooks/types';

export default definePermissionEventHandler(
  'admin',
  'any',
  async ({ event }) => {
    const data = await readValidatedBody(
      event,
      validateZod(HooksUpdateSchema, event)
    );
    const defaultInterface = await Database.interfaces.getDefault();
    await Database.hooks.update(defaultInterface.name, data);
    return WireGuard.requestReconcile('update-default-interface-hooks', [
      { interfaceId: defaultInterface.name, action: 'restart' },
    ]);
  }
);
