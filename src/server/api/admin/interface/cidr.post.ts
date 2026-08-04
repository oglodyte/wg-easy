import { readValidatedBody } from 'h3';

import Database from '#server/utils/Database';
import WireGuard from '#server/utils/WireGuard';
import { definePermissionEventHandler } from '#server/utils/handler';
import { validateZod } from '#server/utils/types';
import { InterfaceCidrUpdateSchema } from '#db/repositories/interface/types';

export default definePermissionEventHandler(
  'admin',
  'any',
  async ({ event }) => {
    const data = await readValidatedBody(
      event,
      validateZod(InterfaceCidrUpdateSchema, event)
    );

    const defaultInterface = await Database.interfaces.getDefault();
    await Database.interfaces.updateCidr(defaultInterface.name, data);
    return WireGuard.requestReconcile('update-default-interface-cidr', [
      { interfaceId: defaultInterface.name, action: 'restart' },
    ]);
  }
);
