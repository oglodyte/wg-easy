import { getValidatedRouterParams, readValidatedBody } from 'h3';

import Database from '#server/utils/Database';
import WireGuard from '#server/utils/WireGuard';
import { definePermissionEventHandler } from '#server/utils/handler';
import { validateZod } from '#server/utils/types';
import {
  InterfaceCidrUpdateSchema,
  InterfaceGetSchema,
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
      validateZod(InterfaceCidrUpdateSchema, event)
    );
    await Database.interfaces.assertCidrAndPortAvailable(data, interfaceId);
    await Database.interfaces.updateCidr(interfaceId, data);
    return WireGuard.requestReconcile('update-interface-cidr', [
      { interfaceId, action: 'restart' },
    ]);
  }
);
