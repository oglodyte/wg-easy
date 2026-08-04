import { readValidatedBody } from 'h3';

import Database from '#server/utils/Database';
import WireGuard from '#server/utils/WireGuard';
import { definePermissionEventHandler } from '#server/utils/handler';
import { validateZod } from '#server/utils/types';
import { InterfaceCreateSchema } from '#db/repositories/interface/types';

export default definePermissionEventHandler(
  'admin',
  'any',
  async ({ event }) => {
    const data = await readValidatedBody(
      event,
      validateZod(InterfaceCreateSchema, event)
    );
    const wgInterface = await Database.interfaces.create(data);
    const result = await WireGuard.requestReconcile('create-interface', [
      { interfaceId: wgInterface.name, action: 'none' },
    ]);
    const { privateKey: _privateKey, ...safeInterface } = wgInterface;

    return {
      ...result,
      interface: safeInterface,
      warning:
        'The interface is saved disabled until it is explicitly enabled.',
    };
  }
);
