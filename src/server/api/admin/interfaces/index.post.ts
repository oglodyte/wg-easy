import { readValidatedBody } from 'h3';

import Database from '#server/utils/Database';
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
    const { privateKey: _privateKey, ...safeInterface } = wgInterface;

    return {
      success: true,
      interface: safeInterface,
      runtime: {
        status: 'disabled',
        observedUp: false,
      },
      warning:
        'The interface is saved disabled. Starting additional interfaces is available in Phase 3.',
    };
  }
);
