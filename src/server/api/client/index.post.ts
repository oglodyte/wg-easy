import { readValidatedBody } from 'h3';

import Database from '#server/utils/Database';
import WireGuard from '#server/utils/WireGuard';
import { definePermissionEventHandler } from '#server/utils/handler';
import { validateZod } from '#server/utils/types';
import { ClientCreateSchema } from '#db/repositories/client/types';

export default definePermissionEventHandler(
  'clients',
  'create',
  async ({ event }) => {
    const { name, expiresAt, interfaceId } = await readValidatedBody(
      event,
      validateZod(ClientCreateSchema, event)
    );

    const result = await Database.clients.create({
      name,
      expiresAt,
      interfaceId,
    });

    const selectedInterface = await Database.interfaces.getByName(
      interfaceId ?? (await Database.interfaces.getDefault()).name
    );
    const defaultInterface = await Database.interfaces.getDefault();
    // Phase 2 only runs the legacy default interface. A client on a disabled
    // additional interface is persisted without claiming that it is applied.
    if (selectedInterface.name === defaultInterface.name) {
      await WireGuard.saveConfig();
    }

    const clientId = result[0]!.clientId;
    return {
      success: true,
      clientId,
      warning: selectedInterface.enabled
        ? undefined
        : `Interface ${selectedInterface.name} is disabled; this profile will not connect until Phase 3 runtime support is available.`,
    };
  }
);
