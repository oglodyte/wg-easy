import { createError, readValidatedBody } from 'h3';

import Database from '#server/utils/Database';
import WireGuard from '#server/utils/WireGuard';
import { definePermissionEventHandler } from '#server/utils/handler';
import { validateZod } from '#server/utils/types';
import { InterfaceUnavailableForClientCreationError } from '#db/repositories/client/service';
import { ClientCreateSchema } from '#db/repositories/client/types';

export default definePermissionEventHandler(
  'clients',
  'create',
  async ({ event }) => {
    const { name, expiresAt, interfaceId } = await readValidatedBody(
      event,
      validateZod(ClientCreateSchema, event)
    );

    let result: Awaited<ReturnType<typeof Database.clients.create>>;
    try {
      result = await Database.clients.create({ name, expiresAt, interfaceId });
    } catch (error) {
      if (error instanceof InterfaceUnavailableForClientCreationError) {
        throw createError({ statusCode: 409, statusMessage: error.message });
      }
      throw error;
    }

    const selectedInterface = await Database.interfaces.getByName(
      interfaceId ?? (await Database.interfaces.getDefault()).name
    );
    const runtimeResult = await WireGuard.requestReconcile('create-client', [
      { interfaceId: selectedInterface.name, action: 'sync' },
    ]);

    const clientId = result[0]!.clientId;
    return {
      ...runtimeResult,
      clientId,
      warning: selectedInterface.enabled
        ? undefined
        : `Interface ${selectedInterface.name} is disabled; this profile will not connect until the interface is enabled.`,
    };
  }
);
