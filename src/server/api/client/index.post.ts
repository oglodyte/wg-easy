import { readValidatedBody } from 'h3';
import { useTranslation } from '@intlify/h3';

import Database from '#server/utils/Database';
import WireGuard from '#server/utils/WireGuard';
import { definePermissionEventHandler } from '#server/utils/handler';
import { validateZod } from '#server/utils/types';
import { ClientConfigurationCreateSchema } from '#db/repositories/client/types';
import { clientMutationHttpError } from '#server/utils/clientMutationRequest';

export default definePermissionEventHandler(
  'clients',
  'create',
  async ({ event }) => {
    const input = await readValidatedBody(
      event,
      validateZod(ClientConfigurationCreateSchema, event)
    );

    let result: Awaited<ReturnType<typeof Database.clients.create>>;
    try {
      result = await Database.clients.create(input);
    } catch (error) {
      return clientMutationHttpError(event, error);
    }
    const clientId = result[0]!.clientId,
      created = (await Database.clients.get(clientId))!;
    const selectedInterface = await Database.interfaces.getByName(
      created.interfaceId
    );
    const runtimeResult = await WireGuard.requestReconcile('create-client', [
      { interfaceId: selectedInterface.name, action: 'sync' },
    ]);

    const t = await useTranslation(event);
    return {
      ...runtimeResult,
      clientId,
      warning: selectedInterface.enabled
        ? undefined
        : t('client.interfaceDisabledWarning', [selectedInterface.name]),
    };
  }
);
