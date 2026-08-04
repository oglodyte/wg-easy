import { createError, getValidatedRouterParams } from 'h3';

import Database from '#server/utils/Database';
import WireGuard from '#server/utils/WireGuard';
import { definePermissionEventHandler } from '#server/utils/handler';
import { validateZod } from '#server/utils/types';
import { ClientGetSchema } from '#db/repositories/client/types';

export default definePermissionEventHandler(
  'clients',
  'view',
  async ({ event, checkPermissions }) => {
    const { clientId } = await getValidatedRouterParams(
      event,
      validateZod(ClientGetSchema, event)
    );

    const result = await Database.clients.get(clientId);
    checkPermissions(result);

    if (!result) {
      throw createError({
        statusCode: 404,
        statusMessage: 'Client not found',
      });
    }

    // data can be undefined if the client is disabled
    const [wgInterface, userConfig] = await Promise.all([
      Database.interfaces.getByName(result.interfaceId),
      Database.userConfigs.get(result.interfaceId),
    ]);
    const data = await WireGuard.dumpClient(
      result.interfaceId,
      result.publicKey
    );

    return {
      ...result,
      endpoint: data?.endpoint,
      interface: {
        name: wgInterface.name,
        enabled: wgInterface.enabled,
        awgParametersEnabled: wgInterface.awgParametersEnabled,
        defaultConfigFormat: wgInterface.defaultConfigFormat,
        endpointHost: userConfig.host,
        endpointPort: userConfig.port,
      },
    };
  }
);
