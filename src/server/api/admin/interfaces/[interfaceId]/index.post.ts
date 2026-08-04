import { createError, getValidatedRouterParams, readValidatedBody } from 'h3';

import Database from '#server/utils/Database';
import WireGuard from '#server/utils/WireGuard';
import { WG_ENV } from '#server/utils/config';
import { firewall } from '#server/utils/firewall';
import { definePermissionEventHandler } from '#server/utils/handler';
import { validateZod } from '#server/utils/types';
import { getInterfaceRuntimeAction } from '#shared/utils/interfaceLifecycle';
import {
  InterfaceGetSchema,
  InterfaceUpdateSchema,
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
      validateZod(InterfaceUpdateSchema, event)
    );
    const current = await Database.interfaces.getByName(interfaceId);
    if (data.firewallEnabled && !current.firewallEnabled) {
      firewall.clearAvailabilityCache();
      if (!(await firewall.isAvailable(!WG_ENV.DISABLE_IPV6))) {
        throw createError({
          statusCode: 400,
          statusMessage: 'Per-client firewall tools are unavailable.',
        });
      }
    }

    const action =
      current.enabled !== data.enabled
        ? getInterfaceRuntimeAction({
            kind: 'enabled',
            before: current.enabled,
            after: data.enabled,
          })
        : Object.entries(data).some(
              ([key, value]) =>
                key !== 'enabled' &&
                key !== 'firewallEnabled' &&
                key !== 'defaultConfigFormat' &&
                current[key as keyof typeof current] !== value
            )
          ? getInterfaceRuntimeAction({ kind: 'server' })
          : data.firewallEnabled !== current.firewallEnabled
            ? getInterfaceRuntimeAction({ kind: 'peer' })
            : 'none';

    await Database.interfaces.update(interfaceId, data);
    return WireGuard.requestReconcile('update-interface', [
      { interfaceId, action },
    ]);
  }
);
