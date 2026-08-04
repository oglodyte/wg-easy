import { createError, readValidatedBody } from 'h3';

import Database from '#server/utils/Database';
import WireGuard from '#server/utils/WireGuard';
import { WG_ENV } from '#server/utils/config';
import { firewall } from '#server/utils/firewall';
import { definePermissionEventHandler } from '#server/utils/handler';
import { validateZod } from '#server/utils/types';
import { InterfaceUpdateSchema } from '#db/repositories/interface/types';
import { getInterfaceRuntimeAction } from '#shared/utils/interfaceLifecycle';

export default definePermissionEventHandler(
  'admin',
  'any',
  async ({ event }) => {
    const data = await readValidatedBody(
      event,
      validateZod(InterfaceUpdateSchema, event)
    );

    // If enabling firewall, check if iptables is available
    if (data.firewallEnabled) {
      // Clear cache to force fresh check
      firewall.clearAvailabilityCache();

      const iptablesAvailable = await firewall.isAvailable(
        !WG_ENV.DISABLE_IPV6
      );
      if (!iptablesAvailable) {
        const requiredTools = WG_ENV.DISABLE_IPV6
          ? 'iptables'
          : 'iptables and ip6tables';
        throw createError({
          statusCode: 400,
          statusMessage: `Per-Client Firewall requires ${requiredTools} to be installed on the host system. Please install ${requiredTools} before enabling this feature.`,
        });
      }
    }

    const defaultInterface = await Database.interfaces.getDefault();
    const action =
      defaultInterface.enabled !== data.enabled
        ? getInterfaceRuntimeAction({
            kind: 'enabled',
            before: defaultInterface.enabled,
            after: data.enabled,
          })
        : Object.entries(data).some(
              ([key, value]) =>
                key !== 'enabled' &&
                key !== 'firewallEnabled' &&
                key !== 'defaultConfigFormat' &&
                defaultInterface[key as keyof typeof defaultInterface] !== value
            )
          ? 'restart'
          : data.firewallEnabled !== defaultInterface.firewallEnabled
            ? 'sync'
            : 'none';
    await Database.interfaces.update(defaultInterface.name, data);
    return WireGuard.requestReconcile('update-default-interface', [
      { interfaceId: defaultInterface.name, action },
    ]);
  }
);
