import { defineEventHandler } from 'h3';
import { gt } from 'semver';

import Database from '#server/utils/Database';
import { RELEASE, WG_ENV } from '#server/utils/config';
import { cachedFetchLatestRelease } from '#server/utils/release';
import { toSafeRuntimeState } from '#db/repositories/runtime/service';

export default defineEventHandler(async () => {
  const latestRelease = await cachedFetchLatestRelease();
  const updateAvailable = gt(latestRelease.version, RELEASE);
  const insecure = WG_ENV.INSECURE;
  const [interfaces, defaultInterface, runtimeStates, reconciliation] =
    await Promise.all([
      Database.interfaces.getAll(),
      Database.interfaces.getDefault(),
      Database.runtime.getAllInterfaces(),
      Database.runtime.getGlobal(),
    ]);
  const runtimeByInterface = new Map(
    runtimeStates.map((runtime) => [runtime.interfaceId, runtime])
  );

  return {
    currentRelease: RELEASE,
    latestRelease: latestRelease,
    updateAvailable,
    insecure,
    isAwg: true,
    runtimeBackend: 'awg',
    defaultInterfaceId: defaultInterface.name,
    firewallEnabled: interfaces.some(
      (wgInterface) => wgInterface.enabled && wgInterface.firewallEnabled
    ),
    interfaces: interfaces.map((wgInterface) => ({
      name: wgInterface.name,
      enabled: wgInterface.enabled,
      firewallEnabled: wgInterface.firewallEnabled,
      runtime: runtimeByInterface.get(wgInterface.name)
        ? toSafeRuntimeState(runtimeByInterface.get(wgInterface.name)!)
        : undefined,
    })),
    runtime: toSafeRuntimeState(reconciliation),
    commonRouting: {
      available: true,
      reason: null,
    },
  };
});
