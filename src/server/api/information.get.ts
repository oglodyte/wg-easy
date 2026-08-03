import { defineEventHandler } from 'h3';
import { gt } from 'semver';

import Database from '#server/utils/Database';
import { RELEASE, WG_ENV } from '#server/utils/config';
import { cachedFetchLatestRelease } from '#server/utils/release';

export default defineEventHandler(async () => {
  const latestRelease = await cachedFetchLatestRelease();
  const updateAvailable = gt(latestRelease.version, RELEASE);
  const insecure = WG_ENV.INSECURE;
  const interfaces = await Database.interfaces.getAll();
  const defaultInterface = await Database.interfaces.getDefault();

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
    })),
  };
});
