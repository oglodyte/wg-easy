import Database from '#server/utils/Database';
import { definePermissionEventHandler } from '#server/utils/handler';

export default definePermissionEventHandler('clients', 'create', async () => {
  const [interfaces, defaultInterface, runtimeStates] = await Promise.all([
    Database.interfaces.getAll(),
    Database.interfaces.getDefault(),
    Database.runtime.getAllInterfaces(),
  ]);
  const runtimeByInterface = new Map(
    runtimeStates.map((runtime) => [runtime.interfaceId, runtime])
  );
  return interfaces
    .filter(({ pendingDelete }) => !pendingDelete)
    .map((wgInterface) => ({
      interfaceId: wgInterface.name,
      default: wgInterface.name === defaultInterface.name,
      enabled: wgInterface.enabled,
      observedUp: runtimeByInterface.get(wgInterface.name)?.observedUp === true,
      runtimeStatus: runtimeByInterface.get(wgInterface.name)?.status,
      compatibleExportFormats: wgInterface.awgParametersEnabled
        ? ['amneziawg']
        : ['wireguard', 'amneziawg'],
      warning: !wgInterface.enabled
        ? 'This interface is disabled; a new profile will not connect until it is enabled.'
        : runtimeByInterface.get(wgInterface.name)?.status === 'degraded'
          ? 'This interface is degraded; an administrator must resolve its runtime error.'
          : undefined,
    }));
});
