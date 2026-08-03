import Database from '#server/utils/Database';
import { definePermissionEventHandler } from '#server/utils/handler';

export default definePermissionEventHandler('clients', 'create', async () => {
  const [interfaces, defaultInterface] = await Promise.all([
    Database.interfaces.getAll(),
    Database.interfaces.getDefault(),
  ]);
  return interfaces.map((wgInterface) => ({
    interfaceId: wgInterface.name,
    default: wgInterface.name === defaultInterface.name,
    enabled: wgInterface.enabled,
    observedUp: false,
    compatibleExportFormats: wgInterface.awgParametersEnabled
      ? ['amneziawg']
      : ['wireguard', 'amneziawg'],
    warning: wgInterface.enabled
      ? 'Runtime status is unavailable until Phase 3.'
      : 'This interface is disabled; a new profile will not connect until Phase 3 runtime support is available.',
  }));
});
