import Database from '#server/utils/Database';
import { definePermissionEventHandler } from '#server/utils/handler';

export default definePermissionEventHandler('admin', 'any', async () => {
  const [interfaces, defaultInterface, runtimeStates] = await Promise.all([
    Database.interfaces.getAll(),
    Database.interfaces.getDefault(),
    Database.runtime.getAllInterfaces(),
  ]);
  const runtimeByInterface = new Map(
    runtimeStates.map((runtime) => [runtime.interfaceId, runtime])
  );

  return interfaces.map(({ privateKey: _privateKey, ...wgInterface }) => ({
    ...wgInterface,
    isDefault: wgInterface.name === defaultInterface.name,
    runtime: runtimeByInterface.get(wgInterface.name),
  }));
});
