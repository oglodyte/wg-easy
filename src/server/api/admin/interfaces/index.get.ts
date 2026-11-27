import { publicInterface } from '#server/utils/publicInterface';
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

  return interfaces.map((value) => ({
    ...publicInterface(value),
    isDefault: value.name === defaultInterface.name,
    runtime: runtimeByInterface.get(value.name),
  }));
});
