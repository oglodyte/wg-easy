import Database from '#server/utils/Database';
import { definePermissionEventHandler } from '#server/utils/handler';

export default definePermissionEventHandler('admin', 'any', async () => {
  const wgInterface = await Database.interfaces.get();
  const runtime = await Database.runtime.getInterface(wgInterface.name);

  return {
    ...wgInterface,
    privateKey: undefined,
    runtime,
  };
});
