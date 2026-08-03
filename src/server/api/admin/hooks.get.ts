import Database from '#server/utils/Database';
import { definePermissionEventHandler } from '#server/utils/handler';

export default definePermissionEventHandler('admin', 'any', async () => {
  const defaultInterface = await Database.interfaces.getDefault();
  const hooks = await Database.hooks.get(defaultInterface.name);
  return hooks;
});
