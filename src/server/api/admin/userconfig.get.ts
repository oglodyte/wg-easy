import Database from '#server/utils/Database';
import { definePermissionEventHandler } from '#server/utils/handler';

export default definePermissionEventHandler('admin', 'any', async () => {
  const defaultInterface = await Database.interfaces.getDefault();
  const userConfig = await Database.userConfigs.get(defaultInterface.name);
  return userConfig;
});
