import Database from '#server/utils/Database';
import { definePermissionEventHandler } from '#server/utils/handler';

export default definePermissionEventHandler('admin', 'any', async () => {
  const [interfaces, defaultInterface] = await Promise.all([
    Database.interfaces.getAll(),
    Database.interfaces.getDefault(),
  ]);

  return interfaces.map(({ privateKey: _privateKey, ...wgInterface }) => ({
    ...wgInterface,
    isDefault: wgInterface.name === defaultInterface.name,
    runtime: {
      status: wgInterface.enabled ? 'unavailable' : 'disabled',
      observedUp: false,
    },
  }));
});
