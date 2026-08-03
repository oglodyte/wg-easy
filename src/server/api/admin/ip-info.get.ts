import { definePermissionEventHandler } from '#server/utils/handler';
import Database from '#server/utils/Database';
import { getIpInformation } from '#server/utils/ip';

export default definePermissionEventHandler('admin', 'any', async () => {
  const interfaces = await Database.interfaces.getAll();
  return getIpInformation(interfaces.map((wgInterface) => wgInterface.name));
});
