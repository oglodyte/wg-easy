import { readValidatedBody } from 'h3';

import Database from '#server/utils/Database';
import WireGuard from '#server/utils/WireGuard';
import { defineSetupEventHandler } from '#server/utils/handler';
import { validateZod } from '#server/utils/types';
import { UserConfigSetupSchema } from '#db/repositories/userConfig/types';

export default defineSetupEventHandler(4, async ({ event }) => {
  const { host, port } = await readValidatedBody(
    event,
    validateZod(UserConfigSetupSchema, event)
  );

  const defaultInterface = await Database.interfaces.getDefault();
  await Database.userConfigs.updateHostPort(defaultInterface.name, host, port);

  await Database.general.setSetupStep(0);
  return WireGuard.requestReconcile('complete-setup', [
    { interfaceId: defaultInterface.name, action: 'none' },
  ]);
});
