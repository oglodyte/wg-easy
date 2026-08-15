import { readValidatedBody } from 'h3';

import Database from '#server/utils/Database';
import WireGuard from '#server/utils/WireGuard';
import { definePermissionEventHandler } from '#server/utils/handler';
import { validateZod } from '#server/utils/types';
import { RoutingHealthSettingsSchema } from '#shared/utils/schemas';

export default definePermissionEventHandler(
  'admin',
  'any',
  async ({ event }) => {
    const settings = await readValidatedBody(
      event,
      validateZod(RoutingHealthSettingsSchema, event)
    );
    const revision =
      await Database.general.updateRoutingHealthSettings(settings);
    const reconciled = await WireGuard.requestReconcile(
      'routing-health-settings'
    );
    return { success: true, revision, runtime: reconciled.runtime };
  }
);
