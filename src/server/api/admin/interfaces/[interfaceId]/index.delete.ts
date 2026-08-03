import { createError } from 'h3';

import { definePermissionEventHandler } from '#server/utils/handler';

export default definePermissionEventHandler('admin', 'any', async () => {
  throw createError({
    statusCode: 409,
    statusMessage: 'Staged interface deletion is unavailable until Phase 3.',
  });
});
