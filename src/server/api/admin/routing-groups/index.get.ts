import Database from '#server/utils/Database';
import { definePermissionEventHandler } from '#server/utils/handler';

export default definePermissionEventHandler('admin', 'any', async () => {
  const [groups, runtime] = await Promise.all([
    Database.routingGroups.getAll(),
    Database.runtime.getGlobal(),
  ]);
  return {
    executionAvailable: false,
    executionReason: 'Common routing execution is unavailable until Phase 6.',
    desiredRevision: runtime.desiredRevision,
    appliedRevision: runtime.appliedRevision,
    groups,
  };
});
