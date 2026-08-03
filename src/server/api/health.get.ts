import { defineEventHandler } from 'h3';

import Database from '#server/utils/Database';

/**
 * Container health is application/database readiness. Individual interface
 * runtime state is intentionally descriptive only until Phase 3 owns it.
 */
export default defineEventHandler(async () => {
  const interfaces = await Database.interfaces.getAll();
  return {
    status: 'ready',
    interfaces: interfaces.map((wgInterface) => ({
      name: wgInterface.name,
      enabled: wgInterface.enabled,
      runtime: 'unavailable',
    })),
  };
});
