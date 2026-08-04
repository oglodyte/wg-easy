import { defineEventHandler } from 'h3';

import Database from '#server/utils/Database';
import { toSafeRuntimeState } from '#db/repositories/runtime/service';

/**
 * Container health is application/database readiness. A degraded interface is
 * reported truthfully without making the administration plane unhealthy.
 */
export default defineEventHandler(async () => {
  const [interfaces, runtimeStates, reconciliation] = await Promise.all([
    Database.interfaces.getAll(),
    Database.runtime.getAllInterfaces(),
    Database.runtime.getGlobal(),
  ]);
  const runtimeByInterface = new Map(
    runtimeStates.map((runtime) => [runtime.interfaceId, runtime])
  );
  return {
    status: 'ready',
    runtime: toSafeRuntimeState(reconciliation),
    interfaces: interfaces.map((wgInterface) => ({
      name: wgInterface.name,
      enabled: wgInterface.enabled,
      runtime: runtimeByInterface.get(wgInterface.name)
        ? toSafeRuntimeState(runtimeByInterface.get(wgInterface.name)!)
        : undefined,
    })),
  };
});
