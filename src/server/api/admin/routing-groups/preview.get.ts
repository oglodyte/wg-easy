import Database from '#server/utils/Database';
import WireGuard from '#server/utils/WireGuard';
import { definePermissionEventHandler } from '#server/utils/handler';
import {
  buildRoutingPlan,
  selectActiveExit,
  type ExitSelectionResult,
} from '#server/utils/routing';

export default definePermissionEventHandler('admin', 'any', async () => {
  const [snapshot, dump] = await Promise.all([
    Database.routingGroups.getPlannerSnapshot(),
    WireGuard.dumpAll(),
  ]);
  const interfaceById = new Map(
    snapshot.interfaces.map((wgInterface) => [
      wgInterface.interfaceId,
      wgInterface,
    ])
  );
  const clientById = new Map(
    snapshot.clients.map((client) => [client.id, client])
  );
  const statusByPeer = new Map(
    dump.statuses.map((status) => [
      `${status.interfaceId}\u0000${status.publicKey}`,
      status,
    ])
  );
  const evaluations: Array<{
    groupId: number;
    selection: ExitSelectionResult;
  }> = [];
  const planningBlockedGroups: Array<{ groupId: number; reason: string }> = [];

  const groups = snapshot.groups.map((group) => {
    if (!group.enabled || group.runtime?.status === 'draft_invalid') {
      if (group.runtime?.status === 'draft_invalid') {
        planningBlockedGroups.push({
          groupId: group.id,
          reason: group.runtime.reason ?? 'Routing group is invalid',
        });
      }
      return { ...group, enabled: false, selectedExitClientId: null };
    }
    const selection = selectActiveExit({
      candidates: group.exits.map((exit) => {
        const client = clientById.get(exit.clientId);
        if (!client) throw new Error(`Routing exit ${exit.clientId} not found`);
        const wgInterface = interfaceById.get(client.interfaceId);
        if (!wgInterface) {
          throw new Error(
            `Routing exit interface ${client.interfaceId} not found`
          );
        }
        const status = statusByPeer.get(
          `${client.interfaceId}\u0000${client.publicKey}`
        );
        return {
          clientId: client.id,
          priority: exit.priority,
          candidateEnabled: exit.enabled,
          clientEnabled: client.enabled,
          interfaceEnabled: wgInterface.enabled,
          interfaceObservedUp:
            wgInterface.observedUp && wgInterface.runtimeStatus === 'up',
          persistentKeepalive: client.persistentKeepalive,
          latestHandshakeAt: status?.latestHandshakeAt ?? null,
          endpoint: status?.endpoint ?? null,
        };
      }),
      current: {
        selectedExitClientId: group.runtime?.selectedExitClientId ?? null,
        selectedSince: group.runtime?.selectedSince
          ? new Date(group.runtime.selectedSince)
          : null,
      },
      settings: snapshot.settings,
    });
    evaluations.push({ groupId: group.id, selection });
    return { ...group, selectedExitClientId: selection.selectedExitClientId };
  });

  const plan = buildRoutingPlan({
    interfaces: snapshot.interfaces,
    clients: snapshot.clients,
    groups,
  });

  return {
    executionAvailable: true,
    executionReason: null,
    desiredRevision: snapshot.runtime.desiredRevision,
    appliedRevision: snapshot.runtime.appliedRevision,
    dumpFailures: dump.failures.map(({ interfaceId }) => ({ interfaceId })),
    planningBlockedGroups,
    evaluations,
    plan,
  };
});
