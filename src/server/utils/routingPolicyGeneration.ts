import type { PrivateDesiredRoutingGeneration } from '#db/repositories/runtime/generationSnapshot';
import { deriveClientPublicKey } from '#server/utils/clientCredentials';
import { buildPolicyClientFirewall } from '#server/utils/firewall';
import { parseManagedInterfaceConfig } from '#server/utils/managedInterfaceState';
import { admitManagedServerHooks } from '#server/utils/managedServerHooks';
import {
  specializeRoutingPolicy,
  verifyRoutingPolicyPeerMap,
} from '#server/utils/routingPolicyRuntime';
import { wg } from '#server/utils/wgHelper';
import type { RoutingPolicyJournal } from '#shared/types/routingPolicy';

/** Private transient inputs only: never serialize this result in status or logs. */
export function prepareDesiredRoutingConfigurations(
  generation: PrivateDesiredRoutingGeneration,
  previousConfigurations: ReadonlyMap<string, string | null>,
  enableIpv6: boolean
) {
  const configurations = new Map<string, string | null>(),
    failures = new Map<string, string>(),
    clients = new Map<string, PrivateDesiredRoutingGeneration['clients']>(),
    hooks = new Map(generation.hooks.map((h) => [h.id, h]));
  for (const client of generation.clients) {
    const peers = clients.get(client.interfaceId) ?? [];
    peers.push(client);
    clients.set(client.interfaceId, peers);
  }
  for (const iface of generation.interfaces) {
    if (iface.pendingDelete) {
      configurations.set(iface.name, null);
      continue;
    }
    try {
      if (
        iface.defaultConfigFormat === 'migration_pending' ||
        !hooks.has(iface.name) ||
        !generation.defaults.some((d) => d.id === iface.name) ||
        deriveClientPublicKey(iface.privateKey) !== iface.publicKey
      )
        throw new Error();
      const config = [
        wg.generateServerInterface(iface, hooks.get(iface.name)!, {
          enableIpv6,
        }),
        ...(clients.get(iface.name) ?? [])
          .filter((c) => c.enabled)
          .map((c) => wg.generateServerPeer(c, { enableIpv6 })),
        '',
      ].join('\n\n');
      const parsed = parseManagedInterfaceConfig(iface.name, config);
      if (iface.enabled) {
        try {
          admitManagedServerHooks(iface.name, parsed.fields);
        } catch {
          failures.set(iface.name, 'unsupported_server_hooks');
        }
      }
      configurations.set(iface.name, config);
    } catch {
      failures.set(iface.name, 'configuration_unavailable');
      configurations.set(
        iface.name,
        previousConfigurations.get(iface.name) ?? null
      );
    }
  }
  return { configurations, failures };
}

/** One static snapshot drives the complete classifier, filter and private peer map. */
export function specializePrivateRoutingGeneration(
  generation: PrivateDesiredRoutingGeneration,
  prepared: ReturnType<typeof prepareDesiredRoutingConfigurations>,
  {
    selectedExitClientIds,
    upInterfaceIds,
    hooksAppliedInterfaceIds,
    namespaceId,
    enableIpv6,
  }: {
    selectedExitClientIds: ReadonlyMap<number, number | null>;
    upInterfaceIds: ReadonlySet<string>;
    hooksAppliedInterfaceIds: ReadonlySet<string>;
    namespaceId: string;
    enableIpv6: boolean;
  }
) {
  const up = new Set(
      [...upInterfaceIds].filter((id) => !prepared.failures.has(id))
    ),
    enabled = new Set(
      generation.interfaces
        .filter((i) => i.enabled && !i.pendingDelete)
        .map((i) => i.name)
    ),
    clientsById = new Map(generation.clients.map((c) => [c.id, c])),
    defaults = new Map(generation.defaults.map((d) => [d.id, d])),
    hooks = new Map(generation.hooks.map((h) => [h.id, h]));
  const filter = buildPolicyClientFirewall(
    generation.interfaces
      .filter((i) => !i.pendingDelete)
      .map((iface) => ({
        wgInterface: iface,
        observedUp: up.has(iface.name),
        clients: generation.clients.filter((c) => c.interfaceId === iface.name),
        userConfig: {
          defaultAllowedIps: defaults.get(iface.name)?.defaultAllowedIps ?? [],
        },
      })),
    enableIpv6
  );
  const selections = new Map(
    [...selectedExitClientIds].map(([id, clientId]) => [
      id,
      clientId !== null && up.has(clientsById.get(clientId)?.interfaceId ?? '')
        ? clientId
        : null,
    ])
  );
  const specialized = specializeRoutingPolicy(generation.snapshot, {
    selectedExitClientIds: selections,
    enabledInterfaceIds: enabled,
    upInterfaceIds: up,
    hooksAppliedInterfaceIds: new Set(
      [...hooksAppliedInterfaceIds].filter((id) => enabled.has(id))
    ),
    namespaceId,
    enableIpv6,
    clientFirewall: filter,
  });
  const configurations = new Map(prepared.configurations),
    peerPrefixes = new Map(
      specialized.plan.peers.map((p) => [p.clientId, p.prefixes])
    );
  for (const iface of generation.interfaces) {
    if (!up.has(iface.name)) continue;
    const config = [
      wg.generateServerInterface(iface, hooks.get(iface.name)!, { enableIpv6 }),
      ...generation.clients
        .filter((c) => c.interfaceId === iface.name && c.enabled)
        .map((c) =>
          wg.generateServerPeer(c, {
            enableIpv6,
            additionalAllowedIps: peerPrefixes.get(c.id) ?? [],
          })
        ),
      '',
    ].join('\n\n');
    parseManagedInterfaceConfig(iface.name, config);
    configurations.set(iface.name, config);
  }
  verifyRoutingPolicyPeerMap(
    specialized.plan,
    [...configurations].flatMap(([id, config]) =>
      up.has(id) && config !== null
        ? parseManagedInterfaceConfig(id, config).peers.map((p) => ({
            interfaceId: id,
            publicKey: p.get('publickey')!,
            allowedIps: p
              .get('allowedips')!
              .split(',')
              .map((p) => p.trim()),
          }))
        : []
    )
  );
  const record: RoutingPolicyJournal = {
    revision: generation.policy.runtime.desiredRevision,
    plan: specialized.plan,
    fingerprint: specialized.fingerprint,
  };
  return { record, configurations, failures: prepared.failures };
}
