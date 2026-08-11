import { setHeader } from 'h3';

import Database from '#server/utils/Database';
import WireGuard from '#server/utils/WireGuard';
import { defineMetricsHandler } from '#server/utils/handler';
import { formatPrometheusLabels } from '#server/utils/prometheus';
import { isPeerConnected } from '#shared/utils/time';

export default defineMetricsHandler('prometheus', async ({ event }) => {
  setHeader(event, 'Content-Type', 'text/plain');
  return getPrometheusResponse();
});

export async function getPrometheusResponse() {
  const [interfaces, runtimeStates, reconciliation, clients, routingGroups] =
    await Promise.all([
      Database.interfaces.getAll(),
      Database.runtime.getAllInterfaces(),
      Database.runtime.getGlobal(),
      WireGuard.getAllClients(),
      Database.routingGroups.getAll(),
    ]);
  const runtimeByInterface = new Map(
    runtimeStates.map((runtime) => [runtime.interfaceId, runtime])
  );
  const output: string[] = [];

  output.push(
    '# HELP wg_easy_interface_enabled Whether the managed interface is enabled',
    '# TYPE wg_easy_interface_enabled gauge'
  );
  for (const wgInterface of interfaces) {
    const labels = formatPrometheusLabels({ interface: wgInterface.name });
    output.push(
      `wg_easy_interface_enabled{${labels}} ${wgInterface.enabled ? 1 : 0}`
    );
  }

  output.push(
    '',
    '# HELP wg_easy_interface_port Managed interface UDP listen port',
    '# TYPE wg_easy_interface_port gauge',
    '# HELP wg_easy_interface_info Managed interface compatibility and export defaults',
    '# TYPE wg_easy_interface_info gauge',
    '# HELP wg_easy_interface_runtime_status Current observed interface runtime status',
    '# TYPE wg_easy_interface_runtime_status gauge',
    '# HELP wg_easy_interface_restart_required Whether the interface has unapplied restart-required changes',
    '# TYPE wg_easy_interface_restart_required gauge'
  );
  for (const wgInterface of interfaces) {
    const labels = formatPrometheusLabels({ interface: wgInterface.name });
    const runtime = runtimeByInterface.get(wgInterface.name);
    output.push(
      `wg_easy_interface_port{${labels}} ${wgInterface.port}`,
      `wg_easy_interface_info{${formatPrometheusLabels({
        interface: wgInterface.name,
        awg_parameters_enabled: wgInterface.awgParametersEnabled,
        default_config_format: wgInterface.defaultConfigFormat,
      })}} 1`,
      `wg_easy_interface_runtime_status{${formatPrometheusLabels({
        interface: wgInterface.name,
        status: runtime?.status ?? 'pending',
      })}} 1`,
      `wg_easy_interface_restart_required{${labels}} ${runtime?.restartRequired ? 1 : 0}`
    );
  }

  output.push(
    '',
    '# HELP wg_easy_interface_up Whether the managed interface is observed up',
    '# TYPE wg_easy_interface_up gauge'
  );
  for (const wgInterface of interfaces) {
    const labels = formatPrometheusLabels({ interface: wgInterface.name });
    output.push(
      `wg_easy_interface_up{${labels}} ${runtimeByInterface.get(wgInterface.name)?.observedUp ? 1 : 0}`
    );
  }

  output.push(
    '',
    '# HELP wg_easy_interface_desired_revision Desired interface configuration revision',
    '# TYPE wg_easy_interface_desired_revision gauge',
    '# HELP wg_easy_interface_applied_revision Last successfully applied interface configuration revision',
    '# TYPE wg_easy_interface_applied_revision gauge',
    '# HELP wg_easy_interface_reconciliation_degraded Whether interface reconciliation is degraded',
    '# TYPE wg_easy_interface_reconciliation_degraded gauge'
  );
  for (const wgInterface of interfaces) {
    const labels = formatPrometheusLabels({ interface: wgInterface.name });
    const runtime = runtimeByInterface.get(wgInterface.name);
    output.push(
      `wg_easy_interface_desired_revision{${labels}} ${runtime?.desiredRevision ?? 0}`,
      `wg_easy_interface_applied_revision{${labels}} ${runtime?.appliedRevision ?? 0}`,
      `wg_easy_interface_reconciliation_degraded{${labels}} ${runtime?.status === 'degraded' ? 1 : 0}`
    );
  }

  const sent: string[] = [];
  const received: string[] = [];
  const handshakeAge: string[] = [];
  const handshakeTimestamp: string[] = [];
  const connected: string[] = [];
  const clientEnabled: string[] = [];
  const clientInfo: string[] = [];
  let totalEnabled = 0;
  let totalConnected = 0;

  for (const client of clients) {
    if (client.enabled) totalEnabled++;
    if (isPeerConnected(client)) totalConnected++;
    const labels = formatPrometheusLabels({
      interface: client.interfaceId,
      client_id: client.id,
      client_name: client.name,
      enabled: client.enabled,
      ipv4Address: client.ipv4Address,
      ipv6Address: client.ipv6Address,
      name: client.name,
    });
    sent.push(`wireguard_sent_bytes{${labels}} ${client.transferTx ?? 0}`);
    received.push(
      `wireguard_received_bytes{${labels}} ${client.transferRx ?? 0}`
    );
    connected.push(
      `wg_easy_client_connected{${labels}} ${isPeerConnected(client) ? 1 : 0}`
    );
    const identityLabels = formatPrometheusLabels({
      interface: client.interfaceId,
      client_id: client.id,
      client_name: client.name,
    });
    clientEnabled.push(
      `wg_easy_client_enabled{${identityLabels}} ${client.enabled ? 1 : 0}`
    );
    clientInfo.push(
      `wg_easy_client_info{${formatPrometheusLabels({
        interface: client.interfaceId,
        client_id: client.id,
        client_name: client.name,
        ipv4_address: client.ipv4Address,
        ipv6_address: client.ipv6Address,
      })}} 1`
    );
    if (client.latestHandshakeAt) {
      handshakeAge.push(
        `wireguard_latest_handshake_seconds{${labels}} ${(Date.now() - client.latestHandshakeAt.getTime()) / 1000}`
      );
      handshakeTimestamp.push(
        `wireguard_latest_handshake_timestamp_seconds{${labels}} ${client.latestHandshakeAt.getTime() / 1000}`
      );
    }
  }

  const interfaceCounts = interfaces.flatMap((wgInterface) => {
    const interfaceClients = clients.filter(
      ({ interfaceId }) => interfaceId === wgInterface.name
    );
    const labels = formatPrometheusLabels({ interface: wgInterface.name });
    return [
      `wireguard_configured_peers{${labels}} ${interfaceClients.length}`,
      `wireguard_enabled_peers{${labels}} ${interfaceClients.filter(({ enabled }) => enabled).length}`,
      `wireguard_connected_peers{${labels}} ${interfaceClients.filter(isPeerConnected).length}`,
    ];
  });

  const routingGroupMetrics = routingGroups.flatMap((group) => {
    const labels = formatPrometheusLabels({
      group_id: group.id,
      group_name: group.name,
    });
    const allExitsDown =
      group.enabled &&
      ['awaiting_exit', 'blocked', 'host_fallback'].includes(
        group.runtime?.status ?? ''
      );
    return [
      `wg_easy_routing_group_enabled{${labels}} ${group.enabled ? 1 : 0}`,
      `wg_easy_routing_group_active{${labels}} ${group.execution.active ? 1 : 0}`,
      `wg_easy_routing_group_members{${labels}} ${group.members.length}`,
      `wg_easy_routing_group_prefixes{${labels}} ${group.routedIpv4Prefixes.length}`,
      `wg_easy_routing_group_all_exits_down{${labels}} ${allExitsDown ? 1 : 0}`,
    ];
  });
  const exitClientMetrics = clients.flatMap((client) => {
    const configuredGroups = routingGroups.filter((group) =>
      group.exits.some((exit) => exit.clientId === client.id)
    );
    const labels = formatPrometheusLabels({
      interface: client.interfaceId,
      client_id: client.id,
      client_name: client.name,
    });
    return [
      `wg_easy_client_is_exit{${labels}} ${configuredGroups.length > 0 ? 1 : 0}`,
      `wg_easy_exit_client_groups{${labels}} ${configuredGroups.length}`,
      `wg_easy_exit_client_members{${labels}} ${configuredGroups.reduce(
        (total, group) => total + group.members.length,
        0
      )}`,
      `wg_easy_exit_client_active_groups{${labels}} ${
        configuredGroups.filter(
          (group) =>
            group.runtime?.status === 'active' &&
            group.runtime.appliedExitClientId === client.id
        ).length
      }`,
    ];
  });
  const candidatePriorityMetrics = routingGroups.flatMap((group) =>
    group.exits.map(
      (exit) =>
        `wg_easy_exit_client_candidate_priority{${formatPrometheusLabels({
          interface: exit.client.interfaceId,
          client_id: exit.client.id,
          client_name: exit.client.name,
          group_id: group.id,
        })}} ${exit.priority}`
    )
  );

  output.push(
    '',
    '# HELP wireguard_configured_peers Configured peers by interface',
    '# TYPE wireguard_configured_peers gauge',
    '# HELP wireguard_enabled_peers Enabled peers by interface',
    '# TYPE wireguard_enabled_peers gauge',
    '# HELP wireguard_connected_peers Recently connected peers by interface',
    '# TYPE wireguard_connected_peers gauge',
    ...interfaceCounts,
    '',
    `wg_easy_configured_peers_total ${clients.length}`,
    `wg_easy_enabled_peers_total ${totalEnabled}`,
    `wg_easy_connected_peers_total ${totalConnected}`,
    '',
    '# HELP wireguard_sent_bytes Bytes sent to the peer',
    '# TYPE wireguard_sent_bytes counter',
    ...sent,
    '',
    '# HELP wireguard_received_bytes Bytes received from the peer',
    '# TYPE wireguard_received_bytes counter',
    ...received,
    '',
    '# HELP wireguard_latest_handshake_seconds Seconds since the last handshake',
    '# TYPE wireguard_latest_handshake_seconds gauge',
    ...handshakeAge,
    '',
    '# HELP wireguard_latest_handshake_timestamp_seconds UNIX timestamp of the last handshake',
    '# TYPE wireguard_latest_handshake_timestamp_seconds gauge',
    ...handshakeTimestamp,
    '',
    '# HELP wg_easy_client_connected Whether the client has a recent handshake',
    '# TYPE wg_easy_client_connected gauge',
    ...connected,
    '',
    '# HELP wg_easy_client_enabled Whether the client profile is enabled',
    '# TYPE wg_easy_client_enabled gauge',
    ...clientEnabled,
    '',
    '# HELP wg_easy_client_info Client profile addresses and stable identity',
    '# TYPE wg_easy_client_info gauge',
    ...clientInfo,
    '',
    '# HELP wg_easy_routing_groups_total Configured routing groups',
    '# TYPE wg_easy_routing_groups_total gauge',
    `wg_easy_routing_groups_total ${routingGroups.length}`,
    '# HELP wg_easy_routing_group_enabled Whether the routing group is enabled',
    '# TYPE wg_easy_routing_group_enabled gauge',
    '# HELP wg_easy_routing_group_active Whether the latest desired routing policy is verified active',
    '# TYPE wg_easy_routing_group_active gauge',
    '# HELP wg_easy_routing_group_members Configured routing-group members',
    '# TYPE wg_easy_routing_group_members gauge',
    '# HELP wg_easy_routing_group_prefixes Configured routed IPv4 prefixes',
    '# TYPE wg_easy_routing_group_prefixes gauge',
    '# HELP wg_easy_routing_group_all_exits_down Whether no exit is currently selected for an enabled group',
    '# TYPE wg_easy_routing_group_all_exits_down gauge',
    ...routingGroupMetrics,
    '',
    '# HELP wg_easy_client_is_exit Whether the client is configured as a routing-group exit',
    '# TYPE wg_easy_client_is_exit gauge',
    '# HELP wg_easy_exit_client_groups Routing groups that configure the client as an exit',
    '# TYPE wg_easy_exit_client_groups gauge',
    '# HELP wg_easy_exit_client_members Members depending on groups that configure the client as an exit',
    '# TYPE wg_easy_exit_client_members gauge',
    '# HELP wg_easy_exit_client_active_groups Routing groups currently verified through the exit client',
    '# TYPE wg_easy_exit_client_active_groups gauge',
    ...exitClientMetrics,
    '# HELP wg_easy_exit_client_candidate_priority Configured exit priority within a routing group',
    '# TYPE wg_easy_exit_client_candidate_priority gauge',
    ...candidatePriorityMetrics,
    '',
    `wg_easy_runtime_desired_revision ${reconciliation.desiredRevision}`,
    `wg_easy_runtime_applied_revision ${reconciliation.appliedRevision}`,
    `wg_easy_runtime_reconciliation_degraded ${reconciliation.status === 'degraded' ? 1 : 0}`,
    reconciliation.lastSucceededAt
      ? `wg_easy_runtime_last_success_timestamp_seconds ${new Date(reconciliation.lastSucceededAt).getTime() / 1000}`
      : 'wg_easy_runtime_last_success_timestamp_seconds 0',
    ''
  );

  return output.join('\n');
}
