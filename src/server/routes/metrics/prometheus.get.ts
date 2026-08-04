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
  const [interfaces, runtimeStates, reconciliation, clients] =
    await Promise.all([
      Database.interfaces.getAll(),
      Database.runtime.getAllInterfaces(),
      Database.runtime.getGlobal(),
      WireGuard.getAllClients(),
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
