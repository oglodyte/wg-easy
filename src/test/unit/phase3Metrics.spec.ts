import { describe, expect, test, vi } from 'vitest';

import { getPrometheusResponse } from '#server/routes/metrics/prometheus.get';

vi.mock('#server/utils/Database', () => ({
  default: {
    interfaces: {
      getAll: vi.fn(async () => [
        {
          name: 'wg0',
          enabled: true,
          port: 51820,
          awgParametersEnabled: false,
          defaultConfigFormat: 'wireguard',
        },
        {
          name: 'awg1',
          enabled: true,
          port: 51821,
          awgParametersEnabled: true,
          defaultConfigFormat: 'amneziawg',
        },
      ]),
    },
    runtime: {
      getAllInterfaces: vi.fn(async () => [
        {
          interfaceId: 'wg0',
          observedUp: true,
          desiredRevision: 4,
          appliedRevision: 4,
          status: 'up',
          restartRequired: false,
        },
        {
          interfaceId: 'awg1',
          observedUp: false,
          desiredRevision: 3,
          appliedRevision: 2,
          status: 'degraded',
          restartRequired: true,
        },
      ]),
      getGlobal: vi.fn(async () => ({
        desiredRevision: 4,
        appliedRevision: 3,
        status: 'degraded',
        lastSucceededAt: null,
      })),
    },
    routingGroups: {
      getAll: vi.fn(async () => [
        {
          id: 7,
          name: 'phones "via" home',
          enabled: true,
          routedIpv4Prefixes: ['0.0.0.0/0'],
          exits: [
            {
              clientId: 2,
              priority: 10,
              enabled: true,
              client: {
                id: 2,
                name: 'router',
                interfaceId: 'awg1',
                enabled: true,
                persistentKeepalive: 25,
              },
            },
          ],
          members: [
            {
              clientId: 1,
              client: {
                id: 1,
                name: 'phone',
                interfaceId: 'wg0',
                enabled: true,
                persistentKeepalive: 25,
              },
            },
          ],
          runtime: {
            status: 'active',
            appliedExitClientId: 2,
          },
          execution: { active: true },
        },
        {
          id: 8,
          name: 'offline exits',
          enabled: true,
          routedIpv4Prefixes: ['203.0.113.0/24'],
          exits: [
            {
              clientId: 1,
              priority: 20,
              enabled: true,
              client: {
                id: 1,
                name: 'phone',
                interfaceId: 'wg0',
                enabled: true,
                persistentKeepalive: 25,
              },
            },
          ],
          members: [
            {
              clientId: 2,
              client: {
                id: 2,
                name: 'router',
                interfaceId: 'awg1',
                enabled: true,
                persistentKeepalive: 25,
              },
            },
          ],
          runtime: {
            status: 'host_fallback',
            appliedExitClientId: null,
          },
          execution: { active: false },
        },
      ]),
    },
  },
}));

vi.mock('#server/utils/WireGuard', () => ({
  default: {
    getAllClients: vi.fn(async () => [
      {
        id: 1,
        interfaceId: 'wg0',
        name: 'phone',
        enabled: true,
        ipv4Address: '10.8.0.2',
        ipv6Address: 'fd00::2',
        latestHandshakeAt: new Date(),
        transferRx: 10,
        transferTx: 20,
      },
      {
        id: 2,
        interfaceId: 'awg1',
        name: 'router',
        enabled: true,
        ipv4Address: '10.9.0.2',
        ipv6Address: 'fd01::2',
        latestHandshakeAt: null,
        transferRx: null,
        transferTx: null,
      },
    ]),
  },
}));

vi.mock('#server/utils/handler', () => ({
  defineMetricsHandler: (_type: string, handler: unknown) => handler,
}));

describe('Phase 3 metrics identity', () => {
  test('reports peer and runtime state per interface with stable client IDs', async () => {
    const metrics = await getPrometheusResponse();

    expect(metrics).toContain('wireguard_configured_peers{interface="wg0"} 1');
    expect(metrics).toContain('wireguard_configured_peers{interface="awg1"} 1');
    expect(metrics).toContain(
      'wireguard_sent_bytes{interface="wg0",client_id="1",client_name="phone"'
    );
    expect(metrics).toContain(
      'wireguard_sent_bytes{interface="awg1",client_id="2",client_name="router"'
    );
    expect(metrics).toContain('wg_easy_interface_up{interface="wg0"} 1');
    expect(metrics).toContain('wg_easy_interface_up{interface="awg1"} 0');
    expect(metrics).toContain(
      'wg_easy_interface_desired_revision{interface="awg1"} 3'
    );
    expect(metrics).toContain(
      'wg_easy_interface_applied_revision{interface="awg1"} 2'
    );
    expect(metrics).toContain(
      'wg_easy_interface_reconciliation_degraded{interface="awg1"} 1'
    );
    expect(metrics).toContain('wg_easy_runtime_desired_revision 4');
    expect(metrics).toContain('wg_easy_runtime_applied_revision 3');
    expect(metrics).toContain('wg_easy_runtime_reconciliation_degraded 1');
    expect(metrics).toContain('wg_easy_interface_port{interface="awg1"} 51821');
    expect(metrics).toContain(
      'wg_easy_interface_info{interface="awg1",awg_parameters_enabled="true",default_config_format="amneziawg"} 1'
    );
    expect(metrics).toContain(
      'wg_easy_interface_runtime_status{interface="awg1",status="degraded"} 1'
    );
    expect(metrics).toContain(
      'wg_easy_interface_restart_required{interface="awg1"} 1'
    );
    expect(metrics).toContain(
      'wg_easy_client_enabled{interface="wg0",client_id="1",client_name="phone"} 1'
    );
    expect(metrics).toContain('wg_easy_routing_groups_total 2');
    expect(metrics).toContain(
      'wg_easy_routing_group_active{group_id="7",group_name="phones \\"via\\" home"} 1'
    );
    expect(metrics).toContain(
      'wg_easy_routing_group_members{group_id="7",group_name="phones \\"via\\" home"} 1'
    );
    expect(metrics).toContain(
      'wg_easy_routing_group_all_exits_down{group_id="8",group_name="offline exits"} 1'
    );
    expect(metrics).toContain(
      'wg_easy_client_is_exit{interface="awg1",client_id="2",client_name="router"} 1'
    );
    expect(metrics).toContain(
      'wg_easy_exit_client_active_groups{interface="awg1",client_id="2",client_name="router"} 1'
    );
    expect(metrics).toContain(
      'wg_easy_exit_client_candidate_priority{interface="awg1",client_id="2",client_name="router",group_id="7"} 10'
    );
  });
});
