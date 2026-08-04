import { describe, expect, test, vi } from 'vitest';

import { getPrometheusResponse } from '#server/routes/metrics/prometheus.get';

vi.mock('#server/utils/Database', () => ({
  default: {
    interfaces: {
      getAll: vi.fn(async () => [
        { name: 'wg0', enabled: true },
        { name: 'awg1', enabled: true },
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
        },
        {
          interfaceId: 'awg1',
          observedUp: false,
          desiredRevision: 3,
          appliedRevision: 2,
          status: 'degraded',
        },
      ]),
      getGlobal: vi.fn(async () => ({
        desiredRevision: 4,
        appliedRevision: 3,
        status: 'degraded',
        lastSucceededAt: null,
      })),
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
  });
});
