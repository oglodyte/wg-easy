import { describe, expect, test } from 'vitest';

import { mergeClientStatuses } from '#server/utils/clientStatus';

describe('mergeClientStatuses', () => {
  test('assigns active peer counters only to the enabled version', () => {
    const base = {
      interfaceId: 'wg0',
      publicKey: 'shared',
      latestHandshakeAt: null,
      endpoint: null,
      transferRx: null,
      transferTx: null,
    };
    for (const order of [
      [true, false],
      [false, true],
      [false, false],
    ]) {
      const clients = order.map((enabled) => ({ ...base, enabled }));
      const result = mergeClientStatuses(clients, [
        { ...base, transferRx: 123, transferTx: 456 },
      ]);
      expect(result.map((c) => c.transferRx)).toEqual(
        order.map((enabled) => (enabled ? 123 : null))
      );
    }
  });
  test('merges matching status records by interface and public key', () => {
    const clients = [
      {
        id: 1,
        interfaceId: 'wg0',
        publicKey: 'first',
        latestHandshakeAt: null,
        endpoint: null,
        transferRx: null,
        transferTx: null,
      },
      {
        id: 2,
        interfaceId: 'awg1',
        publicKey: 'second',
        latestHandshakeAt: null,
        endpoint: null,
        transferRx: null,
        transferTx: null,
      },
    ];
    const handshake = new Date('2026-07-20T00:00:00Z');

    const result = mergeClientStatuses(clients, [
      {
        interfaceId: 'awg1',
        publicKey: 'second',
        latestHandshakeAt: handshake,
        endpoint: '192.0.2.1:51820',
        transferRx: 100,
        transferTx: 200,
      },
      {
        interfaceId: 'wg0',
        publicKey: 'unknown',
        latestHandshakeAt: null,
        endpoint: null,
        transferRx: 0,
        transferTx: 0,
      },
    ]);

    expect(result).toBe(clients);
    expect(result[0]?.endpoint).toBeNull();
    expect(result[1]).toMatchObject({
      latestHandshakeAt: handshake,
      endpoint: '192.0.2.1:51820',
      transferRx: 100,
      transferTx: 200,
    });

    const duplicateKey = mergeClientStatuses(
      [
        {
          ...clients[0]!,
          publicKey: 'shared-public-key',
          endpoint: null,
        },
        {
          ...clients[1]!,
          publicKey: 'shared-public-key',
          endpoint: null,
        },
      ],
      [
        {
          interfaceId: 'awg1',
          publicKey: 'shared-public-key',
          latestHandshakeAt: handshake,
          endpoint: '198.51.100.2:51821',
          transferRx: 1,
          transferTx: 2,
        },
      ]
    );
    expect(duplicateKey[0]?.endpoint).toBeNull();
    expect(duplicateKey[1]?.endpoint).toBe('198.51.100.2:51821');
  });
});
