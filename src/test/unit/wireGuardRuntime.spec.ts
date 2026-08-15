import { afterEach, describe, expect, test, vi } from 'vitest';

afterEach(() => {
  vi.resetModules();
  vi.clearAllMocks();
});

async function loadRuntime(
  failedInterface?: string,
  legacyInterface?: string,
  withRouting = false
) {
  const interfaces = [
    {
      name: 'wg0',
      ipv4Cidr: '10.8.0.0/24',
      enabled: true,
      pendingDelete: false,
      defaultConfigFormat: 'wireguard',
      awgParametersEnabled: false,
      privateKey: 'wg0-private',
      publicKey: 'wg0-public',
    },
    {
      name: 'awg1',
      ipv4Cidr: '10.9.0.0/24',
      enabled: true,
      pendingDelete: false,
      defaultConfigFormat: 'amneziawg',
      awgParametersEnabled: true,
      privateKey: 'awg1-private',
      publicKey: 'awg1-public',
      h1: '0',
    },
  ];
  const runtimeStates = interfaces.map(({ name }) => ({
    interfaceId: name,
    desiredRevision: 2,
    appliedRevision: 2,
    status: 'up',
    observedUp: true,
    restartRequired: false,
    lastStartedAt: null,
    lastStoppedAt: null,
    lastAppliedAt: null,
    lastError: null,
  }));
  const globalState = {
    desiredRevision: 2,
    appliedRevision: 1,
    status: 'applying',
    lastError: null as string | null,
  };
  const clients = {
    wg0: [
      {
        id: 1,
        interfaceId: 'wg0',
        name: 'wg-client',
        publicKey: 'wg-client-key',
        ipv4Address: '10.8.0.2',
        persistentKeepalive: 25,
        serverAllowedIps: [] as string[],
        enabled: true,
        expiresAt: null as string | null,
        oneTimeLink: null,
      },
    ],
    awg1: [
      {
        id: 2,
        interfaceId: 'awg1',
        name: 'awg-client',
        publicKey: 'awg-client-key',
        ipv4Address: '10.9.0.2',
        persistentKeepalive: 25,
        serverAllowedIps: [] as string[],
        enabled: true,
        expiresAt: null as string | null,
        oneTimeLink: null,
      },
    ],
  };
  const routingGroupRuntime = {
    groupId: 1,
    selectedExitClientId: null as number | null,
    appliedExitClientId: null as number | null,
    evaluatedRevision: 2,
    appliedRevision: null as number | null,
    selectedSince: null as string | null,
    appliedSince: null as string | null,
    lastEvaluatedAt: null as string | null,
    lastFailoverAt: null as string | null,
    status: 'awaiting_exit',
    reason: null as string | null,
  };
  const routingSnapshot = () => ({
    settings: {
      healthCheckIntervalSeconds: 60,
      healthTimeoutSeconds: 180,
      minHoldSeconds: 60,
      failbackDelaySeconds: 180,
    },
    runtime: globalState,
    interfaces: interfaces.map((wgInterface) => ({
      interfaceId: wgInterface.name,
      ipv4Cidr: wgInterface.ipv4Cidr,
      enabled: wgInterface.enabled,
      observedUp:
        runtimeStates.find(
          (runtime) => runtime.interfaceId === wgInterface.name
        )?.observedUp ?? false,
      runtimeStatus:
        runtimeStates.find(
          (runtime) => runtime.interfaceId === wgInterface.name
        )?.status ?? 'pending',
    })),
    clients: [...clients.wg0, ...clients.awg1],
    groups: [
      {
        id: 1,
        routingSlot: 1,
        enabled: true,
        natEnabled: true,
        allExitsDownPolicy: 'block' as const,
        routedIpv4Prefixes: ['203.0.113.0/24'],
        memberClientIds: [1],
        exits: [{ clientId: 2, priority: 10, enabled: true }],
        runtime: routingGroupRuntime,
      },
    ],
    tombstones: [],
  });
  const updateRuntimeStates = vi.fn(
    async (
      updates: Array<{
        groupId: number;
        state: Record<string, unknown>;
      }>
    ) => {
      for (const update of updates)
        Object.assign(routingGroupRuntime, update.state);
    }
  );

  const runtime = {
    markApplying: vi.fn(async () => 2),
    getAllInterfaces: vi.fn(async () => runtimeStates),
    markInterfaceApplying: vi.fn(async () => {}),
    markInterfaceApplied: vi.fn(async (interfaceId: string, up: boolean) => {
      const state = runtimeStates.find(
        (item) => item.interfaceId === interfaceId
      )!;
      state.observedUp = up;
      state.status = up ? 'up' : 'disabled';
      state.appliedRevision = state.desiredRevision;
    }),
    markInterfaceFailed: vi.fn(
      async (interfaceId: string, error: unknown, observedUp = false) => {
        const state = runtimeStates.find(
          (item) => item.interfaceId === interfaceId
        )!;
        state.observedUp = observedUp;
        state.status = 'degraded';
        state.lastError =
          error instanceof Error ? error.message : String(error);
      }
    ),
    markGlobalApplied: vi.fn(async () => ({
      ...globalState,
      appliedRevision: 2,
      status: 'idle',
    })),
    markGlobalFailed: vi.fn(async (error: Error) => ({
      ...globalState,
      status: 'degraded',
      lastError: error.message,
    })),
    markGlobalPending: vi.fn(async () => ({
      ...globalState,
      status: 'pending',
    })),
  };
  const Database = {
    interfaces: {
      getAll: vi.fn(async () => interfaces),
      getDefault: vi.fn(async () => interfaces[0]),
      getByName: vi.fn(async (interfaceId: string) =>
        interfaces.find(({ name }) => name === interfaceId)
      ),
      updateKeyPair: vi.fn(async () => {}),
      updateAwgHeaders: vi.fn(
        async (
          interfaceId: string,
          headers: { h1: string; h2: string; h3: string; h4: string }
        ) => {
          Object.assign(
            interfaces.find(({ name }) => name === interfaceId)!,
            headers
          );
        }
      ),
      update: vi.fn(async () => {}),
      finalizeDelete: vi.fn(async () => {}),
    },
    clients: {
      getAllForInterface: vi.fn(
        async (interfaceId: keyof typeof clients) => clients[interfaceId]
      ),
      getAll: vi.fn(async () => [...clients.wg0, ...clients.awg1]),
      toggle: vi.fn(async (id: number, enabled: boolean) => {
        const item = [...clients.wg0, ...clients.awg1].find(
          (client) => client.id === id
        );
        if (item) item.enabled = enabled;
      }),
    },
    oneTimeLinks: { delete: vi.fn(async () => {}) },
    hooks: { get: vi.fn(async () => ({})) },
    userConfigs: { get: vi.fn(async () => ({})) },
    routingGroups: {
      hasDeferredRoutingState: vi.fn(async () => withRouting),
      getPlannerSnapshot: vi.fn(async () => routingSnapshot()),
      updateRuntimeStates,
      releaseTombstones: vi.fn(async () => {}),
    },
    runtime,
  };
  const atomicWriteFile = vi.fn(
    async (
      _path: string,
      _contents: string,
      validate?: (path: string) => Promise<void>
    ) => validate?.('/etc/wireguard/.wge-test.conf')
  );
  const existingDevices = new Set(interfaces.map(({ name }) => name));
  const wg = {
    generateServerInterface: vi.fn(
      (wgInterface: { name: string }) => `interface:${wgInterface.name}`
    ),
    generateServerPeer: vi.fn(
      (client: { name: string }) => `peer:${client.name}`
    ),
    validateConfig: vi.fn(async () => {}),
    up: vi.fn(async (interfaceId: string) => {
      if (interfaceId === failedInterface)
        throw new Error('injected up failure');
      existingDevices.add(interfaceId);
    }),
    down: vi.fn(async (interfaceId: string) => {
      if (interfaceId === legacyInterface) {
        throw new Error('not an AmneziaWG interface');
      }
      existingDevices.delete(interfaceId);
    }),
    downLegacy: vi.fn(async (interfaceId: string) => {
      existingDevices.delete(interfaceId);
    }),
    interfaceExists: vi.fn(async (interfaceId: string) =>
      existingDevices.has(interfaceId)
    ),
    sync: vi.fn(async () => {}),
    dump: vi.fn(async (interfaceId: string) => {
      if (!withRouting) return [];
      if (interfaceId === 'wg0') {
        return clients.wg0.map((client) => ({
          publicKey: client.publicKey,
          allowedIps: [
            `${client.ipv4Address}/32`,
            ...client.serverAllowedIps,
          ].join(','),
          endpoint: '192.0.2.20:51820',
          latestHandshakeAt: new Date(),
          transferRx: 1,
          transferTx: 1,
        }));
      }
      return interfaceId === 'awg1'
        ? [
            {
              publicKey: 'awg-client-key',
              allowedIps: '10.9.0.2/32,203.0.113.0/24',
              endpoint: '192.0.2.10:51820',
              latestHandshakeAt: new Date(),
              transferRx: 1,
              transferTx: 1,
            },
          ]
        : [];
    }),
    generatePrivateKey: vi.fn(async () => 'private'),
    getPublicKey: vi.fn(async () => 'public'),
  };
  const firewall = { rebuildAllRules: vi.fn(async () => {}) };
  const applyRouting = vi.fn(async () => {});

  vi.doMock('#server/utils/Database', () => ({ default: Database }));
  vi.doMock('#server/utils/wgHelper', () => ({ wg }));
  vi.doMock('#server/utils/firewall', () => ({ firewall }));
  vi.doMock('#server/utils/routingExecutor', () => ({
    RoutingExecutor: class {
      apply = applyRouting;
    },
  }));
  vi.doMock('#server/utils/atomicFile', () => ({ atomicWriteFile }));
  vi.doMock('#server/utils/config', () => ({
    OLD_ENV: {},
    WG_ENV: { DISABLE_IPV6: false },
  }));

  const WireGuard = (await import('#server/utils/WireGuard')).default;
  return {
    WireGuard,
    Database,
    runtime,
    runtimeStates,
    wg,
    atomicWriteFile,
    firewall,
    applyRouting,
    routingGroupRuntime,
    updateRuntimeStates,
  };
}

describe('interface-scoped WireGuard runtime', () => {
  test('writes per-interface peer sets and isolates an interface startup failure', async () => {
    const { WireGuard, Database, runtime, wg, atomicWriteFile } =
      await loadRuntime('awg1');

    const result = await WireGuard.requestReconcile('startup-test', [
      { interfaceId: 'wg0', action: 'up' },
      { interfaceId: 'awg1', action: 'up' },
    ]);

    expect(result.runtime).toMatchObject({ status: 'degraded' });
    expect(wg.up).toHaveBeenCalledWith('wg0');
    expect(wg.up).toHaveBeenCalledWith('awg1');
    expect(runtime.markInterfaceApplied).toHaveBeenCalledWith('wg0', true, 2);
    expect(runtime.markInterfaceFailed).toHaveBeenCalledWith(
      'awg1',
      expect.any(Error),
      false
    );
    expect(atomicWriteFile).toHaveBeenCalledWith(
      '/etc/wireguard/wg0.conf',
      expect.stringContaining('peer:wg-client'),
      expect.any(Function)
    );
    expect(atomicWriteFile).toHaveBeenCalledWith(
      '/etc/wireguard/awg1.conf',
      expect.stringContaining('peer:awg-client'),
      expect.any(Function)
    );
    expect(atomicWriteFile.mock.calls[0]?.[1]).not.toContain('peer:awg-client');
    expect(wg.validateConfig).toHaveBeenCalledWith(
      '/etc/wireguard/.wge-test.conf'
    );
    expect(Database.interfaces.updateAwgHeaders).toHaveBeenCalledWith(
      'awg1',
      expect.objectContaining({
        h1: expect.not.stringMatching(/^0$/),
        h2: expect.any(String),
        h3: expect.any(String),
        h4: expect.any(String),
      })
    );
  });

  test('restarts only the requested observed-up interface', async () => {
    const { WireGuard, wg } = await loadRuntime();

    const result = await WireGuard.restart('awg1');

    expect(result.runtime.status).toBe('applied');
    expect(wg.down).toHaveBeenCalledTimes(1);
    expect(wg.down).toHaveBeenCalledWith('awg1');
    expect(wg.up).toHaveBeenCalledTimes(1);
    expect(wg.up).toHaveBeenCalledWith('awg1');
    expect(wg.sync).toHaveBeenCalledTimes(1);
    expect(wg.sync).toHaveBeenCalledWith('awg1');
  });

  test('transitions an exact legacy managed device through wg-quick once', async () => {
    const { WireGuard, wg } = await loadRuntime(undefined, 'wg0');

    const result = await WireGuard.restart('wg0');

    expect(result.runtime.status).toBe('applied');
    expect(wg.down).toHaveBeenCalledWith('wg0');
    expect(wg.downLegacy).toHaveBeenCalledWith('wg0');
    expect(wg.up).toHaveBeenCalledWith('wg0');
  });

  test('retries a durable degraded interface without restarting a healthy peer', async () => {
    const { WireGuard, runtimeStates, wg } = await loadRuntime();
    Object.assign(runtimeStates[1]!, {
      appliedRevision: 1,
      status: 'degraded',
      restartRequired: true,
      lastError: 'previous sync failed',
    });

    await WireGuard.requestReconcile('retry-durable-failure');

    expect(wg.down).toHaveBeenCalledTimes(1);
    expect(wg.down).toHaveBeenCalledWith('awg1');
    expect(wg.up).toHaveBeenCalledTimes(1);
    expect(wg.up).toHaveBeenCalledWith('awg1');
  });

  test('keeps client detail available when its interface status dump fails', async () => {
    const { WireGuard, wg } = await loadRuntime();
    wg.dump.mockRejectedValueOnce(new Error('injected dump failure'));

    await expect(WireGuard.dumpClient('awg1', 'client-key')).resolves.toBe(
      undefined
    );
  });

  test('expires clients across interfaces and syncs only the affected configs', async () => {
    const { WireGuard, Database, wg } = await loadRuntime();
    const allClients = await Database.clients.getAll();
    allClients[0]!.expiresAt = '2000-01-01T00:00:00.000Z';
    allClients[1]!.expiresAt = '2000-01-01T00:00:00.000Z';

    await WireGuard.cronJob();

    expect(Database.clients.toggle).toHaveBeenCalledWith(1, false);
    expect(Database.clients.toggle).toHaveBeenCalledWith(2, false);
    expect(wg.sync).toHaveBeenCalledTimes(2);
    expect(wg.sync).toHaveBeenCalledWith('wg0');
    expect(wg.sync).toHaveBeenCalledWith('awg1');
  });

  test('shuts down every interface recorded as observed up', async () => {
    const { WireGuard, wg } = await loadRuntime();

    await WireGuard.Shutdown();

    expect(wg.down).toHaveBeenCalledTimes(2);
    expect(wg.down).toHaveBeenCalledWith('wg0');
    expect(wg.down).toHaveBeenCalledWith('awg1');
  });

  test('bootstraps block policy, moves prefixes to the selected exit, and verifies runtime state', async () => {
    const {
      WireGuard,
      wg,
      applyRouting,
      Database,
      routingGroupRuntime,
      updateRuntimeStates,
    } = await loadRuntime(undefined, undefined, true);
    const [siteToSiteClient] = await Database.clients.getAll();
    siteToSiteClient!.serverAllowedIps = ['198.51.100.0/24'];

    const result = await WireGuard.requestReconcile('routing-group-update');

    expect(result.runtime.status).toBe('applied');
    expect(applyRouting).toHaveBeenCalledTimes(2);
    expect(applyRouting.mock.calls[0]?.[0].groups).toContainEqual(
      expect.objectContaining({ outcome: 'block' })
    );
    expect(applyRouting.mock.calls[0]?.[0].routes).not.toContainEqual(
      expect.objectContaining({ table: 51999 })
    );
    expect(applyRouting.mock.calls[0]?.[0].policyRules).not.toContainEqual(
      expect.objectContaining({ priority: 23000 })
    );
    expect(
      applyRouting.mock.calls[0]?.[0].routes.every(
        (route: { device?: string }) => route.device === undefined
      )
    ).toBe(true);
    expect(applyRouting.mock.calls[1]?.[0].groups).toContainEqual(
      expect.objectContaining({
        outcome: 'selected_exit',
        selectedExitClientId: 2,
      })
    );
    expect(applyRouting.mock.calls[1]?.[0].routes).toContainEqual(
      expect.objectContaining({
        table: 51999,
        prefix: '198.51.100.0/24',
        device: 'wg0',
      })
    );
    expect(wg.generateServerPeer).toHaveBeenCalledWith(
      expect.objectContaining({ id: 2 }),
      expect.objectContaining({
        additionalAllowedIps: ['203.0.113.0/24'],
      })
    );
    expect(updateRuntimeStates).toHaveBeenCalled();
    expect(routingGroupRuntime).toMatchObject({
      selectedExitClientId: 2,
      appliedExitClientId: 2,
      appliedRevision: 2,
      status: 'active',
    });

    await WireGuard.requestReconcile('routing-health-check');
    expect(applyRouting).toHaveBeenCalledTimes(2);
  });

  test('retains the bootstrap plan when exit peer prefixes cannot be verified', async () => {
    const { WireGuard, wg, applyRouting, routingGroupRuntime } =
      await loadRuntime(undefined, undefined, true);
    wg.dump.mockResolvedValue([
      {
        publicKey: 'awg-client-key',
        allowedIps: '10.9.0.2/32',
        endpoint: '192.0.2.10:51820',
        latestHandshakeAt: new Date(),
        transferRx: 1,
        transferTx: 1,
      },
    ]);

    const result = await WireGuard.requestReconcile('routing-group-update');

    expect(result.runtime.status).toBe('degraded');
    expect(applyRouting).toHaveBeenCalledTimes(3);
    expect(routingGroupRuntime).toMatchObject({
      selectedExitClientId: 2,
      appliedExitClientId: null,
      appliedRevision: null,
      status: 'degraded',
    });
  });
});
