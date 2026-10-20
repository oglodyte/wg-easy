/** Veth classifier proof; real AWG peer ownership has a separate phase gate. */
import assert from "node:assert/strict";

import {
  RoutingExecutor,
  type RoutingApplyPhase,
} from "../../src/server/utils/routingExecutor";
import {
  RoutingGuard,
  type RoutingGuardScope,
} from "../../src/server/utils/routingGuard";
import { renderRoutingPolicyLinux } from "../../src/server/utils/routingPolicyLinux";
import { specializeRoutingPolicy } from "../../src/server/utils/routingPolicyRuntime";
import { buildRoutingPolicyTransition } from "../../src/server/utils/routingPolicyTransition";
import type {
  PolicySnapshot,
  AppliedRoutingPolicyPlan,
} from "../../src/shared/types/routingPolicy";
import type { execFile } from "../../src/server/utils/cmd";

export async function provePolicyClassifier({
  server,
  fetchFrom,
  denied,
  management,
  protectedPaths,
  checkpoint,
  exitMac,
}: {
  server: typeof execFile;
  fetchFrom: (destination?: string) => Promise<{ source: string }>;
  denied: () => Promise<void>;
  management: () => Promise<unknown>;
  protectedPaths: RoutingGuardScope[];
  checkpoint: (name: string) => void;
  exitMac: string;
}) {
  const snapshot: PolicySnapshot = {
    interfaces: [
      { interfaceId: "wg0", ipv4Cidr: "10.240.1.0/24" },
      { interfaceId: "awg1", ipv4Cidr: "10.240.2.0/24" },
    ],
    clients: [
      { id: 1, interfaceId: "wg0", ipv4Address: "10.240.1.2" },
      { id: 2, interfaceId: "awg1", ipv4Address: "10.240.2.2" },
      { id: 3, interfaceId: "awg1", ipv4Address: "10.240.2.3" },
    ].map((c) => ({
      ...c,
      name: `probe ${c.id}`,
      publicKey: `public ${c.id}`,
      enabled: true,
      serverAllowedIps: [],
    })),
    groups: [
      {
        id: 1,
        name: "Default",
        routingSlot: 1,
        enabled: true,
        natEnabled: true,
        allExitsDownPolicy: "block",
        routedIpv4Prefixes: ["0.0.0.0/0"],
        memberClientIds: [1],
        exits: [{ clientId: 2, priority: 0, enabled: true }],
      },
      {
        id: 2,
        name: "LAN",
        routingSlot: 2,
        enabled: true,
        natEnabled: false,
        allExitsDownPolicy: "block",
        routedIpv4Prefixes: ["172.31.200.0/24"],
        memberClientIds: [1],
        exits: [{ clientId: 3, priority: 0, enabled: true }],
      },
    ],
  };
  const runtime = (value: PolicySnapshot, selected: number | null) =>
    specializeRoutingPolicy(value, {
      selectedExitClientIds: new Map(
        value.groups.map((g) => [g.id, g.id === 1 ? 2 : selected]),
      ),
      enabledInterfaceIds: new Set(["wg0", "awg1"]),
      upInterfaceIds: new Set(["wg0", "awg1"]),
      enableIpv6: false,
      clientFirewall: { enableIpv6: false, interfaces: [], entries: [] },
    }).plan;
  for (const address of ["172.31.200.2", "172.31.201.2"])
    await server("ip", [
      "neigh",
      "replace",
      address,
      "lladdr",
      exitMac,
      "nud",
      "permanent",
      "dev",
      "awg1",
    ]);
  const guard = new RoutingGuard(server);
  let current = runtime({ ...snapshot, groups: [] }, null);
  let currentLinux = renderRoutingPolicyLinux(current);
  async function apply(target: AppliedRoutingPolicyPlan) {
    const closure = buildRoutingPolicyTransition(current, target, {
        protectedPaths,
      }),
      next = renderRoutingPolicyLinux(target);
    await guard.install(closure);
    await new RoutingExecutor(server).apply(next, {
      previousPlan: currentLinux,
      guardedTransition: { guard: closure, knownPlans: [currentLinux] },
    });
    await guard.remove(closure);
    await new RoutingExecutor(server).verify(next, null);
    current = target;
    currentLinux = next;
  }
  checkpoint("policy-shared-classifier");
  await apply(runtime(snapshot, 3));
  assert.equal(currentLinux.classifier!.children.length, 1);
  assert.equal((await fetchFrom()).source, "10.240.1.2");
  assert.equal((await fetchFrom("172.31.201.2")).source, "10.240.2.1");
  await management();

  const blocked = runtime(snapshot, null);
  checkpoint("policy-terminal-block");
  await apply(blocked);
  await denied();
  assert.equal((await fetchFrom("172.31.201.2")).source, "10.240.2.1");
  const host = runtime(
    {
      ...snapshot,
      groups: snapshot.groups.map((g) =>
        g.id === 2 ? { ...g, allExitsDownPolicy: "host" } : g,
      ),
    },
    null,
  );
  checkpoint("policy-terminal-host");
  await apply(host);
  assert.equal((await fetchFrom()).source, "10.240.1.2");
  await apply(runtime(snapshot, 3));

  const phases: RoutingApplyPhase[] = [
    "preflight",
    "routes",
    "rules",
    "transition_nat",
    "mark_activation",
    "final_nat",
    "cleanup",
    "verify",
  ];
  for (const phase of phases) {
    checkpoint(`policy-fault-${phase}`);
    const target = renderRoutingPolicyLinux(blocked),
      previous = currentLinux;
    const closure = buildRoutingPolicyTransition(current, blocked, {
      protectedPaths,
    });
    await guard.install(closure);
    await assert.rejects(
      new RoutingExecutor(server).apply(target, {
        previousPlan: previous,
        guardedTransition: { guard: closure, knownPlans: [previous] },
        afterPhase: (at) => {
          if (at === phase) throw new Error(`injected ${phase}`);
        },
      }),
      /injected/,
    );
    await new RoutingGuard(server).verify(closure);
    await denied();
    // The unchanged default path, independent management and foreign state stay available.
    assert.equal((await fetchFrom("172.31.201.2")).source, "10.240.2.1");
    await management();
    // A fresh executor restores complete Linux state under the retained guard.
    await new RoutingExecutor(server).apply(previous, {
      previousPlan: target,
      guardedTransition: { guard: closure, knownPlans: [previous, target] },
    });
    await guard.remove(closure);
    await new RoutingExecutor(server).verify(previous, null);
    assert.equal((await fetchFrom()).source, "10.240.1.2");
  }
  checkpoint("policy-foreign-body-refusal");
  const child = currentLinux.classifier!.children[0]!.name;
  await server("iptables", ["-t", "mangle", "-A", child, "-j", "ACCEPT"]);
  const before = await server("iptables-save", ["-t", "mangle"]);
  const closure = buildRoutingPolicyTransition(current, blocked, {
    protectedPaths,
  });
  await guard.install(closure);
  await assert.rejects(
    new RoutingExecutor(server).apply(renderRoutingPolicyLinux(blocked), {
      previousPlan: currentLinux,
      guardedTransition: { guard: closure, knownPlans: [currentLinux] },
    }),
    /ownership is unknown/,
  );
  const after = await server("iptables-save", ["-t", "mangle"]);
  // Background probe traffic may advance built-in-chain packet/byte counters.
  // Retain exact table/chain identity, policy and every ordered rule body.
  const policyBody = (save: string) =>
    save
      .split("\n")
      .filter((line) => !line.startsWith("#"))
      .map((line) =>
        line.startsWith(":") ? line.replace(/\[\d+:\d+\]$/, "[0:0]") : line,
      );
  assert.deepEqual(policyBody(after), policyBody(before));
  await server("iptables", ["-t", "mangle", "-D", child, "-j", "ACCEPT"]);
  await guard.remove(closure);
  await new RoutingExecutor(server).verify(currentLinux, null);
  assert.equal((await fetchFrom()).source, "10.240.1.2");
  return {
    policyClassifier: true,
    terminalBlockHost: true,
    sameOutputDevice: true,
    faultBoundaries: phases.length,
    retainedGuardRecovery: true,
    foreignBodyRefused: true,
  };
}
