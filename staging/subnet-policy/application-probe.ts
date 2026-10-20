/** Synthetic application-service proof; no real application volume or host network. */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { createNodeSqliteDatabase } from "../../src/server/database/nodeSqlite";
import * as schema from "../../src/server/database/schema";
import { ClientService } from "../../src/server/database/repositories/client/service";
import { ClientUpdateSchema } from "../../src/server/database/repositories/client/types";
import { InterfaceService } from "../../src/server/database/repositories/interface/service";
import { RoutingGenerationSnapshotService } from "../../src/server/database/repositories/runtime/generationSnapshot";
import { RoutingPolicyRuntimeService } from "../../src/server/database/repositories/runtime/policyService";
import { RuntimeStateService } from "../../src/server/database/repositories/runtime/service";
import { deriveClientPublicKey } from "../../src/server/utils/clientCredentials";
import { execFile } from "../../src/server/utils/cmd";
import { firewall } from "../../src/server/utils/firewall";
import { buildRoutingPlan } from "../../src/server/utils/routing";
import { buildRoutingGuard } from "../../src/server/utils/routingGuard";
import {
  RoutingPolicyApplication,
  createRoutingPolicyApplicationPorts,
} from "../../src/server/utils/routingPolicyApplication";
import { buildPolicyBootstrapBaseline } from "../../src/server/utils/routingPolicyBootstrap";
import {
  prepareDesiredRoutingConfigurations,
  specializePrivateRoutingGeneration,
} from "../../src/server/utils/routingPolicyGeneration";

if (
  process.platform !== "linux" ||
  process.getuid?.() !== 0 ||
  process.env.WG_EASY_RUN_PRIVILEGED_TESTS !== "1"
)
  throw new Error("Explicit privileged isolated staging execution required");
process.umask(0o077);
const run = (binary: string, args: readonly string[] = []) =>
  execFile(binary, args, { log: false });
const key = () => randomBytes(32).toString("base64");
let stage = "setup";
function checkpoint(value: string) {
  stage = value;
  console.log(JSON.stringify({ applicationProbeStage: value }));
}
function provider(root: string) {
  const store = createNodeSqliteDatabase(path.join(root, "test.db"), schema),
    db = store.db;
  return {
    store,
    db,
    clients: new ClientService(db),
    interfaces: new InterfaceService(db),
    runtime: new RuntimeStateService(db),
    routingGeneration: new RoutingGenerationSnapshotService(db),
    routingPolicy: new RoutingPolicyRuntimeService(db),
  };
}
async function worker(root: string) {
  assert(/^\/tmp\/wge-policy-application-[A-Za-z0-9]+$/.test(root));
  assert.equal(
    await fs.readFile(path.join(root, "owner"), "utf8"),
    "wg-easy isolated application proof\n",
  );
  const p = provider(root),
    ports = createRoutingPolicyApplicationPorts(root),
    down = ports.devices.down.bind(ports.devices);
  ports.devices.down = async (id, config) => {
    await down(id, config);
    if (id === "wg0") process.kill(process.pid, "SIGKILL");
  };
  await new RoutingPolicyApplication(ports, false).reconcile(p, [
    { interfaceId: "wg0", action: "restart" },
  ]);
  throw new Error("Expected worker termination");
}
async function coldWorker(root: string) {
  assert(/^\/tmp\/wge-policy-application-[A-Za-z0-9]+$/.test(root));
  assert.equal(
    await fs.readFile(path.join(root, "owner"), "utf8"),
    "wg-easy isolated application proof\n",
  );
  const p = provider(root),
    ports = createRoutingPolicyApplicationPorts(root),
    app = new RoutingPolicyApplication(ports, false),
    previous = await p.routingPolicy.get();
  assert.ok(previous.pending);
  assert.notEqual(previous.applied!.plan.namespaceId, await ports.namespace());
  try {
    assert.equal((await app.reconcile(p, [])).runtime.status, "applied");
    const state = await p.routingPolicy.get();
    assert.equal(state.pending, null);
    assert.equal(state.applied!.plan.namespaceId, await ports.namespace());
    assert.equal(state.runtime.appliedRevision, state.runtime.desiredRevision);
    await ports.guard.verify(null, { families: [4, 6] });
    console.log(
      JSON.stringify({
        coldPendingNamespaceRecovery: "PASS",
        oldDevicesNotRequired: true,
        newDevicesVerified: true,
      }),
    );
    await app.reconcile(p, [], true);
  } finally {
    await p.store.close();
  }
}
async function main() {
  const root = await fs.mkdtemp("/tmp/wge-policy-application-"),
    p = provider(root),
    ports = createRoutingPolicyApplicationPorts(root),
    app = new RoutingPolicyApplication(ports, false);
  await fs.writeFile(
    path.join(root, "owner"),
    "wg-easy isolated application proof\n",
    { mode: 0o600 },
  );
  const index = async (id: string) =>
    JSON.parse(await run("ip", ["-j", "link", "show", "dev", id]))[0].ifindex;
  try {
    await p.store.migrate({
      migrationsFolder: "/app/server/database/migrations",
    });
    await p.db
      .insert(schema.user)
      .values({
        id: 1,
        username: "lab",
        password: "fixture",
        email: "lab@example.test",
        name: "Lab",
        role: 1,
        enabled: true,
        totpVerified: false,
      })
      .execute();
    const privateKey = key();
    await p.db
      .update(schema.wgInterface)
      .set({
        privateKey,
        publicKey: deriveClientPublicKey(privateKey),
        ipv4Cidr: "10.72.10.0/24",
        ipv6Cidr: null,
        defaultConfigFormat: "wireguard",
      })
      .execute();
    const [iface, defaults, hooks] = await Promise.all([
        p.db.query.wgInterface.findFirst(),
        p.db.query.userConfig.findFirst(),
        p.db.query.hooks.findFirst(),
      ]),
      awgKey = key();
    await p.db.transaction(async (tx) => {
      await tx
        .insert(schema.wgInterface)
        .values({
          ...iface!,
          name: "awg1",
          ipv4Cidr: "10.72.11.0/24",
          port: 62002,
          privateKey: awgKey,
          publicKey: deriveClientPublicKey(awgKey),
          defaultConfigFormat: "amneziawg",
          awgParametersEnabled: true,
          jC: 4,
          jMin: 40,
          jMax: 70,
          h1: "10",
          h2: "20",
          h3: "30",
          h4: "40",
        })
        .execute();
      await tx
        .insert(schema.userConfig)
        .values({ ...defaults!, id: "awg1" })
        .execute();
      await tx
        .insert(schema.hooks)
        .values({ ...hooks!, id: "awg1" })
        .execute();
      await tx
        .insert(schema.interfaceRuntimeState)
        .values({ interfaceId: "awg1" })
        .execute();
      await tx
        .update(schema.hooks)
        .set({ preUp: "", postUp: "", preDown: "", postDown: "" })
        .execute();
    });
    await p.clients.create({ name: "member", interfaceId: "wg0" });
    await p.clients.create({ name: "exit", interfaceId: "awg1" });
    let g = await p.routingGeneration.readPrivateDesiredGeneration();
    const prepared = prepareDesiredRoutingConfigurations(g, new Map(), false),
      up = new Set(["wg0", "awg1"]);
    assert.equal(prepared.failures.size, 0);
    checkpoint("real-v1-baseline");
    for (const [id, config] of prepared.configurations) {
      await fs.writeFile(path.join(root, `${id}.conf`), config!, {
        mode: 0o600,
      });
      await ports.devices.up(id, config!);
      await p.runtime.markInterfaceApplied(id, true);
    }
    await firewall.rebuildAllRules(
      g.interfaces.map((iface) => ({
        wgInterface: iface,
        observedUp: true,
        clients: g.clients.filter((c) => c.interfaceId === iface.name),
        userConfig: {
          defaultAllowedIps: g.defaults.find((d) => d.id === iface.name)!
            .defaultAllowedIps,
        },
      })),
      false,
    );
    const target = specializePrivateRoutingGeneration(g, prepared, {
      upInterfaceIds: up,
      hooksAppliedInterfaceIds: up,
      selectedExitClientIds: new Map(),
      namespaceId: await ports.namespace(),
      enableIpv6: false,
    });
    await ports.executor.apply(
      buildRoutingPlan(buildPolicyBootstrapBaseline(g.snapshot, target.record)),
    );
    await p.runtime.markGlobalApplied(g.policy.runtime.desiredRevision);
    checkpoint("real-promotion");
    await app.promote(p);
    assert.equal((await p.routingPolicy.get()).version, 2);
    const healthyIndex = await index("awg1");
    checkpoint("controlled-stop-sigkill");
    const child = spawn(
      process.execPath,
      [fileURLToPath(import.meta.url), "--worker", root],
      { stdio: ["ignore", "ignore", "ignore"], env: process.env },
    );
    const signal = await new Promise<string | null>((resolve, reject) => {
      child.once("error", reject);
      child.once("exit", (_code, signal) => resolve(signal));
    });
    assert.equal(signal, "SIGKILL");
    assert.ok(
      (
        await p.routingPolicy.get()
      ).pending?.withdrawal?.stopInterfaceIds?.includes("wg0"),
    );
    const fresh = new RoutingPolicyApplication(ports, false);
    await fresh.recover(p);
    assert.equal(await ports.devices.observe("wg0"), null);
    assert.equal(await index("awg1"), healthyIndex);
    assert.equal((await p.routingPolicy.get()).pending, null);
    checkpoint("failed-start-down-rollback");
    const start = ports.devices.up.bind(ports.devices);
    let fail = true;
    ports.devices.up = async (id, config) => {
      if (id === "wg0" && fail) {
        fail = false;
        throw new Error("injected start failure");
      }
      await start(id, config);
    };
    assert.equal((await fresh.reconcile(p, [])).runtime.status, "degraded");
    assert.equal(await ports.devices.observe("wg0"), null);
    assert.equal(await index("awg1"), healthyIndex);
    assert.equal((await fresh.reconcile(p, [])).runtime.status, "applied");
    checkpoint("real-credential-sync");
    const member = (await p.clients.getAll()).find(
      (c) => c.interfaceId === "wg0",
    )!;
    await p.clients.update(member.id, {
      ...ClientUpdateSchema.parse(member),
      privateKey: key(),
      preSharedKey: null,
    });
    assert.equal((await fresh.reconcile(p, [])).runtime.status, "applied");
    assert.equal(await index("awg1"), healthyIndex);
    checkpoint("same-identity-psk-rollback");
    const currentMember = (await p.clients.get(member.id))!,
      beforePsk = await p.routingPolicy.get(),
      oldPrivateBytes = await fs.readFile(path.join(root, "wg0.conf"), "utf8"),
      sync = ports.devices.sync.bind(ports.devices);
    let interruptSync = true;
    ports.devices.sync = async (id, config) => {
      await sync(id, config);
      if (id === "wg0" && interruptSync) {
        interruptSync = false;
        throw new Error("injected post-sync interruption");
      }
    };
    await p.clients.update(member.id, {
      ...ClientUpdateSchema.parse(currentMember),
      preSharedKey: key(),
    });
    await assert.rejects(
      () => fresh.reconcile(p, []),
      (error: { code?: string }) =>
        error.code === "desired_generation_restored",
    );
    assert.equal((await p.routingPolicy.get()).pending, null);
    assert.ok(
      (await p.routingPolicy.get()).applied!.fingerprint ===
        beforePsk.applied!.fingerprint,
    );
    assert.ok(
      (await fs.readFile(path.join(root, "wg0.conf"), "utf8")) ===
        oldPrivateBytes,
    );
    assert.equal((await fresh.reconcile(p, [])).runtime.status, "applied");
    checkpoint("controlled-shutdown-and-restart");
    await fresh.reconcile(p, [], true);
    assert.equal(await ports.devices.observe("wg0"), null);
    assert.equal(await ports.devices.observe("awg1"), null);
    assert.equal(
      (await new RoutingPolicyApplication(ports, false).reconcile(p, []))
        .runtime.status,
      "applied",
    );
    g = await p.routingGeneration.readPrivateDesiredGeneration();
    assert.equal(g.policy.pending, null);
    assert.equal(
      g.policy.runtime.appliedRevision,
      g.policy.runtime.desiredRevision,
    );
    await ports.guard.verify(null, { families: [4, 6] });
    checkpoint("pending-recovery-in-new-namespace");
    const interrupted = spawn(
      process.execPath,
      [fileURLToPath(import.meta.url), "--worker", root],
      {
        stdio: ["ignore", "ignore", "ignore"],
        env: process.env,
      },
    );
    const interruptedSignal = await new Promise<string | null>(
      (resolve, reject) => {
        interrupted.once("error", reject);
        interrupted.once("exit", (_code, signal) => resolve(signal));
      },
    );
    assert.equal(interruptedSignal, "SIGKILL");
    const oldPending = (await p.routingPolicy.get()).pending!;
    assert.ok(oldPending.withdrawal);
    // A replacement container retires the old namespace and userspace daemons.
    // Named netns share this fixture's filesystem, including AWG socket paths;
    // retire its old devices explicitly before entering the replacement netns.
    for (const id of ["wg0", "awg1"])
      await ports.devices.down(
        id,
        await fs.readFile(path.join(root, `${id}.conf`), "utf8"),
      );
    const namespaceName = `wpa${process.pid}`;
    await run("ip", ["netns", "add", namespaceName]);
    try {
      await run("ip", ["-n", namespaceName, "link", "set", "lo", "up"]);
      await run("ip", [
        "netns",
        "exec",
        namespaceName,
        process.execPath,
        fileURLToPath(import.meta.url),
        "--cold-worker",
        root,
      ]);
      assert.equal((await p.routingPolicy.get()).pending, null);
    } finally {
      await run("ip", ["netns", "delete", namespaceName]);
    }
    // Only this fixture's exact old namespace manifest is removed on teardown.
    await ports.guard.remove(
      buildRoutingGuard(oldPending.guardScopes, { protectedPaths: [] }),
    );
    console.log(
      JSON.stringify({
        applicationServiceProof: "PASS",
        promotion: true,
        controlledStopSigkill: true,
        failedStartRestoredDown: true,
        unaffectedObfuscatedDevice: true,
        credentialReplacementAndPskClear: true,
        sameIdentityPskRollback: true,
        shutdownRestart: true,
        coldPendingNamespaceRecovery: true,
        databaseIntegrity:
          (await p.store.raw.execute("PRAGMA integrity_check")).rows[0]
            ?.integrity_check === "ok",
        backend:
          process.env.AWG_FORCE_USERSPACE === "true"
            ? "pinned-userspace"
            : "kernel",
        componentOnly: true,
      }),
    );
  } finally {
    for (const id of ["wg0", "awg1"]) {
      const config = await fs
        .readFile(path.join(root, `${id}.conf`), "utf8")
        .catch(() => null);
      if (config) await ports.devices.down(id, config).catch(() => {});
    }
    await p.store.close();
    await fs.rm(root, { recursive: true, force: true });
  }
}
try {
  if (process.argv[2] === "--worker") await worker(process.argv[3]!);
  else if (process.argv[2] === "--cold-worker")
    await coldWorker(process.argv[3]!);
  else await main();
} catch (error) {
  const code = (error as { code?: unknown }).code;
  console.error(
    JSON.stringify({
      applicationServiceProof: "FAIL",
      stage,
      code:
        typeof code === "string" && /^[a-z_]+$/.test(code)
          ? code
          : "probe_failed",
    }),
  );
  process.exitCode = 1;
}
