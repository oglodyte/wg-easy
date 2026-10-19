/** Dedicated staging only: real AWG kernel peers and durable process recovery. */
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { createNodeSqliteDatabase } from "../../src/server/database/nodeSqlite";
import { RoutingPolicyRuntimeService } from "../../src/server/database/repositories/runtime/policyService";
import * as schema from "../../src/server/database/schema";
import { execFile, withSecureInputFile } from "../../src/server/utils/cmd";
import {
  preparePeerSyncConfig,
  verifyPeerSyncPresharedKeys,
} from "../../src/server/utils/peerSyncConfig";
import { RoutingExecutor } from "../../src/server/utils/routingExecutor";
import {
  buildRoutingGuard,
  assertRoutingGuardState,
  RoutingGuard,
  type RoutingGuardScope,
} from "../../src/server/utils/routingGuard";
import { RoutingPolicyBackups } from "../../src/server/utils/routingPolicyBackups";
import { RoutingPolicyFirewall } from "../../src/server/utils/routingPolicyFirewall";
import {
  ManagedInterfaceStateError,
  verifyManagedInterfaceState,
} from "../../src/server/utils/managedInterfaceState";
import { parseRoutingPolicyJournal } from "../../src/server/utils/routingPolicyJournal";
import { renderRoutingPolicyLinux } from "../../src/server/utils/routingPolicyLinux";
import {
  applyGuardedRoutingPolicy,
  restorePendingRoutingPolicy,
  type PolicyRecoveryDependencies,
} from "../../src/server/utils/routingPolicyRecovery";
import {
  specializeRoutingPolicy,
  verifyRoutingPolicyPeerMap,
} from "../../src/server/utils/routingPolicyRuntime";
import { buildRoutingPolicyTransition } from "../../src/server/utils/routingPolicyTransition";
import type {
  AppliedRoutingPolicyPlan,
  PolicySnapshot,
  RoutingPolicyJournal,
} from "../../src/shared/types/routingPolicy";

if (
  process.platform !== "linux" ||
  process.getuid?.() !== 0 ||
  process.env.WG_EASY_RUN_PRIVILEGED_TESTS !== "1"
)
  throw new Error("Explicit privileged isolated staging execution is required");
process.umask(0o077);
const LAN = "172.31.210.0/24",
  SINK = "172.31.210.2",
  OTHER_SINK = "172.31.211.2";
const V6MEMBERS = "fd41:1::/64",
  V6LAN = "2001:db8:210::/64",
  V6SINK = "2001:db8:210::2";
const diagnosticOnly =
  process.env.WG_EASY_AWG_PROBE_MATRIX === "credential-only";
type Namespaces = Record<
  "server" | "member" | "other" | "exit" | "sink" | "management",
  string
>;
type Metadata = {
  ns: Namespaces;
  previous: RoutingPolicyJournal;
  target: RoutingPolicyJournal;
  protectedPaths: RoutingGuardScope[];
};
const quiet = (binary: string, args: readonly string[] = [], input?: string) =>
  execFile(binary, args, { input, log: false });
const inside = (
  ns: string,
  binary: string,
  args: readonly string[] = [],
  input?: string,
) => quiet("ip", ["netns", "exec", ns, binary, ...args], input);
const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
class ProbeFailure extends Error {}
function trace(step: string) {
  process.stderr.write(JSON.stringify({ awgWorkerStep: step }) + "\n");
}
async function privateFile(file: string, contents: string) {
  await fs.writeFile(file, contents, { mode: 0o600 });
}
async function syncPrivateConfig(
  ns: string,
  interfaceId: string,
  file: string,
) {
  const config = await fs.readFile(file, "utf8");
  await withSecureInputFile(preparePeerSyncConfig(config), (input) =>
    inside(ns, "awg", ["syncconf", interfaceId, input]),
  );
  verifyPeerSyncPresharedKeys(
    interfaceId,
    config,
    await inside(ns, "awg", ["show", interfaceId, "preshared-keys"]),
  );
}
async function metadata(root: string): Promise<Metadata> {
  assert(
    /^\/tmp\/wg-easy-awg-recovery-[A-Za-z0-9]+$/.test(root),
    "restricted fixture directory",
  );
  assert.equal(
    await fs.readFile(path.join(root, "owner"), "utf8"),
    "wg-easy isolated AWG recovery proof\n",
  );
  const value = JSON.parse(
    await fs.readFile(path.join(root, "probe.json"), "utf8"),
  ) as Metadata;
  for (const name of Object.values(value.ns))
    assert(/^a2[a-z0-9]{1,12}$/.test(name), "owned namespace name");
  return {
    ...value,
    previous: parseRoutingPolicyJournal(value.previous),
    target: parseRoutingPolicyJournal(value.target),
  };
}
async function peerMap(ns: string, plan: AppliedRoutingPolicyPlan) {
  const observed: {
    interfaceId: string;
    publicKey: string;
    allowedIps: string[];
  }[] = [];
  for (const iface of plan.interfaces) {
    const output = await inside(ns, "awg", [
      "show",
      iface.interfaceId,
      "allowed-ips",
    ]);
    for (const line of output.split("\n").filter(Boolean)) {
      const [publicKey, prefixes] = line.split("\t");
      assert(publicKey && prefixes, "complete AWG allowed-ips observation");
      observed.push({
        interfaceId: iface.interfaceId,
        publicKey,
        allowedIps: prefixes!.split(/[ ,]+/).filter(Boolean),
      });
    }
  }
  verifyRoutingPolicyPeerMap(plan, observed);
}
async function tunnelEvidence(ns: string) {
  const counters: {
    interfaceId: string;
    peersWithBidirectionalTraffic: number;
  }[] = [];
  for (const interfaceId of ["wg0", "awg1"]) {
    const rows = (await inside(ns, "awg", ["show", interfaceId, "transfer"]))
      .split("\n")
      .filter(Boolean);
    const active = rows.filter((line) => {
      const fields = line.split("\t");
      return Number(fields[1]) > 0 && Number(fields[2]) > 0;
    }).length;
    console.log(
      JSON.stringify({
        awgCounterEvidence: {
          interfaceId,
          observedPeers: rows.length,
          peersWithBidirectionalTraffic: active,
        },
      }),
    );
    assert.equal(
      active,
      interfaceId === "wg0" ? 2 : 1,
      "each expected real peer has bidirectional counters",
    );
    counters.push({ interfaceId, peersWithBidirectionalTraffic: active });
  }
  for (const [destination, mark, table] of [
    [SINK, "0x54020000", 52002],
    [OTHER_SINK, "0x54010000", 52001],
  ] as const) {
    const routes = JSON.parse(
      await inside(ns, "ip", [
        "-j",
        "-4",
        "route",
        "get",
        destination,
        "from",
        "10.241.1.2",
        "iif",
        "wg0",
        "mark",
        mark,
      ]),
    );
    console.log(
      JSON.stringify({
        awgRouteEvidence: {
          expectedTable: table,
          observedTable: Number(routes[0]?.table) || null,
          expectedDevice: routes[0]?.dev === "awg1",
        },
      }),
    );
    assert(
      routes[0]?.dev === "awg1" && Number(routes[0]?.table) === table,
      "real marked lookup uses the selected AWG table/device",
    );
  }
  const routes6 = JSON.parse(
    await inside(ns, "ip", [
      "-j",
      "-6",
      "route",
      "get",
      V6SINK,
      "from",
      "fd41:1::2",
      "iif",
      "wg0",
    ]),
  );
  assert(
    routes6[0]?.dev === "awg1" && Number(routes6[0]?.table) === 51999,
    "IPv6 legacy route uses its existing site table",
  );
  console.log(
    JSON.stringify({
      ipv6LegacyRouteEvidence: {
        expectedTable: 51999,
        observedTable: Number(routes6[0]?.table),
        expectedDevice: true,
      },
    }),
  );
  return counters;
}
async function context(root: string, action: string, failAt = "") {
  const meta = await metadata(root),
    app = path.join(root, "app");
  const database = createNodeSqliteDatabase(
    path.join(app, "wg-easy.db"),
    schema,
  );
  const run: typeof execFile = async (binary, args = [], options = {}) => {
    const result = await inside(meta.ns.server, binary, args, options.input);
    if (binary.endsWith("tables-restore") && !args.includes("--test")) {
      const family = binary.startsWith("ip6") ? "ipv6" : "ipv4";
      if (options.input?.includes("-F WG_ROUTE_GUARD"))
        crash(
          `${action === "recover" ? "restore_" : ""}guard_${family}_written`,
        );
      if (options.input?.includes("-X WG_ROUTE_GUARD"))
        crash(
          `${action === "recover" ? "restore_" : ""}guard_${family}_removed`,
        );
    }
    return result;
  };
  const journal = new RoutingPolicyRuntimeService(database.db),
    backups = new RoutingPolicyBackups(app);
  const guard = new RoutingGuard(run),
    executor = new RoutingExecutor(run),
    clientFirewall = new RoutingPolicyFirewall(run);
  const executorPrepare = executor.prepare.bind(executor);
  executor.prepare = async (...args) => {
    trace("linux_preflight_begin");
    try {
      await executorPrepare(...args);
    } catch {
      trace("linux_preflight_failed");
      throw new ProbeFailure("preflight");
    }
    trace("linux_preflight_complete");
  };
  function crash(step: string) {
    trace(step);
    if (step === failAt) process.kill(process.pid, "SIGKILL");
  }
  const create = backups.create.bind(backups);
  backups.create = async (...args) => {
    const result = await create(...args);
    crash("backup");
    return result;
  };
  const restore = backups.restore.bind(backups);
  backups.restore = async (...args) => {
    await restore(...args);
    crash("restored_files");
  };
  const prepare = journal.prepare.bind(journal);
  journal.prepare = async (...args) => {
    const result = await prepare(...args);
    crash("prepared");
    return result;
  };
  const advance = journal.advance.bind(journal);
  journal.advance = async (...args) => {
    const result = await advance(...args);
    crash(result.stage);
    return result;
  };
  const mark = journal.markRestoring.bind(journal);
  journal.markRestoring = async (...args) => {
    const result = await mark(...args);
    crash("restoring");
    return result;
  };
  const apply = executor.apply.bind(executor);
  executor.apply = (plan, options = {}) =>
    apply(plan, {
      ...options,
      afterPhase: async (phase) => {
        await options.afterPhase?.(phase);
        crash(`${action === "recover" ? "restore_" : ""}linux_${phase}`);
      },
    });
  const remove = guard.remove.bind(guard);
  guard.remove = async (...args) => {
    await remove(...args);
    crash(action === "recover" ? "restore_guard_removed" : "guard_removed");
  };
  const finish = journal.finishApplied.bind(journal);
  journal.finishApplied = async (...args) => {
    const result = await finish(...args);
    crash("applied_commit");
    return result;
  };
  const finishRestore = journal.finishRestored.bind(journal);
  journal.finishRestored = async (...args) => {
    const result = await finishRestore(...args);
    crash("restored_commit");
    return result;
  };
  const syncServer = async () => {
    for (const name of ["wg0", "awg1"]) {
      const baseline = await fs.readFile(
        path.join(root, "original", `${name}.conf`),
      );
      const target = await fs.readFile(
        path.join(root, "target", `${name}.conf`),
      );
      if (baseline.equals(target)) continue;
      await syncPrivateConfig(
        meta.ns.server,
        name,
        path.join(app, `${name}.conf`),
      );
    }
  };
  const deps: PolicyRecoveryDependencies = {
    journal,
    backups,
    executor,
    guard,
    protectedPaths: meta.protectedPaths,
    preflightManagedState: async () => {
      trace("managed_preflight_begin");
      await peerMap(meta.ns.server, meta.previous.plan);
      await completeInterfaces(root, meta);
      await clientFirewall.prepare(
        meta.target.plan.clientFirewall,
        [meta.previous.plan.clientFirewall],
        null,
      );
      trace("managed_preflight_complete");
    },
    applyManagedState: async (plan, activeGuard) => {
      for (const name of ["wg0", "awg1"])
        await fs.copyFile(
          path.join(root, "target", `${name}.conf`),
          path.join(app, `${name}.conf`),
        );
      await syncServer();
      crash("server_peer_sync");
      await syncPrivateConfig(
        meta.ns.member,
        "vpn0",
        path.join(root, "member-new.conf"),
      );
      crash("client_peer_sync");
      await clientFirewall.apply(
        plan.clientFirewall,
        [meta.previous.plan.clientFirewall],
        activeGuard,
      );
      crash("client_firewall");
    },
    restoreManagedState: async (plan, _backup, activeGuard) => {
      await syncServer();
      await syncPrivateConfig(
        meta.ns.member,
        "vpn0",
        path.join(root, "member-old.conf"),
      );
      crash("restored_peers");
      await clientFirewall.apply(
        plan.clientFirewall,
        [meta.target.plan.clientFirewall],
        activeGuard,
      );
      crash("restored_firewall");
    },
    verifyManagedState: async (plan, activeGuard) => {
      await peerMap(meta.ns.server, plan);
      await completeInterfaces(root, meta);
      await clientFirewall.verify(plan.clientFirewall, activeGuard);
    },
    validateConfig: async (_id, file) => {
      const text = await fs.readFile(file, "utf8");
      assert(
        text.startsWith("[Interface]\n") && text.includes("\n[Peer]\n"),
        "retained complete private config",
      );
    },
    publishGroups: async (tx, record, restored) => {
      await tx
        .update(schema.interfaceRuntimeState)
        .set({
          appliedRevision: record.revision,
          desiredRevision: record.revision,
          observedUp: true,
          status: "up",
        })
        .execute();
      crash(restored ? "restore_before_commit" : "before_commit");
    },
  };
  return { meta, database, deps, syncServer, run };
}
async function completeInterfaces(root: string, meta: Metadata) {
  for (const [name, addresses] of [
    ["wg0", "10.241.1.1/24, fd41:1::1/64"],
    ["awg1", "10.241.2.1/24, fd41:2::1/64"],
  ]) {
    const stripped = await fs.readFile(
      path.join(root, "app", `${name}.conf`),
      "utf8",
    );
    const quick = stripped.replace(
      "[Interface]",
      `[Interface]\nAddress = ${addresses}\nMTU = 1420\nTable = off`,
    );
    try {
      verifyManagedInterfaceState(name!, quick, {
        showconf: await inside(meta.ns.server, "awg", ["showconf", name!]),
        addresses: await inside(meta.ns.server, "ip", [
          "-j",
          "address",
          "show",
          "dev",
          name!,
        ]),
      });
    } catch (error) {
      if (error instanceof ManagedInterfaceStateError)
        trace(`interface_${name}_${error.code}`);
      throw error;
    }
  }
}
async function worker(root: string, action: string, failAt: string) {
  const c = await context(root, action, failAt);
  try {
    const result =
      action === "recover"
        ? await restorePendingRoutingPolicy(c.deps)
        : await applyGuardedRoutingPolicy(c.deps, c.meta.target, {
            forcePeerIds: new Set(
              [...c.meta.previous.plan.peers, ...c.meta.target.plan.peers]
                .filter((p) => p.clientId === 1)
                .map((p) => p.peerId),
            ),
          });
    assert.equal(
      result.status,
      action === "recover" ? "restored" : "applied",
      "complete transition result",
    );
  } finally {
    await c.database.close();
  }
}
async function runWorker(root: string, action: string, failAt = "") {
  return new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(
    (resolve, reject) => {
      const child = spawn(
        process.execPath,
        [fileURLToPath(import.meta.url), "worker", root, action, failAt],
        { stdio: ["ignore", "pipe", "pipe"] },
      );
      let size = 0;
      let diagnostic = "";
      for (const stream of [child.stdout, child.stderr])
        stream.on("data", (data: Buffer) => {
          size += data.length;
          diagnostic += data.toString();
        });
      child.once("error", () =>
        reject(new Error("Recovery worker could not start")),
      );
      child.once("close", (code, signal) => {
        if (code && signal !== "SIGKILL")
          reject(
            new ProbeFailure(
              `Recovery worker failed (${action}/${failAt || "normal"}; diagnostic bytes ${size}; steps ${diagnostic
                .split("\n")
                .flatMap((l) => {
                  try {
                    const v = JSON.parse(l);
                    return typeof v.awgWorkerStep === "string" &&
                      /^[a-z0-9_]+$/.test(v.awgWorkerStep)
                      ? [v.awgWorkerStep]
                      : [];
                  } catch {
                    return [];
                  }
                })
                .slice(-8)
                .join(",")})`,
            ),
          );
        else resolve({ code, signal });
      });
    },
  );
}
async function fetchFrom(ns: string, destination = SINK) {
  const address = destination.includes(":") ? `[${destination}]` : destination;
  const code = `const http=require('node:http');const r=http.get('http://${address}:8080/',x=>{let b='';x.on('data',d=>b+=d);x.on('end',()=>console.log(b));});const timer=setTimeout(()=>r.destroy(new Error('timeout')),1200);r.on('close',()=>clearTimeout(timer));r.on('error',()=>process.exit(9));`;
  return JSON.parse(await inside(ns, "node", ["-e", code])) as {
    source: string;
  };
}
async function reachable(ns: string, source: string, destination = SINK) {
  for (let i = 0; i < 20; i++) {
    try {
      if ((await fetchFrom(ns, destination)).source === source) return;
    } catch {
      /* Await real handshake/ARP readiness. */
    }
    await delay(100);
  }
  throw new ProbeFailure(
    `Actual tunnel/source observation did not converge (${source} to ${destination})`,
  );
}
async function parent() {
  const root = await fs.mkdtemp("/tmp/wg-easy-awg-recovery-");
  await fs.chmod(root, 0o700);
  await privateFile(
    path.join(root, "owner"),
    "wg-easy isolated AWG recovery proof\n",
  );
  const suffix = process.pid.toString(36),
    roles = [
      "server",
      "member",
      "other",
      "exit",
      "sink",
      "management",
    ] as const;
  const ns = Object.fromEntries(
    roles.map((role, i) => [role, `a2${i}${suffix}`]),
  ) as Namespaces;
  const created: string[] = [],
    children: ChildProcess[] = [];
  let stage = "setup";
  const checkpoint = (value: string) => {
    stage = value;
    console.log(JSON.stringify({ awgRecoveryStage: value }));
  };
  async function memberTraffic() {
    await reachable(ns.member, "10.241.1.2");
    await reachable(ns.member, "fd41:1::2", V6SINK);
  }
  async function survivorTraffic() {
    await reachable(ns.other, "10.241.1.3");
    await reachable(ns.other, "fd41:1::3", V6SINK);
    await inside(ns.management, "ping", ["-c", "1", "-W", "1", "192.0.2.13"]);
    await inside(ns.management, "ping", [
      "-6",
      "-c",
      "1",
      "-W",
      "1",
      "fd41:ff::1",
    ]);
  }
  try {
    const existing = (await quiet("ip", ["netns", "list"]))
      .split("\n")
      .map((l) => l.split(" ")[0]);
    assert(
      Object.values(ns).every((n) => !existing.includes(n)),
      "namespace collision",
    );
    for (const name of Object.values(ns)) {
      await quiet("ip", ["netns", "add", name]);
      created.push(name);
      await inside(name, "ip", ["link", "set", "lo", "up"]);
      await inside(name, "sysctl", [
        "-q",
        "-w",
        "net.ipv6.conf.all.disable_ipv6=0",
        "net.ipv6.conf.default.disable_ipv6=0",
      ]);
    }
    let sequence = 0;
    async function connect(
      a: string,
      ad: string,
      aa: string,
      b: string,
      bd: string,
      ba: string,
    ) {
      const left = `a2${suffix}${++sequence}a`,
        right = `a2${suffix}${sequence}b`;
      await quiet("ip", [
        "link",
        "add",
        left,
        "type",
        "veth",
        "peer",
        "name",
        right,
      ]);
      await quiet("ip", ["link", "set", left, "netns", a]);
      await quiet("ip", ["link", "set", right, "netns", b]);
      for (const [space, from, to, address] of [
        [a, left, ad, aa],
        [b, right, bd, ba],
      ]) {
        await inside(space!, "ip", ["link", "set", from!, "name", to!]);
        await inside(space!, "ip", ["addr", "add", address!, "dev", to!]);
        await inside(space!, "ip", ["link", "set", to!, "up"]);
      }
    }
    await connect(
      ns.server,
      "u0",
      "192.0.2.1/30",
      ns.member,
      "u0",
      "192.0.2.2/30",
    );
    await connect(
      ns.server,
      "u1",
      "192.0.2.5/30",
      ns.exit,
      "u0",
      "192.0.2.6/30",
    );
    await connect(
      ns.server,
      "u2",
      "192.0.2.9/30",
      ns.other,
      "u0",
      "192.0.2.10/30",
    );
    await connect(
      ns.server,
      "eth0",
      "192.0.2.13/30",
      ns.management,
      "eth0",
      "192.0.2.14/30",
    );
    await connect(
      ns.exit,
      "lan0",
      "172.31.210.1/24",
      ns.sink,
      "eth0",
      "172.31.210.2/24",
    );
    await inside(ns.exit, "ip", [
      "addr",
      "add",
      "172.31.211.1/24",
      "dev",
      "lan0",
    ]);
    await inside(ns.sink, "ip", [
      "addr",
      "add",
      "172.31.211.2/24",
      "dev",
      "eth0",
    ]);
    for (const space of [ns.server, ns.exit])
      await inside(space, "sysctl", [
        "-q",
        "-w",
        "net.ipv4.ip_forward=1",
        "net.ipv6.conf.all.forwarding=1",
      ]);
    for (const space of Object.values(ns))
      for (const dev of ["all", "default"])
        await inside(space, "sysctl", [
          "-q",
          "-w",
          `net.ipv4.conf.${dev}.rp_filter=0`,
        ]);
    for (const [space, name, address] of [
      [ns.server, "wg0", "10.241.1.1/24"],
      [ns.server, "awg1", "10.241.2.1/24"],
      [ns.member, "vpn0", "10.241.1.2/24"],
      [ns.other, "vpn0", "10.241.1.3/24"],
      [ns.exit, "vpn0", "10.241.2.2/24"],
    ]) {
      await inside(space!, "ip", ["link", "add", name!, "type", "amneziawg"]);
      await inside(space!, "ip", ["addr", "add", address!, "dev", name!]);
      await inside(space!, "ip", ["link", "set", name!, "mtu", "1420", "up"]);
    }
    for (const [space, name, address] of [
      [ns.server, "wg0", "fd41:1::1/64"],
      [ns.server, "awg1", "fd41:2::1/64"],
      [ns.member, "vpn0", "fd41:1::2/64"],
      [ns.other, "vpn0", "fd41:1::3/64"],
      [ns.exit, "vpn0", "fd41:2::2/64"],
      [ns.exit, "lan0", "2001:db8:210::1/64"],
      [ns.sink, "eth0", `${V6SINK}/64`],
      [ns.server, "eth0", "fd41:ff::1/64"],
      [ns.management, "eth0", "fd41:ff::2/64"],
    ])
      await inside(space!, "ip", [
        "-6",
        "addr",
        "add",
        address!,
        "dev",
        name!,
        "nodad",
      ]);
    for (const space of [ns.member, ns.other])
      await inside(space, "ip", ["-6", "route", "add", V6LAN, "dev", "vpn0"]);
    await inside(ns.exit, "ip", [
      "-6",
      "route",
      "add",
      V6MEMBERS,
      "dev",
      "vpn0",
    ]);
    await inside(ns.sink, "ip", [
      "-6",
      "route",
      "add",
      V6MEMBERS,
      "via",
      "2001:db8:210::1",
    ]);
    for (const space of [ns.member, ns.other])
      for (const prefix of [LAN, "172.31.211.0/24"])
        await inside(space, "ip", ["route", "add", prefix, "dev", "vpn0"]);
    await inside(ns.exit, "ip", [
      "route",
      "add",
      "10.241.1.0/24",
      "dev",
      "vpn0",
    ]);
    await inside(ns.sink, "ip", [
      "route",
      "add",
      "10.241.0.0/16",
      "via",
      "172.31.210.1",
    ]);
    await inside(ns.server, "ip", [
      "route",
      "add",
      LAN,
      "via",
      "192.0.2.6",
      "dev",
      "u1",
    ]);
    const app = path.join(root, "app"),
      targetDir = path.join(root, "target"),
      originalDir = path.join(root, "original");
    for (const dir of [app, targetDir, originalDir])
      await fs.mkdir(dir, { mode: 0o700 });
    const keys: Record<string, { privateKey: string; publicKey: string }> = {};
    for (const role of [
      "server0",
      "server1",
      "memberOld",
      "memberNew",
      "other",
      "exit",
    ]) {
      const privateKey = await quiet("awg", ["genkey"]);
      keys[role] = {
        privateKey,
        publicKey: await quiet("awg", ["pubkey"], privateKey + "\n"),
      };
    }
    const pskOld = await quiet("awg", ["genpsk"]),
      pskNew = await quiet("awg", ["genpsk"]);
    const awg =
      "Jc = 3\nJmin = 20\nJmax = 40\nS1 = 64\nS2 = 32\nH1 = 11111111\nH2 = 22222222\nH3 = 33333333\nH4 = 44444444\n";
    const snapshot = (replacement: boolean): PolicySnapshot => ({
      interfaces: [
        { interfaceId: "wg0", ipv4Cidr: "10.241.1.0/24" },
        { interfaceId: "awg1", ipv4Cidr: "10.241.2.0/24" },
      ],
      clients: [
        {
          id: 1,
          interfaceId: "wg0",
          name: "member",
          ipv4Address: "10.241.1.2",
          ipv6Address: "fd41:1::2",
          publicKey: keys[replacement ? "memberNew" : "memberOld"]!.publicKey,
        },
        {
          id: 4,
          interfaceId: "wg0",
          name: "other",
          ipv4Address: "10.241.1.3",
          ipv6Address: "fd41:1::3",
          publicKey: keys.other!.publicKey,
        },
        {
          id: 2,
          interfaceId: "awg1",
          name: "exit",
          ipv4Address: "10.241.2.2",
          ipv6Address: "fd41:2::2",
          publicKey: keys.exit!.publicKey,
        },
      ].map((c) => ({
        ...c,
        enabled: true,
        serverAllowedIps: c.id === 2 ? [V6LAN] : [],
      })),
      groups: [
        {
          id: 1,
          routingSlot: 1,
          name: "Default",
          enabled: true,
          natEnabled: true,
          allExitsDownPolicy: "block",
          routedIpv4Prefixes: ["0.0.0.0/0"],
          memberClientIds: [1, 4],
          exits: [{ clientId: 2, priority: 0, enabled: true }],
        },
        {
          id: 2,
          routingSlot: 2,
          name: "LAN",
          enabled: true,
          natEnabled: false,
          allExitsDownPolicy: "block",
          routedIpv4Prefixes: [LAN],
          memberClientIds: [1, 4],
          exits: [{ clientId: 2, priority: 0, enabled: true }],
        },
      ],
    });
    const make = (
      replacement: boolean,
      revision: number,
    ): RoutingPolicyJournal => {
      const value = specializeRoutingPolicy(snapshot(replacement), {
        selectedExitClientIds: new Map([
          [1, 2],
          [2, 2],
        ]),
        enabledInterfaceIds: new Set(["wg0", "awg1"]),
        upInterfaceIds: new Set(["wg0", "awg1"]),
        enableIpv6: true,
        clientFirewall: {
          enableIpv6: true,
          interfaces: [{ interfaceId: "wg0", ipv6: true }],
          entries: [1, 4].flatMap((id) => [
            ...(id === 1 && replacement
              ? [LAN, "172.31.211.0/24"]
              : ["0.0.0.0/0"]
            ).map((destination) => ({
              interfaceId: "wg0",
              clientId: id,
              clientName: `client ${id}: fixture`,
              family: 4,
              source: id === 1 ? "10.241.1.2" : "10.241.1.3",
              destination,
            })),
            {
              interfaceId: "wg0",
              clientId: id,
              clientName: `client ${id}: fixture`,
              family: 6,
              source: id === 1 ? "fd41:1::2" : "fd41:1::3",
              destination: id === 1 && replacement ? V6LAN : "::/0",
            },
          ]),
        },
      });
      return { revision, fingerprint: value.fingerprint, plan: value.plan };
    };
    checkpoint("setup-policy");
    const previous = make(false, 1),
      target = make(true, 2);
    function serverConfig(
      record: RoutingPolicyJournal,
      name: string,
      replacement: boolean,
    ) {
      const serverKey = keys[name === "wg0" ? "server0" : "server1"]!;
      return (
        `[Interface]\nPrivateKey = ${serverKey.privateKey}\nListenPort = ${name === "wg0" ? 62001 : 62002}\n${name === "awg1" ? awg : ""}` +
        record.plan.peers
          .filter((p) => p.interfaceId === name)
          .map((p) => {
            const role =
              p.clientId === 1
                ? replacement
                  ? "memberNew"
                  : "memberOld"
                : p.clientId === 4
                  ? "other"
                  : "exit";
            return `\n[Peer]\nPublicKey = ${keys[role]!.publicKey}\n${p.clientId === 1 ? `PresharedKey = ${replacement ? pskNew : pskOld}\n` : ""}AllowedIPs = ${p.prefixes.join(", ")}\n`;
          })
          .join("")
      );
    }
    for (const name of ["wg0", "awg1"]) {
      await privateFile(
        path.join(originalDir, `${name}.conf`),
        serverConfig(previous, name, false),
      );
      await privateFile(
        path.join(app, `${name}.conf`),
        serverConfig(previous, name, false),
      );
      await privateFile(
        path.join(targetDir, `${name}.conf`),
        serverConfig(target, name, true),
      );
    }
    function clientConfig(
      role: string,
      serverRole: string,
      endpoint: string,
      allowed: string,
      psk?: string,
    ) {
      return `[Interface]\nPrivateKey = ${keys[role]!.privateKey}\n${serverRole === "server1" ? awg : ""}\n[Peer]\nPublicKey = ${keys[serverRole]!.publicKey}\n${psk ? `PresharedKey = ${psk}\n` : ""}Endpoint = ${endpoint}\nAllowedIPs = ${allowed}\nPersistentKeepalive = 1\n`;
    }
    await privateFile(
      path.join(root, "member-old.conf"),
      clientConfig(
        "memberOld",
        "server0",
        "192.0.2.1:62001",
        `${LAN},172.31.211.0/24,10.241.1.1/32,${V6LAN},fd41:1::1/128`,
        pskOld,
      ),
    );
    await privateFile(
      path.join(root, "member-new.conf"),
      clientConfig(
        "memberNew",
        "server0",
        "192.0.2.1:62001",
        `${LAN},172.31.211.0/24,10.241.1.1/32,${V6LAN},fd41:1::1/128`,
        pskNew,
      ),
    );
    await privateFile(
      path.join(root, "other.conf"),
      clientConfig(
        "other",
        "server0",
        "192.0.2.9:62001",
        `${LAN},172.31.211.0/24,10.241.1.1/32,${V6LAN},fd41:1::1/128`,
      ),
    );
    await privateFile(
      path.join(root, "exit.conf"),
      clientConfig(
        "exit",
        "server1",
        "192.0.2.5:62002",
        "10.241.1.0/24,10.241.2.1/32,fd41:1::/64,fd41:2::1/128",
      ),
    );
    const protectedPaths: RoutingGuardScope[] = [
      {
        direction: "input",
        inputInterface: "eth0",
        source: "fd41:ff::2/128",
        destination: "fd41:ff::1/128",
      },
      {
        direction: "output",
        outputInterface: "eth0",
        source: "fd41:ff::1/128",
        destination: "fd41:ff::2/128",
      },
      {
        direction: "input",
        inputInterface: "eth0",
        source: "192.0.2.14/32",
        destination: "192.0.2.13/32",
      },
      {
        direction: "output",
        outputInterface: "eth0",
        source: "192.0.2.13/32",
        destination: "192.0.2.14/32",
      },
    ];
    await privateFile(
      path.join(root, "probe.json"),
      JSON.stringify({ ns, previous, target, protectedPaths }),
    );
    const database = createNodeSqliteDatabase(
      path.join(app, "wg-easy.db"),
      schema,
    );
    await database.migrate({
      migrationsFolder:
        process.env.WG_EASY_PROBE_MIGRATIONS ??
        "/app/server/database/migrations",
    });
    const defaultInterface = await database.db.query.wgInterface.findFirst();
    assert(defaultInterface, "synthetic default interface");
    await database.db
      .insert(schema.wgInterface)
      .values({
        ...defaultInterface,
        name: "awg1",
        port: 62002,
        ipv4Cidr: "10.241.2.0/24",
        ipv6Cidr: null,
        privateKey: keys.server1!.privateKey,
        publicKey: keys.server1!.publicKey,
      })
      .execute();
    await database.db
      .insert(schema.interfaceRuntimeState)
      .values({
        interfaceId: "awg1",
      })
      .execute();
    await database.db
      .update(schema.general)
      .set({ routingPolicyVersion: 2 })
      .execute();
    await database.db
      .update(schema.runtimeReconciliationState)
      .set({ desiredRevision: 2, appliedRevision: 1, status: "pending" })
      .execute();
    await database.close();
    for (const [space, file] of [
      [ns.member, "member-old.conf"],
      [ns.other, "other.conf"],
      [ns.exit, "exit.conf"],
    ])
      await inside(space!, "awg", ["setconf", "vpn0", path.join(root, file!)]);
    const server = (
      binary: string,
      args: readonly string[] = [],
      options: { input?: string } = {},
    ) => inside(ns.server, binary, args, options.input);
    for (const name of ["wg0", "awg1"])
      await server("awg", ["setconf", name, path.join(app, `${name}.conf`)]);
    const initialGuard = buildRoutingPolicyTransition(null, previous.plan, {
        protectedPaths,
      }),
      guard = new RoutingGuard(server),
      executor = new RoutingExecutor(server);
    checkpoint("setup-guard");
    await guard.install(initialGuard);
    await executor.apply(renderRoutingPolicyLinux(previous.plan), {
      guardedTransition: { guard: initialGuard, knownPlans: [] },
    });
    checkpoint("setup-linux");
    await new RoutingPolicyFirewall(server).apply(
      previous.plan.clientFirewall,
      [],
      initialGuard,
      { allowAbsent: true },
    );
    await peerMap(ns.server, previous.plan);
    await completeInterfaces(root, { ns, previous, target, protectedPaths });
    await guard.remove(initialGuard);
    await executor.verify(renderRoutingPolicyLinux(previous.plan), null);
    checkpoint("setup-firewall");
    const sink = spawn(
      "ip",
      [
        "netns",
        "exec",
        ns.sink,
        "node",
        "-e",
        `require('node:http').createServer((q,s)=>s.end(JSON.stringify({source:q.socket.remoteAddress.replace('::ffff:','')}))).listen(8080,'::')`,
      ],
      { stdio: "ignore" },
    );
    children.push(sink);
    checkpoint("setup-traffic");
    await memberTraffic();
    await survivorTraffic();
    await reachable(ns.member, "10.241.2.1", OTHER_SINK);
    checkpoint("baseline-route-counter-evidence");
    await tunnelEvidence(ns.server);
    const seed = await context(root, "setup");
    await seed.database.db
      .update(schema.routingPolicyRuntime)
      .set({ applied: previous })
      .execute();
    await seed.database.close();
    checkpoint("baseline-real-kernel-awg");
    checkpoint("kill-private-backup-before-journal");
    assert.equal((await runWorker(root, "apply", "backup")).signal, "SIGKILL");
    const orphan = await context(root, "inspect");
    assert.equal((await orphan.deps.journal.get()).pending, null);
    await orphan.deps.guard.verify(null);
    await peerMap(ns.server, previous.plan);
    assert.equal(
      await orphan.deps.backups.cleanupOrphans(new Set()),
      1,
      "exact valid private orphan cleanup",
    );
    await orphan.database.close();
    const failures = diagnosticOnly
      ? []
      : [
          "prepared",
          "guard_ipv4_written",
          "guarded",
          "server_peer_sync",
          "client_peer_sync",
          "client_firewall",
          "peers",
          "linux_preflight",
          "linux_routes",
          "linux_rules",
          "linux_transition_nat",
          "linux_mark_activation",
          "linux_final_nat",
          "linux_cleanup",
          "linux_verify",
          "classified",
          "verified",
          "guard_ipv4_removed",
          "guard_removed",
          "before_commit",
        ];
    for (const failure of failures) {
      checkpoint(`kill-${failure}`);
      const killed = await runWorker(root, "apply", failure);
      assert.equal(killed.signal, "SIGKILL", "injected real process death");
      checkpoint(`kill-${failure}-persisted`);
      const c = await context(root, "inspect");
      const pending = (await c.deps.journal.get()).pending;
      assert(pending, "durable interrupted transition");
      assert.equal(
        (await c.deps.journal.get()).runtime.appliedRevision,
        1,
        "target never prematurely Applied",
      );
      const persistedGuard = buildRoutingGuard(pending.guardScopes, {
        protectedPaths,
      });
      if (failure === "guard_ipv4_written") {
        assertRoutingGuardState(
          await c.deps.guard.observe(4),
          persistedGuard,
          4,
        );
        assertRoutingGuardState(await c.deps.guard.observe(6), null, 6);
        await assert.rejects(fetchFrom(ns.member));
        await reachable(ns.member, "fd41:1::2", V6SINK);
      } else if (failure === "guard_ipv4_removed") {
        assertRoutingGuardState(await c.deps.guard.observe(4), null, 4);
        assertRoutingGuardState(
          await c.deps.guard.observe(6),
          persistedGuard,
          6,
        );
        await assert.rejects(fetchFrom(ns.member, V6SINK));
      } else if (
        !["prepared", "guard_removed", "before_commit"].includes(failure)
      ) {
        await c.deps.guard.verify(
          buildRoutingGuard(pending.guardScopes, { protectedPaths }),
        );
        await assert.rejects(fetchFrom(ns.member));
        await assert.rejects(fetchFrom(ns.member, V6SINK));
      }
      await c.database.close();
      await survivorTraffic();
      checkpoint(`kill-${failure}-survivor`);
      assert.equal(
        (await runWorker(root, "recover")).code,
        0,
        "independent recovery process",
      );
      checkpoint(`kill-${failure}-recover-exited`);
      const recovered = await context(root, "inspect");
      const state = await recovered.deps.journal.get();
      assert.equal(state.pending, null);
      assert.equal(state.applied?.revision, 1);
      checkpoint(`kill-${failure}-restored-record`);
      await peerMap(ns.server, previous.plan);
      await recovered.deps.guard.verify(null, { families: [4, 6] });
      await recovered.database.close();
      checkpoint(`kill-${failure}-restored-map`);
      await memberTraffic();
      await survivorTraffic();
    }
    const recoveryFailures = diagnosticOnly
      ? []
      : [
          "restoring",
          "restore_guard_ipv4_written",
          "restore_guard_ipv6_written",
          "restored_files",
          "restored_peers",
          "restored_firewall",
          ...[
            "preflight",
            "routes",
            "rules",
            "transition_nat",
            "mark_activation",
            "final_nat",
            "cleanup",
            "verify",
          ].map((p) => `restore_linux_${p}`),
          "restore_guard_removed",
          "restore_guard_ipv4_removed",
          "restore_before_commit",
          "restored_commit",
        ];
    for (const failure of recoveryFailures) {
      checkpoint(`kill-${failure}`);
      const seedFailure =
        failure === "restore_guard_ipv6_written"
          ? "guard_ipv4_written"
          : failure === "restore_guard_ipv4_written"
            ? "guard_ipv4_removed"
            : "peers";
      assert.equal(
        (await runWorker(root, "apply", seedFailure)).signal,
        "SIGKILL",
      );
      assert.equal(
        (await runWorker(root, "recover", failure)).signal,
        "SIGKILL",
      );
      const c = await context(root, "inspect"),
        state = await c.deps.journal.get();
      assert.equal(state.runtime.appliedRevision, 1);
      if (failure === "restored_commit") {
        assert.equal(state.pending, null);
        await peerMap(ns.server, previous.plan);
        await c.deps.guard.verify(null, { families: [4, 6] });
        assert.equal(await c.deps.backups.cleanupOrphans(new Set()), 1);
      } else {
        assert(state.pending, "unfinished restoration remains durable");
        if (failure === "restore_guard_ipv4_removed") {
          const expected = buildRoutingGuard(state.pending.guardScopes, {
            protectedPaths,
          });
          assertRoutingGuardState(await c.deps.guard.observe(4), null, 4);
          assertRoutingGuardState(await c.deps.guard.observe(6), expected, 6);
          await assert.rejects(fetchFrom(ns.member, V6SINK));
        } else if (
          !["restore_guard_removed", "restore_before_commit"].includes(failure)
        ) {
          await c.deps.guard.verify(
            buildRoutingGuard(state.pending.guardScopes, { protectedPaths }),
          );
          await assert.rejects(fetchFrom(ns.member));
          await assert.rejects(fetchFrom(ns.member, V6SINK));
        }
      }
      await c.database.close();
      await survivorTraffic();
      if (failure !== "restored_commit")
        assert.equal((await runWorker(root, "recover")).code, 0);
      const final = await context(root, "inspect");
      assert.equal((await final.deps.journal.get()).pending, null);
      await peerMap(ns.server, previous.plan);
      await final.deps.guard.verify(null, { families: [4, 6] });
      await final.database.close();
      await memberTraffic();
      await survivorTraffic();
    }
    checkpoint("successful-key-and-psk-replacement-commit-crash");
    assert.equal(
      (await runWorker(root, "apply", "applied_commit")).signal,
      "SIGKILL",
    );
    await memberTraffic();
    await survivorTraffic();
    const counters = await tunnelEvidence(ns.server);
    const applied = await context(root, "inspect");
    assert.equal((await applied.deps.journal.get()).applied?.revision, 2);
    assert.equal((await applied.deps.journal.get()).pending, null);
    await peerMap(ns.server, target.plan);
    assert.equal(await applied.deps.backups.cleanupOrphans(new Set()), 1);
    await applied.database.close();
    checkpoint("same-identity-preshared-key-clear");
    const clearedPlan = structuredClone(target.plan);
    clearedPlan.clientFirewall.entries =
      clearedPlan.clientFirewall.entries.filter(
        (e) =>
          e.clientId !== 1 || e.destination === LAN || e.destination === V6LAN,
      );
    const cleared = {
      ...target,
      revision: 3,
      plan: clearedPlan,
      fingerprint: specializeRoutingPolicy(snapshot(true), {
        selectedExitClientIds: new Map([
          [1, 2],
          [2, 2],
        ]),
        enabledInterfaceIds: new Set(["wg0", "awg1"]),
        upInterfaceIds: new Set(["wg0", "awg1"]),
        enableIpv6: true,
        clientFirewall: clearedPlan.clientFirewall,
      }).fingerprint,
    };
    for (const name of ["wg0", "awg1"])
      await fs.copyFile(
        path.join(app, `${name}.conf`),
        path.join(originalDir, `${name}.conf`),
      );
    const withoutPsk = (text: string) =>
      text.replace(/^PresharedKey = .+\n/gm, "");
    await privateFile(
      path.join(targetDir, "wg0.conf"),
      withoutPsk(await fs.readFile(path.join(targetDir, "wg0.conf"), "utf8")),
    );
    await fs.copyFile(
      path.join(root, "member-new.conf"),
      path.join(root, "member-old.conf"),
    );
    await privateFile(
      path.join(root, "member-new.conf"),
      withoutPsk(await fs.readFile(path.join(root, "member-new.conf"), "utf8")),
    );
    await privateFile(
      path.join(root, "probe.json"),
      JSON.stringify({ ns, previous: target, target: cleared, protectedPaths }),
    );
    const next = await context(root, "setup");
    await next.database.db
      .update(schema.runtimeReconciliationState)
      .set({ desiredRevision: 3, status: "pending" })
      .execute();
    await next.database.close();
    assert.equal((await runWorker(root, "apply")).code, 0);
    checkpoint("preshared-key-clear-worker-complete");
    await memberTraffic();
    await survivorTraffic();
    checkpoint("preshared-key-clear-traffic-complete");
    await assert.rejects(fetchFrom(ns.member, OTHER_SINK));
    await reachable(ns.other, "10.241.2.1", OTHER_SINK);
    const serverPsk = (await server("awg", ["show", "wg0", "preshared-keys"]))
      .split("\n")
      .find((l) => l.split("\t")[0] === keys.memberNew!.publicKey)
      ?.split("\t")[1];
    const clientPsk = (
      await inside(ns.member, "awg", ["show", "vpn0", "preshared-keys"])
    ).split("\t")[1];
    console.log(
      JSON.stringify({
        presharedKeyEvidence: {
          serverCleared:
            serverPsk === "(none)" ||
            serverPsk === "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
          clientCleared:
            clientPsk === "(none)" ||
            clientPsk === "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
          serverFormat:
            serverPsk === "(none)"
              ? "none"
              : serverPsk?.length === 44
                ? "base64"
                : "other",
          clientFormat:
            clientPsk === "(none)"
              ? "none"
              : clientPsk?.length === 44
                ? "base64"
                : "other",
        },
      }),
    );
    assert(
      [serverPsk, clientPsk].every(
        (value) =>
          value === "(none)" || value === Buffer.alloc(32).toString("base64"),
      ),
      "preshared key truly removed on both actual peers",
    );
    await tunnelEvidence(ns.server);
    console.log(
      JSON.stringify({
        awgRecovery: diagnosticOnly ? "DIAGNOSTIC_PASS" : "PASS",
        completeMatrix: !diagnosticOnly,
        kernelAwg: true,
        ipv6LegacyTraffic: true,
        dualFamilyGuards: true,
        partialFamilyCrashRepair: !diagnosticOnly,
        obfuscatedExit: true,
        sameInterfaceUnrelatedPeer: true,
        realProcessKills: 1 + failures.length + 2 * recoveryFailures.length + 1,
        applyCrashBoundaries: failures.length,
        recoveryCrashBoundaries: recoveryFailures.length,
        completePeerMap: true,
        completeInterfaceConfiguration: true,
        completeClientFirewall: true,
        clientFilterDenial: true,
        privateByteRestore: true,
        newKeyAndPskTraffic: true,
        presharedKeyClear: true,
        managementPreserved: true,
        natSources: ["10.241.1.2", "10.241.1.3", "10.241.2.1"],
        externalTraversal: false,
        counters,
      }),
    );
  } catch (error) {
    throw new Error(
      `Isolated AWG recovery proof failed at ${stage}${error instanceof ProbeFailure ? `: ${error.message}` : ""}`,
    );
  } finally {
    for (const child of children) child.kill("SIGTERM");
    for (const name of [...created].reverse())
      await quiet("ip", ["netns", "delete", name]).catch(() => {});
    // Only this exact private fixture directory, with its owner marker, qualifies.
    if (
      (await fs.readFile(path.join(root, "owner"), "utf8").catch(() => "")) ===
      "wg-easy isolated AWG recovery proof\n"
    )
      await fs.rm(root, { recursive: true });
  }
}
if (process.argv[2] === "worker") {
  try {
    await worker(process.argv[3]!, process.argv[4]!, process.argv[5]!);
  } catch {
    trace("worker_failed");
    throw new Error("Private AWG recovery worker failed");
  }
} else await parent();
