/** Staging-only real AWG lifecycle proof, no application volume/host network. */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { execFile, withSecureInputFile } from "../../src/server/utils/cmd";
import { LinuxManagedInterfaceDevices } from "../../src/server/utils/managedInterfaceDevices";
import { ManagedInterfaceTransition } from "../../src/server/utils/managedInterfaceTransition";
import { ManagedServerHookEffects } from "../../src/server/utils/managedServerHooks";
import { RoutingPolicyBackups } from "../../src/server/utils/routingPolicyBackups";
import {
  RoutingGuard,
  buildRoutingGuard,
} from "../../src/server/utils/routingGuard";
import { specializeRoutingPolicy } from "../../src/server/utils/routingPolicyRuntime";
import { routingPolicyRuntimeFingerprint } from "../../src/server/utils/routingPolicyRuntime";
import { readRoutingKernelNamespace } from "../../src/server/utils/routingPolicyKernelContext";
import { buildRoutingPolicyTransition } from "../../src/server/utils/routingPolicyTransition";
import type {
  RoutingPolicyJournal,
  RoutingPolicyGuardScope,
} from "../../src/shared/types/routingPolicy";

if (
  process.platform !== "linux" ||
  process.getuid?.() !== 0 ||
  process.env.WG_EASY_RUN_PRIVILEGED_TESTS !== "1"
)
  throw new Error("Explicit privileged isolated staging execution required");
process.umask(0o077);
const run = (binary: string, args: readonly string[] = [], input?: string) =>
  execFile(binary, args, { input, log: false });
const inside = (
  ns: string,
  binary: string,
  args: readonly string[] = [],
  input?: string,
) => run("ip", ["netns", "exec", ns, binary, ...args], input);
const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
type Metadata = {
  ns: Record<"server" | "member" | "other" | "management", string>;
  previous: RoutingPolicyJournal;
  target: RoutingPolicyJournal;
  protectedPaths: RoutingPolicyGuardScope[];
  identical: boolean;
  baselineDown?: boolean;
};
async function readMeta(root: string) {
  assert(/^\/tmp\/wge-interface-lifecycle-[A-Za-z0-9]+$/.test(root));
  assert.equal(
    await fs.readFile(path.join(root, "owner"), "utf8"),
    "wg-easy isolated lifecycle proof\n",
  );
  return JSON.parse(
    await fs.readFile(path.join(root, "metadata.json"), "utf8"),
  ) as Metadata;
}
async function worker(root: string, action: string, failAt: string) {
  const meta = await readMeta(root),
    app = path.join(root, "app"),
    backups = new RoutingPolicyBackups(app);
  let hookWrites = 0;
  const crash = (step: string) => {
    if (step === failAt) process.kill(process.pid, "SIGKILL");
  };
  const server: typeof execFile = async (binary, args = [], options = {}) => {
    const result = await inside(meta.ns.server, binary, args, options.input);
    if (
      binary.endsWith("tables-restore") &&
      !args.includes("--test") &&
      /^-F (INPUT|FORWARD|POSTROUTING)$/m.test(options.input ?? "")
    )
      crash(`${action}_hook_${++hookWrites}`);
    return result;
  };
  const devices = new LinuxManagedInterfaceDevices(server),
    hooks = new ManagedServerHookEffects(server),
    guard = new RoutingGuard(server),
    deps = { configDirectory: app, backups, devices, hooks };
  const originalDown = devices.down.bind(devices),
    originalUp = devices.up.bind(devices);
  devices.down = async (...args) => {
    await originalDown(...args);
    crash(`${action}_stopped`);
  };
  devices.up = async (id, config) => {
    if (action === "recover" && meta.baselineDown && id === "wg0")
      throw new Error(
        "withdrawn device must not be restarted during restoration",
      );
    crash(`${action}_file_before_up`);
    if (failAt === `${action}_blank_device`) {
      // Exact known partial quick startup: device exists before setconf.
      if (process.env.AWG_FORCE_USERSPACE === "true")
        await server("env", [
          "WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1",
          "amneziawg-go",
          id,
        ]);
      else await server("ip", ["link", "add", id, "type", "amneziawg"]);
      crash(`${action}_blank_device`);
    }
    await originalUp(id, config);
    crash(`${action}_started`);
  };
  const candidates = new Map(
    await Promise.all(
      ["wg0", "awg1"].map(
        async (id) =>
          [
            id,
            await fs.readFile(path.join(root, "target", `${id}.conf`), "utf8"),
          ] as const,
      ),
    ),
  );
  const closure = buildRoutingPolicyTransition(
    meta.previous.plan,
    meta.target.plan,
    {
      protectedPaths: meta.protectedPaths,
      forcePeerIds: new Set(
        meta.previous.plan.peers
          .filter((p) => p.interfaceId === "wg0")
          .map((p) => p.peerId),
      ),
    },
  );
  const verifyGuard = () => guard.verify(closure);
  if (action === "apply") {
    const transition = await ManagedInterfaceTransition.prepare(
      deps,
      meta.previous.plan,
      meta.target.plan,
      candidates,
      { restartInterfaceIds: meta.identical ? new Set(["wg0"]) : new Set() },
    );
    if (meta.identical)
      for (const id of ["wg0", "awg1"])
        assert(
          transition.previousConfigurations.get(id) ===
            transition.candidateConfigurations.get(id),
          "manual restart retains exactly identical private bytes",
        );
    const reference = await backups.create(["wg0", "awg1"], {
      candidateConfigurations: transition.candidateConfigurations,
      expectedPreviousConfigurations: transition.previousConfigurations,
      lifecycleIntent: transition.intent,
    });
    await fs.writeFile(path.join(root, "pending-reference"), reference, {
      mode: 0o600,
    });
    crash("apply_backup");
    await guard.install(closure);
    crash("apply_guarded");
    await transition.apply(verifyGuard);
    await transition.verify("target");
    await verifyGuard();
    return;
  }
  const reference = await fs.readFile(
      path.join(root, "pending-reference"),
      "utf8",
    ),
    transition = await ManagedInterfaceTransition.reopen(
      deps,
      reference,
      meta.previous.plan,
      meta.target.plan,
    );
  await guard.ensure(closure);
  await transition.beforeRestore(verifyGuard);
  await backups.restore(reference);
  crash("recover_files");
  await transition.restorePrevious(verifyGuard);
  await guard.remove(closure);
  await transition.verify("previous");
  await guard.verify(null, { families: [4, 6] });
  await backups.remove(reference);
  await fs.unlink(path.join(root, "pending-reference"));
}
if (process.argv[2] === "--worker") {
  try {
    await worker(process.argv[3]!, process.argv[4]!, process.argv[5] ?? "");
  } catch (error) {
    const value = error as { code?: unknown; verificationScope?: unknown };
    const safe = (v: unknown) =>
      typeof v === "string" && /^[a-zA-Z_]{1,64}$/.test(v) ? v : undefined;
    process.stderr.write(
      JSON.stringify({
        lifecycleWorkerFailure: true,
        action: process.argv[4],
        code: safe(value.code) ?? "unexpected_failure",
        scope: safe(value.verificationScope),
      }) + "\n",
    );
    process.exitCode = 1;
  }
} else {
  const root = await fs.mkdtemp("/tmp/wge-interface-lifecycle-"),
    suffix = process.pid.toString(36),
    created: string[] = [];
  const ns = Object.fromEntries(
    ["server", "member", "other", "management"].map((role, i) => [
      role,
      `l2${i}${suffix}`,
    ]),
  ) as Metadata["ns"];
  const children: ReturnType<typeof spawn>[] = [];
  let step = "setup";
  const checkpoint = (name: string) => {
    step = name;
    console.log(JSON.stringify({ lifecycleProbeStage: name }));
  };
  async function child(action: string, failAt = "") {
    const processChild = spawn(
      process.execPath,
      [fileURLToPath(import.meta.url), "--worker", root, action, failAt],
      { stdio: ["ignore", "ignore", "pipe"] },
    );
    children.push(processChild);
    let error = "";
    processChild.stderr!.on("data", (data: Buffer) => {
      error += data.toString();
    });
    const result = await new Promise<{
      code: number | null;
      signal: NodeJS.Signals | null;
    }>((resolve, reject) => {
      processChild.once("error", reject);
      processChild.once("exit", (code, signal) => resolve({ code, signal }));
    });
    assert(
      result.code === 0 || result.signal === "SIGKILL",
      `safe worker failure at ${step}: ${error.match(/\{"lifecycleWorkerFailure"[^\n]+/)?.[0] ?? "worker exited"}`,
    );
    return result;
  }
  async function pair(
    a: string,
    aName: string,
    aAddress: string,
    b: string,
    bName: string,
    bAddress: string,
    index: number,
  ) {
    const left = `l2${suffix}${index}a`.slice(0, 15),
      right = `l2${suffix}${index}b`.slice(0, 15);
    await run("ip", [
      "link",
      "add",
      left,
      "type",
      "veth",
      "peer",
      "name",
      right,
    ]);
    await run("ip", ["link", "set", left, "netns", a]);
    await run("ip", ["link", "set", right, "netns", b]);
    for (const [space, from, to, address] of [
      [a, left, aName, aAddress],
      [b, right, bName, bAddress],
    ] as const) {
      await inside(space, "ip", ["link", "set", from, "name", to]);
      await inside(space, "ip", ["address", "add", address, "dev", to]);
      await inside(space, "ip", ["link", "set", to, "up"]);
    }
  }
  const fetchCode = `const http=require('node:http');const timer=setTimeout(()=>process.exit(7),1200);const req=http.get(process.argv[1],res=>{let data='';res.on('data',chunk=>data+=chunk);res.on('end',()=>{clearTimeout(timer);console.log(data);});});req.on('error',()=>process.exit(7));`;
  async function fetchFrom(space: string, ip: string) {
    return JSON.parse(
      await inside(space, "node", [
        "-e",
        fetchCode,
        `http://${ip.includes(":") ? `[${ip}]` : ip}:8080/probe`,
      ]),
    ) as { source: string };
  }
  async function reachable(space: string, ip: string, source: string) {
    for (let i = 0; i < 20; i++) {
      try {
        const result = await fetchFrom(space, ip);
        assert.equal(result.source.replace("::ffff:", ""), source);
        return;
      } catch {
        if (i === 19) throw new Error(`traffic did not recover at ${step}`);
      }
      await pause(100);
    }
  }
  try {
    await fs.chmod(root, 0o700);
    await fs.writeFile(
      path.join(root, "owner"),
      "wg-easy isolated lifecycle proof\n",
      { mode: 0o600 },
    );
    for (const dir of ["app", "original", "target"])
      await fs.mkdir(path.join(root, dir), { mode: 0o700 });
    const existing = (await run("ip", ["netns", "list"]))
      .split("\n")
      .map((l) => l.split(" ")[0]);
    assert(Object.values(ns).every((name) => !existing.includes(name)));
    for (const name of Object.values(ns)) {
      await run("ip", ["netns", "add", name]);
      created.push(name);
      await inside(name, "ip", ["link", "set", "lo", "up"]);
    }
    await pair(
      ns.server,
      "under0",
      "192.0.2.1/30",
      ns.member,
      "under0",
      "192.0.2.2/30",
      1,
    );
    await pair(
      ns.server,
      "under1",
      "192.0.2.5/30",
      ns.other,
      "under0",
      "192.0.2.6/30",
      2,
    );
    await pair(
      ns.server,
      "mgmt0",
      "192.0.2.17/30",
      ns.management,
      "eth0",
      "192.0.2.18/30",
      3,
    );
    await inside(ns.server, "ip", [
      "route",
      "add",
      "default",
      "via",
      "192.0.2.18",
      "dev",
      "mgmt0",
    ]);
    const keys = new Map<string, { privateKey: string; publicKey: string }>();
    for (const name of ["server0", "server1", "member", "other"]) {
      const privateKey = await run("awg", ["genkey"]),
        publicKey = await execFile("awg", ["pubkey"], {
          input: privateKey,
          log: false,
        });
      keys.set(name, { privateKey, publicKey });
    }
    const awg =
        "Jc = 3\nJmin = 20\nJmax = 40\nS1 = 64\nS2 = 32\nH1 = 11111111\nH2 = 22222222\nH3 = 33333333\nH4 = 44444444\n",
      identical = process.env.WG_EASY_LIFECYCLE_IDENTICAL === "1";
    const baselineDown = process.env.WG_EASY_LIFECYCLE_BASELINE_DOWN === "1",
      namespaceId = await readRoutingKernelNamespace(
        (binary, args = [], options = {}) =>
          inside(ns.server, binary, args, options.input),
      );
    function serverConfig(id: string, target = false) {
      const index = id === "wg0" ? 1 : 2,
        port = index === 1 ? (target && !identical ? 62003 : 62001) : 62002;
      const up = `OUT_IF=$(ip -4 route show default | awk "NR == 1 {print \\$5}"); test -n "$OUT_IF" || exit 1; iptables -t nat -A POSTROUTING -s 10.243.${index}.0/24 -o "$OUT_IF" -j MASQUERADE; iptables -A INPUT -p udp -m udp --dport ${port} -j ACCEPT; iptables -A FORWARD -i ${id} -j ACCEPT; iptables -A FORWARD -o ${id} -j ACCEPT; ip6tables -t nat -A POSTROUTING -s fd43:${index}::/64 -o "$OUT_IF" -j MASQUERADE; ip6tables -A INPUT -p udp -m udp --dport ${port} -j ACCEPT; ip6tables -A FORWARD -i ${id} -j ACCEPT; ip6tables -A FORWARD -o ${id} -j ACCEPT;`;
      return `[Interface]\nPrivateKey = ${keys.get(index === 1 ? "server0" : "server1")!.privateKey}\nListenPort = ${port}\nAddress = 10.243.${index}.1/24, fd43:${index}::1/64\nMTU = 1420\nTable = off\n${index === 2 ? awg : ""}PreUp = : phase0-baseline\nPostUp = ${up}\nPreDown = \nPostDown = ${up.replaceAll(" -A ", " -D ")}\n[Peer]\nPublicKey = ${keys.get(index === 1 ? "member" : "other")!.publicKey}\nAllowedIPs = 10.243.${index}.2/32, fd43:${index}::2/128\n${identical ? "# wg-easy managed hook egress: mgmt0\n" : ""}`;
    }
    for (const id of ["wg0", "awg1"])
      for (const dir of ["app", "original", "target"])
        await fs.writeFile(
          path.join(root, dir, `${id}.conf`),
          serverConfig(id, dir === "target"),
          { mode: 0o600 },
        );
    const snapshot = {
      interfaces: [
        { interfaceId: "wg0", ipv4Cidr: "10.243.1.0/24" },
        { interfaceId: "awg1", ipv4Cidr: "10.243.2.0/24" },
      ],
      clients: [
        {
          id: 1,
          interfaceId: "wg0",
          ipv4Address: "10.243.1.2",
          ipv6Address: "fd43:1::2",
          publicKey: keys.get("member")!.publicKey,
        },
        {
          id: 2,
          interfaceId: "awg1",
          ipv4Address: "10.243.2.2",
          ipv6Address: "fd43:2::2",
          publicKey: keys.get("other")!.publicKey,
        },
      ].map((c) => ({
        ...c,
        name: `profile ${c.id}`,
        enabled: true,
        serverAllowedIps: [],
      })),
      groups: [],
    };
    const specialized = specializeRoutingPolicy(snapshot, {
        selectedExitClientIds: new Map(),
        enabledInterfaceIds: new Set(["wg0", "awg1"]),
        upInterfaceIds: new Set(["wg0", "awg1"]),
        enableIpv6: true,
        clientFirewall: { enableIpv6: true, interfaces: [], entries: [] },
        namespaceId,
      }),
      previous = {
        revision: 1,
        fingerprint: specialized.fingerprint,
        plan: specialized.plan,
      },
      target = { ...previous, revision: 2 },
      protectedPaths: RoutingPolicyGuardScope[] = [
        {
          direction: "input",
          inputInterface: "mgmt0",
          source: "192.0.2.18/32",
          destination: "192.0.2.17/32",
        },
        {
          direction: "output",
          outputInterface: "mgmt0",
          source: "192.0.2.17/32",
          destination: "192.0.2.18/32",
        },
      ];
    if (baselineDown) {
      previous.plan = structuredClone(specialized.plan);
      previous.plan.interfaces.find(
        (i) => i.interfaceId === "wg0",
      )!.observedUp = false;
      previous.plan.peers = previous.plan.peers.filter(
        (p) => p.interfaceId !== "wg0",
      );
      previous.fingerprint = routingPolicyRuntimeFingerprint(previous.plan);
    }
    await fs.writeFile(
      path.join(root, "metadata.json"),
      JSON.stringify({
        ns,
        previous,
        target,
        protectedPaths,
        identical,
        baselineDown,
      }),
      { mode: 0o600 },
    );
    const server: typeof execFile = (binary, args = [], options = {}) =>
        inside(ns.server, binary, args, options.input),
      devices = new LinuxManagedInterfaceDevices(server),
      effects = new ManagedServerHookEffects(server);
    for (const id of ["wg0", "awg1"])
      await devices.up(
        id,
        await fs.readFile(path.join(root, "app", `${id}.conf`), "utf8"),
      );
    // Seed the verified old hook effects via the admitted typed implementation.
    const { admitManagedServerHooks, resolveManagedServerHooks } =
      await import("../../src/server/utils/managedServerHooks");
    const { parseManagedInterfaceConfig } =
      await import("../../src/server/utils/managedInterfaceState");
    const oldRules = [];
    for (const id of ["wg0", "awg1"])
      oldRules.push(
        ...resolveManagedServerHooks(
          admitManagedServerHooks(
            id,
            parseManagedInterfaceConfig(
              id,
              await fs.readFile(path.join(root, "app", `${id}.conf`), "utf8"),
            ).fields,
          ),
          "mgmt0",
        ),
      );
    const startupGuard = buildRoutingGuard(
        [
          {
            direction: "input",
            inputInterface: "wg0",
            source: "10.243.1.2/32",
            destination: "0.0.0.0/0",
          },
        ],
        { protectedPaths },
      ),
      startup = new RoutingGuard(server);
    await startup.install(startupGuard);
    await effects.reconcile(await effects.capture([], oldRules), "target", () =>
      startup.verify(startupGuard),
    );
    await startup.remove(startupGuard);
    for (const [space, name, index, role] of [
      [ns.member, "vpn0", 1, "member"],
      [ns.other, "vpn1", 2, "other"],
    ] as const) {
      await inside(space, "ip", ["link", "add", name, "type", "amneziawg"]);
      const config = `[Interface]\nPrivateKey = ${keys.get(role)!.privateKey}\n${index === 2 ? awg : ""}[Peer]\nPublicKey = ${keys.get(index === 1 ? "server0" : "server1")!.publicKey}\nEndpoint = ${index === 1 ? "192.0.2.1:62001" : "192.0.2.5:62002"}\nAllowedIPs = 10.243.${index}.1/32, fd43:${index}::1/128\nPersistentKeepalive = 1\n`;
      await withSecureInputFile(config, (file) =>
        inside(space, "awg", ["setconf", name, file]),
      );
      for (const address of [`10.243.${index}.2/24`, `fd43:${index}::2/64`])
        await inside(space, "ip", ["address", "add", address, "dev", name]);
      await inside(space, "ip", ["link", "set", name, "mtu", "1420", "up"]);
    }
    const listener = spawn(
      "ip",
      [
        "netns",
        "exec",
        ns.server,
        "node",
        "-e",
        "require('node:http').createServer((req,res)=>res.end(JSON.stringify({source:req.socket.remoteAddress}))).listen(8080,'::',()=>console.log('ready'))",
      ],
      { stdio: ["ignore", "pipe", "pipe"] },
    );
    children.push(listener);
    await new Promise<void>((resolve, reject) => {
      listener.stdout!.once("data", () => resolve());
      listener.once("error", reject);
    });
    const healthyIfindex = JSON.parse(
      (await devices.observe("awg1"))!.addresses,
    )[0].ifindex;
    const survivors = async () => {
      await reachable(ns.other, "10.243.2.1", "10.243.2.2");
      await reachable(ns.other, "fd43:2::1", "fd43:2::2");
      await reachable(ns.management, "192.0.2.17", "192.0.2.18");
      assert.equal(
        JSON.parse((await devices.observe("awg1"))!.addresses)[0].ifindex,
        healthyIfindex,
      );
    };
    const member = async () => {
      if (baselineDown) {
        await assert.rejects(fetchFrom(ns.member, "10.243.1.1"));
        await assert.rejects(fetchFrom(ns.member, "fd43:1::1"));
        return;
      }
      await reachable(ns.member, "10.243.1.1", "10.243.1.2");
      await reachable(ns.member, "fd43:1::1", "fd43:1::2");
    };
    if (baselineDown) {
      await reachable(ns.member, "10.243.1.1", "10.243.1.2");
      await reachable(ns.member, "fd43:1::1", "fd43:1::2");
      // A vanished device does not execute the admitted PostDown effects.
      await devices.down(
        "wg0",
        await fs.readFile(path.join(root, "app", "wg0.conf"), "utf8"),
      );
    }
    await member();
    await survivors();
    const diagnosticOnly =
      process.env.WG_EASY_LIFECYCLE_MATRIX === "blank-only";
    const applyFailures = diagnosticOnly
      ? ["apply_blank_device"]
      : [
          "apply_backup",
          "apply_guarded",
          ...(!baselineDown ? ["apply_stopped"] : []),
          "apply_file_before_up",
          "apply_blank_device",
          "apply_started",
          "apply_hook_1",
          "apply_hook_9",
        ];
    let kills = 0;
    for (const failure of applyFailures) {
      checkpoint(failure);
      assert.equal((await child("apply", failure)).signal, "SIGKILL");
      kills++;
      await survivors();
      if (failure !== "apply_backup") {
        await assert.rejects(fetchFrom(ns.member, "10.243.1.1"));
        await assert.rejects(fetchFrom(ns.member, "fd43:1::1"));
      }
      if (failure === "apply_hook_9")
        await inside(ns.server, "ip", [
          "route",
          "replace",
          "default",
          "via",
          "192.0.2.2",
          "dev",
          "under0",
        ]);
      assert.equal((await child("recover")).code, 0);
      if (failure === "apply_hook_9")
        await inside(ns.server, "ip", [
          "route",
          "replace",
          "default",
          "via",
          "192.0.2.18",
          "dev",
          "mgmt0",
        ]);
      await member();
      await survivors();
    }
    for (const failure of diagnosticOnly
      ? []
      : [
          "recover_hook_1",
          "recover_files",
          "recover_stopped",
          ...(!baselineDown
            ? ["recover_file_before_up", "recover_started"]
            : []),
        ]) {
      checkpoint(failure);
      assert.equal((await child("apply", "apply_hook_9")).signal, "SIGKILL");
      kills++;
      assert.equal((await child("recover", failure)).signal, "SIGKILL");
      kills++;
      await survivors();
      assert.equal((await child("recover")).code, 0);
      await member();
      await survivors();
    }
    checkpoint("successful-candidate");
    assert.equal((await child("apply")).code, 0);
    await inside(ns.member, "awg", [
      "set",
      "vpn0",
      "peer",
      keys.get("server0")!.publicKey,
      "endpoint",
      `192.0.2.1:${identical ? 62001 : 62003}`,
    ]);
    await survivors();
    await assert.rejects(fetchFrom(ns.member, "10.243.1.1"));
    assert.equal((await child("recover")).code, 0);
    await inside(ns.member, "awg", [
      "set",
      "vpn0",
      "peer",
      keys.get("server0")!.publicKey,
      "endpoint",
      "192.0.2.1:62001",
    ]);
    await member();
    await survivors();
    console.log(
      JSON.stringify({
        interfaceLifecycleProbe: diagnosticOnly ? "DIAGNOSTIC_PASS" : "PASS",
        completeMatrix: !diagnosticOnly,
        implementation:
          process.env.AWG_FORCE_USERSPACE === "true"
            ? "pinned-userspace"
            : "kernel-first",
        identicalBytesManualRestart: identical && !baselineDown,
        restoredDownBaselineWithoutStart: baselineDown,
        sigkillCases: kills,
        oldStopBeforeCandidateFile: true,
        knownBlankDeviceRecovery: true,
        partialHookRecovery: !diagnosticOnly,
        completePrivateGenerationVerification: true,
        guardedIPv4Ipv6: true,
        unrelatedAwgInterfaceNotRecreated: true,
        independentManagement: true,
        componentOnly: true,
        recoveryUsesFrozenEgress: !diagnosticOnly,
      }),
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : "",
      safe = message.match(
        /\{"lifecycleWorkerFailure":true,"action":"(?:apply|recover)","code":"[A-Za-z_]{1,64}"(?:,"scope":"[A-Za-z_]{1,64}")?\}/,
      )?.[0];
    console.error(
      JSON.stringify({
        interfaceLifecycleProbe: "FAIL",
        stage: step,
        ...(safe ? { worker: JSON.parse(safe) } : {}),
      }),
    );
    process.exitCode = 1;
  } finally {
    for (const child of children)
      if (child.exitCode === null) child.kill("SIGTERM");
    if (created.includes(ns.server)) {
      const server: typeof execFile = (binary, args = [], options = {}) =>
          inside(ns.server, binary, args, options.input),
        cleanup = new LinuxManagedInterfaceDevices(server);
      for (const id of ["wg0", "awg1"])
        await cleanup
          .down(
            id,
            await fs.readFile(
              path.join(root, "original", `${id}.conf`),
              "utf8",
            ),
          )
          .catch(() => {});
    }
    for (const name of [...created].reverse())
      await run("ip", ["netns", "delete", name]).catch(() => {});
    await fs.rm(root, { recursive: true, force: true });
  }
}
