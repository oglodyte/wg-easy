/** Isolated Linux guard checkpoint. No application volume or host network. */
import assert from "node:assert/strict";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createInterface } from "node:readline";

import { execFile } from "../../src/server/utils/cmd";
import { firewallTestExports } from "../../src/server/utils/firewall";
import {
  buildRoutingGuard,
  RoutingGuard,
  type RoutingGuardScope,
} from "../../src/server/utils/routingGuard";

if (
  process.platform !== "linux" ||
  process.getuid?.() !== 0 ||
  process.env.WG_EASY_RUN_PRIVILEGED_TESTS !== "1"
)
  throw new Error("Explicit privileged Linux isolation is required");
const suffix = process.pid.toString(36);
const ns = Object.fromEntries(
  ["server", "member", "exit", "sink", "management"].map((role, i) => [
    role,
    `g2${i}${suffix}`,
  ]),
) as Record<"server" | "member" | "exit" | "sink" | "management", string>;
let stage = "setup";
function checkpoint(name: string) {
  stage = name;
  console.log(JSON.stringify({ guardProbeStage: name }));
}
const created: string[] = [];
const children: ChildProcessWithoutNullStreams[] = [];
type Options = { input?: string; log?: boolean | string };
const run = (
  binary: string,
  args: readonly string[] = [],
  options: Options = {},
) => execFile(binary, args, { ...options, log: false });
const inside = (
  namespace: string,
  binary: string,
  args: readonly string[] = [],
  options: Options = {},
) => run("ip", ["netns", "exec", namespace, binary, ...args], options);
const server = (
  binary: string,
  args: readonly string[] = [],
  options: Options = {},
) => inside(ns.server, binary, args, options);
const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
async function until(check: () => boolean, message: string) {
  for (let i = 0; i < 100; i++) {
    if (check()) return;
    await pause(50);
  }
  throw new Error(message);
}
let pair = 0;
async function connect(
  a: string,
  aDevice: string,
  aAddress: string,
  b: string,
  bDevice: string,
  bAddress: string,
) {
  const left = `g2${suffix}${++pair}a`.slice(0, 15),
    right = `g2${suffix}${pair}b`.slice(0, 15);
  await run("ip", ["link", "add", left, "type", "veth", "peer", "name", right]);
  await run("ip", ["link", "set", left, "netns", a]);
  await run("ip", ["link", "set", right, "netns", b]);
  for (const [space, from, to, address] of [
    [a, left, aDevice, aAddress],
    [b, right, bDevice, bAddress],
  ] as const) {
    await inside(space, "ip", ["link", "set", from, "name", to]);
    await inside(space, "ip", ["addr", "add", address, "dev", to]);
    await inside(space, "ip", ["link", "set", to, "up"]);
  }
}
function start(namespace: string, code: string) {
  const child = spawn(
    "ip",
    ["netns", "exec", namespace, "node", "--input-type=commonjs", "-e", code],
    { stdio: ["pipe", "pipe", "pipe"] },
  );
  children.push(child);
  const events: Array<Record<string, unknown>> = [];
  let failure = "";
  child.stderr.on("data", (data: Buffer) => {
    failure += data.toString();
  });
  createInterface({ input: child.stdout }).on("line", (line) =>
    events.push(JSON.parse(line)),
  );
  return {
    child,
    events,
    diagnostics: () => ({ exitCode: child.exitCode, stderr: failure }),
    ready: async () => {
      await until(
        () => events.some((e) => e.ready === true) || child.exitCode !== null,
        "child ready timeout",
      );
      assert.equal(child.exitCode, null, failure);
    },
  };
}
const httpCode = `const http=require('node:http'),net=require('node:net'),dgram=require('node:dgram');let ready=0;const done=()=>{if(++ready===3)console.log(JSON.stringify({ready:true}));};http.createServer((req,res)=>{const result={source:req.socket.remoteAddress,path:req.url};console.log(JSON.stringify(result));res.end(JSON.stringify(result));}).listen(8080,'0.0.0.0',done);net.createServer(socket=>{socket.on('error',error=>{if(!['ECONNRESET','EPIPE'].includes(error.code))throw error;});socket.on('data',data=>socket.write(data));}).listen(8081,'0.0.0.0',done);const udp=dgram.createSocket('udp4');udp.on('message',(data,remote)=>{const result={source:remote.address,udp:true};console.log(JSON.stringify(result));udp.send(JSON.stringify(result),remote.port,remote.address);});udp.bind(8082,'0.0.0.0',done);`;
const streamCode = `const net=require('node:net'),readline=require('node:readline');let received=0,timer;const socket=net.connect(8081,'172.31.200.2',()=>{console.log(JSON.stringify({ready:true}));timer=setInterval(()=>socket.write('guard-probe'),40);});socket.on('data',d=>received+=d.length);socket.on('error',()=>{});readline.createInterface({input:process.stdin}).on('line',line=>{if(line==='close'){clearInterval(timer);socket.resetAndDestroy();setTimeout(()=>process.exit(0),25);}else console.log(JSON.stringify({received}));});`;
const fetchCode = `fetch('http://172.31.200.2:8080/probe',{signal:AbortSignal.timeout(800)}).then(r=>r.text()).then(t=>console.log(t)).catch(error=>{console.error(error.name+': '+error.message);process.exit(7);});`;
const fetchFrom = async (namespace = ns.member, address = "172.31.200.2") => {
  try {
    return JSON.parse(
      await inside(namespace, "node", [
        "-e",
        fetchCode.replace("172.31.200.2", address),
      ]),
    ) as { source: string };
  } catch (cause) {
    throw new Error(
      `Guard HTTP probe failed during ${stage} from ${namespace} to ${address}`,
      { cause },
    );
  }
};
const udpCode = `const dgram=require('node:dgram'),socket=dgram.createSocket('udp4');const timer=setTimeout(()=>process.exit(7),800);socket.on('message',data=>{clearTimeout(timer);console.log(data.toString());socket.close();});socket.send('probe',8082,'172.31.200.2');`;
const udpFrom = async () =>
  JSON.parse(await inside(ns.member, "node", ["-e", udpCode])) as {
    source: string;
  };
const denied = async (namespace = ns.member) => {
  await assert.rejects(fetchFrom(namespace));
};
const ping = (space: string, address: string) =>
  inside(space, "ping", ["-c", "1", "-W", "1", address]);
const memberSource = "10.240.1.2/32",
  lan = "172.31.200.0/24";
const unrelated = "172.31.201.0/24";
const protectedPaths: RoutingGuardScope[] = [
  {
    direction: "input",
    inputInterface: "eth0",
    source: "192.0.2.2/32",
    destination: "192.0.2.1/32",
  },
  {
    direction: "output",
    outputInterface: "eth0",
    source: "192.0.2.1/32",
    destination: "192.0.2.2/32",
  },
];
const scopes: RoutingGuardScope[] = [
  {
    direction: "forward",
    inputInterface: "wg0",
    source: memberSource,
    destination: lan,
  },
  {
    direction: "forward",
    outputInterface: "wg0",
    source: lan,
    destination: memberSource,
  },
  {
    direction: "forward",
    outputInterface: "awg1",
    source: "0.0.0.0/0",
    destination: lan,
  },
  {
    direction: "output",
    outputInterface: "awg1",
    source: "0.0.0.0/0",
    destination: lan,
  },
  {
    direction: "forward",
    inputInterface: "awg1",
    source: lan,
    destination: "0.0.0.0/0",
  },
  {
    direction: "input",
    inputInterface: "awg1",
    source: lan,
    destination: "0.0.0.0/0",
  },
];
const full = buildRoutingGuard(scopes, { protectedPaths }),
  guard = new RoutingGuard(server);
const sources: string[] = [];
let establishedFrozen = false,
  blockedRequests = 0;
try {
  checkpoint("topology");
  const existing = (await run("ip", ["netns", "list"]))
    .split("\n")
    .map((line) => line.split(" ")[0]);
  assert(
    Object.values(ns).every((name) => !existing.includes(name)),
    "namespace collision",
  );
  for (const name of Object.values(ns)) {
    await run("ip", ["netns", "add", name]);
    created.push(name);
    await inside(name, "ip", ["link", "set", "lo", "up"]);
  }
  await connect(
    ns.server,
    "wg0",
    "10.240.1.1/24",
    ns.member,
    "tun0",
    "10.240.1.2/24",
  );
  await connect(
    ns.server,
    "awg1",
    "10.240.2.1/24",
    ns.exit,
    "tun0",
    "10.240.2.2/24",
  );
  await connect(
    ns.exit,
    "lan0",
    "172.31.200.1/24",
    ns.sink,
    "eth0",
    "172.31.200.2/24",
  );
  await connect(
    ns.server,
    "eth0",
    "192.0.2.1/30",
    ns.management,
    "eth0",
    "192.0.2.2/30",
  );
  for (const space of [ns.server, ns.exit])
    await inside(space, "sysctl", ["-q", "-w", "net.ipv4.ip_forward=1"]);
  await inside(ns.member, "ip", [
    "route",
    "add",
    "default",
    "via",
    "10.240.1.1",
  ]);
  await inside(ns.exit, "ip", [
    "route",
    "add",
    "10.240.1.0/24",
    "via",
    "10.240.2.1",
  ]);
  for (const subnet of ["10.240.1.0/24", "10.240.2.0/24"])
    await inside(ns.sink, "ip", [
      "route",
      "add",
      subnet,
      "via",
      "172.31.200.1",
    ]);
  await server("ip", ["route", "add", lan, "via", "10.240.2.2", "dev", "awg1"]);
  await inside(ns.management, "ip", ["route", "add", lan, "via", "192.0.2.1"]);
  await inside(ns.exit, "ip", [
    "route",
    "add",
    "192.0.2.0/30",
    "via",
    "10.240.2.1",
  ]);
  await inside(ns.sink, "ip", [
    "route",
    "add",
    "192.0.2.0/30",
    "via",
    "172.31.200.1",
  ]);

  await inside(ns.exit, "ip", [
    "addr",
    "add",
    "172.31.201.1/24",
    "dev",
    "lan0",
  ]);
  await inside(ns.sink, "ip", [
    "addr",
    "add",
    "172.31.201.2/24",
    "dev",
    "eth0",
  ]);
  await server("ip", [
    "route",
    "add",
    unrelated,
    "via",
    "10.240.2.2",
    "dev",
    "awg1",
  ]);
  await server("iptables", [
    "-A",
    "FORWARD",
    "-m",
    "conntrack",
    "--ctstate",
    "RELATED,ESTABLISHED",
    "-j",
    "ACCEPT",
  ]);
  await server("iptables", ["-N", "G2_FOREIGN"]);
  await server("iptables", [
    "-A",
    "G2_FOREIGN",
    "-m",
    "comment",
    "--comment",
    "unrelated state",
    "-j",
    "RETURN",
  ]);
  await server("iptables", ["-A", "INPUT", "-i", "eth0", "-j", "G2_FOREIGN"]);
  const foreign = (await server("iptables-save", ["-t", "filter"]))
    .split("\n")
    .filter((line) => line.startsWith("-A "));
  const sink = start(ns.sink, httpCode);
  await sink.ready();
  checkpoint("baseline");
  sources.push((await fetchFrom()).source);
  assert.equal(sources.at(-1), "10.240.1.2");
  assert.equal((await fetchFrom(ns.server)).source, "10.240.2.1");
  const stream = start(ns.member, streamCode);
  await stream.ready();
  await pause(200);
  const snapshot = async () => {
    const before = stream.events.length;
    stream.child.stdin.write("snapshot\n");
    await until(() => stream.events.length > before, "stream snapshot timeout");
    return Number(stream.events.at(-1)!.received);
  };
  const initial = await snapshot();
  await pause(200);
  assert((await snapshot()) > initial, "established stream baseline");
  checkpoint("full-guard");
  await guard.install(full);
  await guard.verify(full);
  const sinkCount = sink.events.length;
  await denied();
  await denied(ns.server);
  blockedRequests += 2;
  assert.equal(
    sink.events.length,
    sinkCount,
    "outbound guard leaked requests to sink",
  );
  await assert.rejects(ping(ns.sink, "10.240.1.2"));
  await assert.rejects(ping(ns.sink, "10.240.2.1"));
  await ping(ns.management, "192.0.2.1");
  await ping(ns.member, "10.240.1.1");
  assert.equal(
    (await fetchFrom(ns.member, "172.31.201.2")).source,
    "10.240.1.2",
  );
  await pause(200);
  const frozen = await snapshot();
  await pause(600);
  assert.equal(await snapshot(), frozen, "established ACCEPT bypassed guard");
  establishedFrozen = true;
  checkpoint("client-firewall-rebuild");
  const document = firewallTestExports.buildRestoreDocument({
    family: 4,
    existingSave: await guard.observe(),
    guard: full,
    states: [
      {
        wgInterface: { name: "wg0", enabled: true, firewallEnabled: true },
        observedUp: true,
        clients: [
          {
            id: 1,
            name: "probe",
            ipv4Address: "10.240.1.2",
            enabled: true,
            allowedIps: [lan, unrelated],
            firewallIps: null,
          },
        ],
        userConfig: { defaultAllowedIps: [lan, unrelated] },
      },
    ] as never,
  });
  await server("iptables-restore", ["--test", "--noflush"], {
    input: document,
  });
  await server("iptables-restore", ["--noflush"], { input: document });
  await guard.verify(full);
  assert.equal(
    (await fetchFrom(ns.member, "172.31.201.2")).source,
    "10.240.1.2",
  );
  await denied();
  blockedRequests++;
  // A new executor must verify and retain a known residual guard.
  await new RoutingGuard(server).verify(full);
  await denied();
  blockedRequests++;
  const counters = await server("iptables", [
    "-L",
    "WG_ROUTE_GUARD",
    "-v",
    "-n",
    "-x",
  ]);
  assert(
    counters
      .split("\n")
      .some(
        (line) =>
          /\bDROP\b/.test(line) && Number(line.trim().split(/\s+/)[0]) > 0,
      ),
  );
  checkpoint("full-guard-remove");
  await guard.remove(full);
  assert.equal((await fetchFrom()).source, "10.240.1.2");
  // Force the intentional test-stream reset; the independent sink must survive.
  stream.child.stdin.write("close\n");
  await until(
    () => stream.child.exitCode !== null,
    "stream reset did not finish",
  );
  assert.equal(sink.child.exitCode, null, JSON.stringify(sink.diagnostics()));
  // Tracked SNAT replies are reverse-translated before the FORWARD filter hook.
  for (const nat of [false, true]) {
    checkpoint(`udp-return-nat-${nat}`);
    if (nat)
      await server("iptables", [
        "-t",
        "nat",
        "-A",
        "POSTROUTING",
        "-s",
        memberSource,
        "-d",
        lan,
        "-o",
        "awg1",
        "-j",
        "SNAT",
        "--to-source",
        "10.240.2.1",
      ]);
    checkpoint(`udp-return-nat-${nat}-baseline`);
    const observed = await udpFrom();
    sources.push(observed.source);
    assert.equal(observed.source, nat ? "10.240.2.1" : "10.240.1.2");
    const reply = buildRoutingGuard(
      [
        {
          direction: "forward",
          inputInterface: "awg1",
          source: lan,
          destination: memberSource,
        },
      ],
      { protectedPaths },
    );
    checkpoint(`udp-return-nat-${nat}-guarded`);
    await guard.install(reply);
    const before = sink.events.length;
    await assert.rejects(udpFrom());
    await until(
      () => sink.events.length > before,
      "outbound request did not reach sink",
    );
    assert.equal(sink.events.at(-1)!.source, nat ? "10.240.2.1" : "10.240.1.2");
    checkpoint(`udp-return-nat-${nat}-restore`);
    await guard.remove(reply);
    assert.equal((await udpFrom()).source, nat ? "10.240.2.1" : "10.240.1.2");
    if (nat)
      await server("iptables", [
        "-t",
        "nat",
        "-D",
        "POSTROUTING",
        "-s",
        memberSource,
        "-d",
        lan,
        "-o",
        "awg1",
        "-j",
        "SNAT",
        "--to-source",
        "10.240.2.1",
      ]);
  }
  checkpoint("local-input-return");
  const localReply = buildRoutingGuard(
    [
      {
        direction: "input",
        inputInterface: "awg1",
        source: lan,
        destination: "10.240.2.1/32",
      },
    ],
    { protectedPaths },
  );
  await guard.install(localReply);
  await denied(ns.server);
  await ping(ns.management, "192.0.2.1");
  await guard.remove(localReply);
  assert.equal((await fetchFrom(ns.server)).source, "10.240.2.1");
  checkpoint("legacy-prefix-only-guard");
  assert.equal((await fetchFrom(ns.management)).source, "192.0.2.2");
  const legacy = buildRoutingGuard(
    [
      { direction: "forward", source: "0.0.0.0/0", destination: lan },
      { direction: "output", source: "0.0.0.0/0", destination: lan },
      { direction: "forward", source: lan, destination: "0.0.0.0/0" },
      { direction: "input", source: lan, destination: "0.0.0.0/0" },
    ],
    { protectedPaths },
  );
  await guard.install(legacy);
  await denied(ns.management);
  await denied(ns.server);
  await ping(ns.management, "192.0.2.1");
  assert.equal(
    (await fetchFrom(ns.member, "172.31.201.2")).source,
    "10.240.1.2",
  );
  await guard.remove(legacy);
  assert.equal((await fetchFrom(ns.management)).source, "192.0.2.2");
  assert.equal((await fetchFrom(ns.server)).source, "10.240.2.1");
  const after = (await server("iptables-save", ["-t", "filter"]))
    .split("\n")
    .filter((line) => foreign.includes(line));
  assert.deepEqual(after, foreign);
  await guard.verify(null);
  console.log(
    JSON.stringify({
      guardProbe: "PASS",
      newFlowBlockedRequests: blockedRequests,
      establishedFrozen,
      natSources: sources,
      inputForwardOutput: true,
      postDnatReturnGuard: true,
      clientFirewallGuardFirst: true,
      residualGuardVerified: true,
      managementAndLocalBaseReachable: true,
      foreignRulesOrderPreserved: true,
      unrelatedForwarding: true,
      legacyPrefixGuard: true,
      unmarkedForwarding: true,
      scopeCount: full.scopes.length,
    }),
  );
} finally {
  for (const child of children) child.kill("SIGTERM");
  for (const name of [...created].reverse())
    await run("ip", ["netns", "delete", name]).catch(() => {});
}
