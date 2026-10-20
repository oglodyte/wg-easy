/** Isolated Linux proof; no application or host firewall is touched. */
import assert from "node:assert/strict";

import type { execFile } from "../../src/server/utils/cmd";
import {
  admitManagedServerHooks,
  ManagedServerHookEffects,
  resolveManagedServerHooks,
} from "../../src/server/utils/managedServerHooks";
import type {
  RoutingGuard,
  RoutingGuardPlan,
} from "../../src/server/utils/routingGuard";

export async function proveManagedHookRecovery({
  server,
  guard,
  guardPlan,
  denied,
  unrelated,
  management,
}: {
  server: typeof execFile;
  guard: RoutingGuard;
  guardPlan: RoutingGuardPlan;
  denied: () => Promise<void>;
  unrelated: () => Promise<unknown>;
  management: () => Promise<unknown>;
}) {
  const up =
    'OUT_IF=$(ip -4 route show default | awk "NR == 1 {print \\$5}"); test -n "$OUT_IF" || exit 1; iptables -t nat -A POSTROUTING -s 10.242.0.0/24 -o "$OUT_IF" -j MASQUERADE; iptables -A INPUT -p udp -m udp --dport 62001 -j ACCEPT; iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; ip6tables -t nat -A POSTROUTING -s fd42:1::/64 -o "$OUT_IF" -j MASQUERADE; ip6tables -A INPUT -p udp -m udp --dport 62001 -j ACCEPT; ip6tables -A FORWARD -i wg0 -j ACCEPT; ip6tables -A FORWARD -o wg0 -j ACCEPT;';
  const compile = (script: string) =>
    admitManagedServerHooks(
      "wg0",
      new Map([
        ["preup", ": phase0-baseline"],
        ["postup", script],
        ["predown", ""],
        ["postdown", script.replaceAll(" -A ", " -D ")],
      ]),
    );
  const effects = new ManagedServerHookEffects(server);
  const originalDefaults = JSON.parse(
    await server("ip", ["-j", "-4", "route", "show", "default"]),
  ) as unknown[];
  assert.equal(
    originalDefaults.length,
    0,
    "isolated probe has no default route",
  );
  await server("ip", [
    "route",
    "add",
    "default",
    "via",
    "192.0.2.2",
    "dev",
    "eth0",
  ]);
  const old = resolveManagedServerHooks(
      compile(up),
      await effects.defaultEgress(),
    ),
    target = resolveManagedServerHooks(
      compile(up.replaceAll("62001", "62002")),
      "lo",
    );
  assert.deepEqual(
    old.filter((r) => r.table === "nat").map((r) => r.args[3]),
    ["eth0", "eth0"],
  );
  // An equal foreign rule precedes another foreign rule and all owned copies.
  // Removing a first equal rule would silently change that ordering.
  await server("iptables", ["-A", "FORWARD", "-i", "wg0", "-j", "ACCEPT"]);
  await server("iptables", [
    "-A",
    "FORWARD",
    "-m",
    "comment",
    "--comment",
    "hook proof foreign sentinel",
    "-j",
    "ACCEPT",
  ]);
  const snapshot = async () => {
    const result: string[] = [];
    for (const binary of ["iptables", "ip6tables"])
      for (const table of ["filter", "nat"])
        result.push(await server(binary, ["-t", table, "-S"]));
    return result;
  };
  const before = await snapshot();
  await guard.install(guardPlan);
  const verifyGuard = () => guard.verify(guardPlan),
    initial = await effects.capture([], old);
  await effects.reconcile(initial, "target", verifyGuard);
  const intent = await effects.capture(old, target);
  let postCommitFaults = 0;
  for (let boundary = 1; boundary <= 16; boundary++) {
    let writes = 0;
    const faulting: typeof execFile = async (binary, args, options) => {
      const result = await server(binary, args, options);
      if (binary.endsWith("-restore") && !args?.includes("--test")) {
        if (++writes === boundary)
          throw new Error("injected post-commit fault");
      }
      return result;
    };
    const attempt = new ManagedServerHookEffects(faulting);
    await assert.rejects(async () => {
      await attempt.reconcile(intent, "base", verifyGuard);
      await attempt.reconcile(intent, "target", verifyGuard);
    }, /effect_repair_failed/);
    assert.equal(writes, boundary);
    postCommitFaults++;
    await guard.verify(guardPlan);
    await denied();
    await unrelated();
    await management();
    const fresh = new ManagedServerHookEffects(server);
    await fresh.reconcile(
      JSON.parse(JSON.stringify(intent)),
      "previous",
      verifyGuard,
    );
    await fresh.verify(intent, "previous");
    await guard.verify(guardPlan);
  }
  await effects.reconcile(intent, "base", verifyGuard);
  await effects.reconcile(intent, "target", verifyGuard);
  await effects.verify(intent, "target");
  await denied();
  await unrelated();
  await management();
  await effects.reconcile(intent, "previous", verifyGuard);
  await effects.reconcile(initial, "previous", verifyGuard);
  await guard.remove(guardPlan);
  await guard.verify(null);
  assert.deepEqual(
    await snapshot(),
    before,
    "all foreign rule bodies/order preserved",
  );
  await server("ip", [
    "route",
    "del",
    "default",
    "via",
    "192.0.2.2",
    "dev",
    "eth0",
  ]);
  return {
    admittedHookRecovery: true,
    hookPostCommitFaults: postCommitFaults,
    frozenDynamicEgress: true,
    equalForeignHookRuleOrder: true,
    hookGuardTraversal: true,
    hookUnrelatedAndManagement: true,
  };
}
