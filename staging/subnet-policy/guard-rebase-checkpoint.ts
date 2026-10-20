/** Real Linux proof of the exact persisted old/new guard repair protocol. */
import assert from "node:assert/strict";

import { execFile } from "../../src/server/utils/cmd";
import {
  buildRoutingGuard,
  RoutingGuard,
  type RoutingGuardPlan,
  type RoutingGuardScope,
} from "../../src/server/utils/routingGuard";

export async function proveGuardRebase({
  server,
  previous,
  protectedPaths,
  denied,
  management,
}: {
  server: typeof execFile;
  previous: RoutingGuardPlan;
  protectedPaths: readonly RoutingGuardScope[];
  denied: () => Promise<void>;
  management: () => Promise<void>;
}) {
  const old = buildRoutingGuard([
    ...previous.scopes,
    { direction: "forward", inputInterface: "tun0", source: "fd08::2/128", destination: "::/0" },
  ], { protectedPaths }),
    target = buildRoutingGuard([
      ...previous.scopes,
      { direction: "forward", inputInterface: "tun0", source: "fd08::2/128", destination: "2001:db8::/32" },
    ], { protectedPaths });
  const guard = new RoutingGuard(server);
  await guard.install(old);
  let written = false;
  const interrupted: typeof execFile = async (binary, args = [], options = {}) => {
    const result = await server(binary, args, options);
    if (binary === "iptables-restore" && !args.includes("--test")) {
      written = true;
      throw new Error("injected stop after IPv4 guard rebase commit");
    }
    return result;
  };
  await assert.rejects(new RoutingGuard(interrupted).ensure(target, old));
  assert(written);
  await new RoutingGuard(server).verify(target, { families: [4] });
  await new RoutingGuard(server).verify(old, { families: [6] });
  const before = (await server("iptables-save", ["-t", "filter"], { log: false }))
    .split("\n").filter((line) => line.includes("WG_ROUTE_GUARD"));
  await server("ip6tables", ["-w", "5", "-A", "WG_ROUTE_GUARD", "-j", "ACCEPT"], { log: false });
  await assert.rejects(new RoutingGuard(server).ensure(target, old));
  const after = (await server("iptables-save", ["-t", "filter"], { log: false }))
    .split("\n").filter((line) => line.includes("WG_ROUTE_GUARD"));
  assert.deepEqual(after, before, "unknown IPv6 refuses any IPv4 change");
  // Remove exactly the rule this isolated fixture introduced, then replay.
  await server("ip6tables", ["-w", "5", "-D", "WG_ROUTE_GUARD", "-j", "ACCEPT"], { log: false });
  await new RoutingGuard(server).ensure(target, old);
  await new RoutingGuard(server).verify(target, { families: [4, 6] });
  await denied();
  await management();
  // A new target can stop using IPv6; stale known family state must disappear.
  await new RoutingGuard(server).ensure(previous, target);
  await new RoutingGuard(server).verify(null, { families: [6] });
  await denied();
  await management();
  await new RoutingGuard(server).remove(previous);
  await new RoutingGuard(server).verify(null, { families: [4, 6] });
  return { exactGuardRebaseRecovery: true, unknownFamilyRebaseRefused: true, obsoleteIpv6GuardRemoved: true };
}
