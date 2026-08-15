---
title: Managed Interfaces and Common Routing
---

## Overview

wg-easy can manage multiple tunnel interfaces in one installation. Each managed
interface has its own name, keys, tunnel CIDRs, listen port, generated-client
endpoint, client defaults, hooks, firewall setting, and AmneziaWG parameters.
The migrated/default interface is `wg0`; existing clients remain assigned to it.

All managed interfaces use the AmneziaWG runtime. An interface with **AWG
parameters disabled** omits every AWG-only server and client setting and can
serve compatible standard WireGuard clients. An interface with AWG parameters
enabled requires an AmneziaWG-compatible client; WireGuard-format export is
unavailable for that interface. This is a per-interface compatibility choice,
not a switch between WireGuard and AWG runtime backends.

/// note

Set `AWG_FORCE_USERSPACE=true` only when the installed AWG kernel path is
incompatible or unstable. It selects the bundled AWG userspace implementation,
not a WireGuard backend. The container must have `/dev/net/tun` available.

///

## Manage Interfaces

Use **Admin Panel → Interfaces** to create, edit, enable, disable, restart, or
delete interfaces. Names are immutable after creation. New interfaces need a
unique Linux-safe name, device, UDP listen port, and non-overlapping tunnel
CIDRs. A clone starts disabled when its copied custom hooks require review.

The page reports desired configuration separately from observed runtime state.
A saved change can be pending or degraded rather than active; inspect the
interface error and retry/restart it before treating the tunnel as usable.
Deleting an interface is blocked while it is the default interface, has clients,
or is referenced by routing groups.

### Listen port and generated-client endpoint

The interface **listen port** is the UDP port used inside the container or host
network namespace. The generated-client **endpoint host and port** are written
to client configurations. They default to the same port, but are intentionally
independent so a Docker or host UDP mapping can use a different public port.

Publishing UDP is an operator responsibility. For every interface that clients
must reach, add an explicit Docker/host mapping and any required perimeter
firewall or provider rule. For example, an interface listening on `51830` inside
the container could be published as host UDP `51840`:

```yaml
services:
    wg-easy:
        ports:
            - '51840:51830/udp'
```

Set that interface's generated-client endpoint port to `51840` and its endpoint
host to the hostname or address clients can reach. Saving either setting does
not publish a port and does not prove that the endpoint is reachable. Verify
reachability with a real client and the appropriate host/network evidence.

## Client profiles and exports

A client is an interface-specific profile. It belongs to exactly one interface
and has its own addresses and cryptographic credentials. To give one person or
device access through two interfaces, create two profiles; do not copy keys
between them. Use the interface filter and badge in the client list to avoid
editing the wrong profile.

Client creation defaults to the configured default interface when an older
caller does not select one. Authorized client creators can select every managed
interface. A disabled or degraded interface is selectable with an operational
warning, but a profile on it will not connect until that interface is healthy.

Config, QR, and one-time-link exports derive the interface from the client
profile. Choose `auto`, WireGuard, or AmneziaWG as appropriate. `auto` follows
the client preference or interface default; one-time links resolve and retain a
concrete format when created. A WireGuard export is rejected when the assigned
interface has AWG parameters enabled.

## Common routing groups

Use **Admin Panel → Routing** to send matching IPv4 traffic from member clients
through an ordered list of exit-client candidates. Members and exits can be on
different managed interfaces. Version 1 supports IPv4 and ordered failover only;
it does not load balance. A member may be in only one group and cannot be an
exit for that same group.

An enabled group needs at least one member, enabled exit candidate, and IPv4
prefix. The default routed prefix is `0.0.0.0/0`, NAT is enabled by default,
and the default all-exits-down policy is `block`. The interface configuration
uses `Table = off`; wg-easy generates and verifies its own routing policy.

### Exit health and failover

Candidates are tried in priority order. A candidate must have an enabled client,
an enabled/observed-up interface, a valid persistent keepalive, and a recent
handshake before it is selected. The recommended persistent keepalive is 25
seconds; it must be no greater than one third of the configured health timeout.
The default timeout is 180 seconds. Hold and delayed-failback timers prevent
flapping, so a healthy higher-priority exit does not necessarily become active
immediately.

The UI distinguishes configuration readiness, observed tunnel health, selected
exit, and verified applied exit. A handshake proves tunnel liveness only; it
does not prove that the exit can forward traffic to the requested destination.
When changing an exit's keepalive or generated configuration, download and
apply the new configuration on that exit device.

### NAT, return paths, and all exits down

With routing-group NAT enabled, wg-easy source-NATs matching traffic to the
server tunnel address on the selected exit interface. The exit still needs IP
forwarding and downstream NAT/routing. With NAT disabled, the exit and its
downstream network must have return routes (and suitable peer AllowedIPs) for
the original member-client addresses.

Ensure forwarded traffic leaves through the intended downstream network and is
not routed back into the same VPN tunnel. wg-easy does not configure the exit
operating system, its firewall, forwarding, NAT, or return routes.

If every exit is unavailable:

- `block` (the default) keeps matching traffic fail-closed with unreachable
  routing.
- `host` is an explicit fail-open choice: matching traffic follows the normal
  host/wg-easy path instead. Use it only when that fallback is acceptable.

Saved group configuration is not necessarily applied. Treat `active` as the
verified state; investigate `selected_pending`, `blocked`, `host_fallback`, or
`degraded` status before relying on the policy.

## Upgrade, backup, and rollback

Before an upgrade that may migrate the database:

1. Record the exact running image digest and Compose/stack definition.
2. Stop writes and take a consistent backup of the `/etc/wireguard` volume.
   Verify that it contains the database and generated interface configuration.
3. Rehearse the upgrade on a restored clone first, including client/profile
   preservation and a real connectivity check.
4. Keep the previous image and matching pre-migration backup until the new
   release has completed its agreed observation period.

Migration preserves `wg0` as the default interface and keeps existing client
IDs, profiles, keys, URLs, one-time links, hooks, and user defaults. If an old
configuration cannot be classified safely as WireGuard-compatible or AWG-only,
the interface remains unresolved/degraded until an operator makes the required
compatibility decision; do not assume a runtime executable can infer it later.

To roll back a migration-bearing release, stop the stack, preserve the failed
volume for diagnosis, restore the matching pre-migration volume backup, then
redeploy the matching previous image. Do not run an older image against a newer
migrated database unless that downgrade path has been explicitly designed and
tested.

## Production promotion checklist

Promote only an immutable image digest that has passed the applicable staging
matrix. Before a production deployment, take and verify a separate production
volume backup, record the current image and stack, deploy only the approved
digest, observe migration and startup before making configuration changes, and
retain the rollback image and backup through the agreed observation period.
