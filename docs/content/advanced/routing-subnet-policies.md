---
title: Routing groups and subnet policies
---

Use a routing group to send selected client profiles through an ordered list of
exit profiles. Members and exits can use different managed interfaces. Every
profile needs its own keys and tunnel addresses, even when two profiles belong
to the same physical router.

For example, put `10.20.0.0/16` in one LAN group. Select the members that need
that LAN, then add router profiles A and B as exits, with A first. Those members
can also belong to an internet group containing `0.0.0.0/0`. The original `/16`
wins for LAN traffic. Failure of A selects B; failure of the physical router
may make both profiles unavailable.

Paste included or excluded IPv4 CIDRs separated by commas or newlines. The
private-network action adds exactly `10.0.0.0/8`, `172.16.0.0/12` and
`192.168.0.0/16` as editable exclusions. An exclusion allows another group or
normal routing to handle that destination. It does not block traffic itself.
Exclusions do not increase the specificity of the original included prefix.
Equal-specificity winners for one member are rejected.

Preview the complete policy before saving. The explanation shows the member,
destination, original matching prefix and winning group. Coverage, shadowing,
observed exits and generated counts are shown separately. A preview does not
apply routing. If another configuration change occurs, review the latest saved
state and preview again. Live status refresh preserves the current draft.

When every exit of the winning group is unavailable, **block** drops matching
traffic. **Host** uses normal unmarked routing and needs a working host/site
route. Neither action falls back to a broader routing group. Disabled groups
do not participate. Existing IPv6 site routing is preserved; common subnet
policies apply only to IPv4.

One output interface cannot independently send the same destination to two
different peers. Every enabled candidate is checked, including an unhealthy
backup. Resolve a conflict by aligning member policies, moving a candidate to
another interface, or putting mutually exclusive alternatives in one group.
Removing a specific LAN group can expose a conflict with a broader internet
group and a static Server Allowed IPs route. Add a suitable exclusion to the
internet group before removing that LAN policy.

Member client AllowedIPs must send the LAN or an appropriate default route
into the tunnel. Download and apply changed profiles on the devices yourself.
The exit router needs forwarding, firewall rules and downstream routing or NAT.
With group NAT enabled, return routing must reach the server's tunnel address
on the exit interface. Without group NAT, the downstream network needs return
routes to each original member address. A recent handshake proves tunnel
health; test downstream traffic and its observed source address separately.

Normal client creation offers supplied-private-key entry and a link to all
configuration fields. Leave untouched key controls alone to generate new
credentials at creation or preserve existing credentials during editing. A
replacement private key derives its public key automatically. Choose PSK
replacement or explicit clearing separately. Editing keeps profile IDs and
routing references. wg-easy does not push updated keys or configuration to the
remote device. Keep independent management access while applying them.

Compare desired and applied revisions after saving. A saved configuration may
still be pending or degraded. Review interface/group errors and any pending
transition before relying on the new path. Database configuration alone does
not prove that the operator-published UDP endpoint is reachable externally.
