# Phase 1 staging checks

Phase 1 reuses the accepted Phase 0 server/client lab for the migration and
compatibility regression gate. `compatibility-smoke.sh` adds the phase-specific
proof that the exact AmneziaWG userspace/tool revisions built into the server
image accept a standard WireGuard peer when every AWG-only directive is
omitted.

Required immutable image references:

```sh
PHASE1_SERVER_IMAGE=ghcr.io/example/wg-easy@sha256:<digest> \
PHASE0_WG_CLIENT_IMAGE=ghcr.io/example/wg-easy-lab-wg@sha256:<digest> \
./staging/phase1/compatibility-smoke.sh
```

The smoke uses an isolated, disposable Docker bridge and two temporary
containers. The server tunnel is created explicitly with the pinned
`amneziawg-go` binary and configured with the pinned `awg` tool. The harness
forces the userspace backend even when the staging host has the AWG kernel
module, then verifies both the userspace control socket and TUN device before
testing traffic. The peer image contains generic `wg`/`wg-quick` tooling only.
Temporary keys/configs are mode `0600`, are never printed, and are removed by
the cleanup trap.
