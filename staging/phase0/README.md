# Phase 0 staging delivery and baseline

This directory defines the isolated, single-interface Phase 0 staging stack,
the pinned client lab, and the backup/manifest automation used as the migration
baseline for later phases. It intentionally adds no multi-interface or common
routing behavior.

## Trust and secret boundary

- The authoritative staging host is `yfedotov@wg-easy-stage.lan`.
- Server management is bound to host loopback TCP 51821 and is reached through
  SSH. No public host-port proof is required in Phase 0.
- Real environment files live under `/opt/wg-easy-staging/secrets` with mode
  `0600`. Generated client configs and one-time-link material live under
  `/var/lib/wg-easy-test-artifacts/phase0` with mode `0600`.
- The application volume is never mounted into a client container. Client
  configs are mounted individually and read-only.
- Do not copy production data, credentials, routes, or VPN ranges into this
  stack.

## Immutable images and registry credentials

Run the `Immutable Phase Images` GitHub Actions workflow on the exact phase
commit. It uses the repository-scoped `GITHUB_TOKEN` with `packages: write` and
publishes an artifact containing four `name@sha256:digest` references. Tags use
`mir-p0-<12-character-commit>` and are never reused.

The selected repository is GHCR under the GitHub repository owner. For a
private package, authenticate Docker on staging with a separate staging-only
personal access token (classic) carrying only `read:packages`. Pass it to
`docker login` over stdin and keep Docker's credential file outside Git. The
local developer token is not copied to staging and is not accepted as a
staging-pull credential. A public GHCR package may instead be pulled
anonymously.

See GitHub's current
[Container registry authentication guidance](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry#authenticating-to-the-container-registry).

Install the workflow artifact as:

```text
/opt/wg-easy-staging/secrets/phase0-images.env
```

Copy `server.env.example` to:

```text
/opt/wg-easy-staging/secrets/phase0-server.env
```

Replace every credential placeholder with staging-only values, then set both
files to mode `0600`.

## Network topology

| Plane            | Subnet            | Participants                         |
| ---------------- | ----------------- | ------------------------------------ |
| Tunnel underlay  | `172.30.110.0/24` | wg-easy plus four VPN clients        |
| Exit egress      | `172.30.111.0/24` | primary/backup exits and sink only   |
| Application/data | `172.30.112.0/24` | wg-easy only; internal bridge        |
| Tunnel IPv4      | `10.251.0.0/24`   | compatibility-mode `wg0` and clients |
| Tunnel IPv6      | `fd42:251:0::/64` | compatibility-mode `wg0` and clients |

The member containers are not attached to exit egress or application/data.
The traffic sink is not attached to the underlay. The client-lab test also
brings the generic member tunnel down and proves the sink becomes unreachable.

## Staging sequence

Run from a checkout of the exact phase commit on the staging host:

```sh
staging/phase0/scripts/preflight.sh
staging/phase0/scripts/deploy.sh
staging/phase0/scripts/seed-baseline.sh
staging/phase0/scripts/run-client-lab.sh
staging/phase0/scripts/generate-manifest.sh phase0-golden.json
staging/phase0/scripts/snapshot-volume.sh phase0-golden-<short-commit>
```

Run snapshot immediately after seeding so the fresh unconsumed one-time link is
inside its supported five-minute lifetime. The manifest contains link row IDs
and expiry timestamps but never the token.

## Snapshot, clone, and rollback

`snapshot-volume.sh` stops the Phase 0 server for a consistent archive, verifies
that `wg-easy.db` and `wg0.conf` are present, writes a SHA-256 sidecar, makes the
files read-only, and restarts the server. It refuses to overwrite an existing
archive.

Restore only into a new explicitly named volume:

```sh
staging/phase0/scripts/restore-volume.sh \
  phase0-golden-<short-commit> \
  wg-easy-phase0-clone-<short-commit>
```

To test the clone, stop the server, set `WG_EASY_VOLUME` to the clone name, and
run `deploy.sh`. Generate `phase0-clone.json` and compare it with the golden
manifest using `compare-manifests.sh`. Restore the normal cumulative volume by
setting `WG_EASY_VOLUME=wg-easy-phase0-data` and rerunning `deploy.sh`.

For a previous-image rollback smoke, create a second restricted images file
whose server entry is the previous immutable digest and whose three lab entries
remain unchanged. Deploy the restored clone with `PHASE0_IMAGE_ENV` pointing at
that file, verify `wg0`, login, config download, client traffic, health, and
logs, then return to the Phase 0 digest. Never run an older image against a
newer migrated database in later phases; restore the matching snapshot first.

Snapshots are stored under `/var/backups/wg-easy-staging/phase0`. They are
root-owned/read-only and addressed by explicit names and checksums. Failed or
post-migration volumes are preserved for diagnosis; the restore automation does
not overwrite or delete the cumulative staging volume.
