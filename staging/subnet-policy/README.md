# Subnet policy staging checks

These checks use only the dedicated staging host and restored application-volume
clones. Preserve the immutable Phase 0 golden archive and the live volume. Keep
management and console recovery independent of the tunnels under test.

Phase 1 retains policy version 1. Exclusions and multiple membership writes remain
unavailable, and the pure version 2 compiler does not apply Linux state. The
policy journal starts with null applied/pending evidence. Supplied-key and full
client edit contracts are prepared but existing routes still use their original
schemas until the complete Phase 2 runtime is verified.

Build the migration harness from the candidate source, using the declared pnpm
version, from `src`:

```sh
pnpm exec esbuild ../staging/subnet-policy/rehearse-migration.ts \
  --bundle --platform=node --format=esm --packages=bundle \
  --alias:#shared=./shared --outfile=/private/tmp/rehearse-migration.mjs
```

Copy that bundle to the restricted staging evidence directory. Run it with Node
in the exact candidate image, mount **only a newly restored clone** at
`/etc/wireguard`, and pass `/etc/wireguard` as its directory argument. The image
provides the migrations at `/app/server/database/migrations`. The harness does
not start networking. It proves original row/column preservation, migration
rerun, integrity, foreign keys, inactive storage, and compiler budget compatibility
with the preserved dataset. It emits counts and hashes, never credentials or
configuration contents. Take a checksum of the bundle and retain it with the
source commit and image identity.

Image/volume rollback and tunnel traffic are separate required gates. Restore a
second clone from the matching old snapshot for the previous image; never start
an old image against the migrated clone. Client containers receive only their
own restricted read-only config files, never an application-data volume.

## Inactive Phase 2 guard checkpoint

`guard-probe.ts` proves directional filter guards with actual Linux namespaces,
TCP/UDP traffic, SNAT return paths and counters. It checks established-flow
blocking before ACCEPT rules, atomic client-firewall replacement, unrelated
forwarding, local traffic, management continuity and exact foreign-rule
preservation. It refuses namespace collisions and removes only namespaces it
created. Its `policy-checkpoint.ts` module also exercises the shared classifier,
same-device default/LAN paths, terminal block/host, per-group NAT, all eight
executor fault boundaries, fresh-executor restoration under a retained guard,
stale-child cleanup and foreign-body refusal. These are veth/Linux proofs;
AWG peer ownership, durable coordinator recovery and version 2 activation have
separate required gates. Normal application paths still use version 1.

Build from `src` with the locked dependencies:

```sh
pnpm exec esbuild ../staging/subnet-policy/guard-probe.ts \
  --bundle --platform=node --format=esm --packages=bundle \
  --alias:#server=./server --alias:#shared=./shared \
  --outfile=/private/tmp/guard-probe.mjs
```

On staging, use a disposable rootful privileged container with `--network none`,
the bundle mounted read-only, `WG_EASY_RUN_PRIVILEGED_TESTS=1`, and an immutable
Node-capable image with iproute2/iptables/ping. Override the entrypoint to run
`node /probe.mjs`. Mount no application volume, host network, host namespaces,
credentials or client configurations. Retain the bundle checksum and output.
The image is only an isolated Node/tool interpreter for that exact bundle; it
does not deploy the inactive application changes. The image workflow runs the
same bundled proof on its disposable Linux runner.

## Real AWG process recovery

`awg-recovery-probe.ts` requires the shipped AWG kernel device/tools on dedicated
staging. It creates separate underlay, member, exit, sink and management
namespaces, ephemeral private keys/configs and a fresh synthetic database. It
mounts no application data, host network or client configurations. Only exact
namespaces and the owner-marked private directory it creates are removed.

Build from `src`:

```sh
pnpm exec esbuild ../staging/subnet-policy/awg-recovery-probe.ts \
  --bundle --platform=node --format=esm --packages=bundle \
  --alias:#server=./server --alias:#shared=./shared --alias:#db=./server/database \
  --outfile=/private/tmp/awg-recovery-probe.mjs
```

Run with the same disposable privileged/network-none pattern above. The immutable
interpreter image must include the matching migrations at
`/app/server/database/migrations`. This fixture seeds a verified synthetic applied
generation; it does not perform initial application promotion. It exercises real
peer/key replacement, an obfuscated exit, complete peer maps, marked route
lookups, byte counters, observed sink sources, independent worker process kills,
retained guards, durable private-byte restoration, complete client-filter recovery
and same-identity preshared-key clearing. It verifies filter denial while another
member on the same interface retains its default path. Unchanged interfaces use
no sync; affected peers use `awg syncconf`.
IPv6 checks preserve the existing unmarked legacy site path, credentials and
client filtering; common routing classification remains IPv4 only. The full
matrix also kills workers between IPv4/IPv6 guard installation and removal,
then repairs only exact known missing family guards before restoration.
Full private interface verification also compares actual server identity,
listen port, MTU, addresses, all AWG parameters and peer PSKs in memory.
Recovery callbacks in this fixture operate the lab endpoints explicitly; the
product does not push configurations to remote clients.

Keep only its safe stage/count/source output and bundle hash as evidence. Keys,
database bytes and configuration text remain inside the disposable private
fixture. This is a component-level AWG proof. Full application callback/firewall
integration, promotion/migration/rollback, browser behavior and independent
published-UDP traversal retain their separate required gates.
