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
