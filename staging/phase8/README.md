# Phase 8 production-candidate verification

Phase 8 is the final verification and hardening gate for the phased
multi-interface/common-routing implementation. The authoritative acceptance
criteria and evidence record remain in the externally managed implementation
runbook; this directory contains only reproducible, non-secret repository-side
checks and operator guidance.

## Candidate build

Run the `Immutable Phase Images` workflow for the exact candidate commit with
phase `p8`. The server image is published as a multi-platform manifest for
`linux/amd64` and `linux/arm64`. CI runs the global source gate, the privileged
Linux namespace routing suite, and architecture-specific binary smokes before
publishing digest evidence. The staging client-lab images remain `linux/amd64`
because the selected disposable staging host is x86_64.

Record the immutable manifest digest from the workflow artifact. Do not treat
the tag alone as release evidence and never replace an existing phase tag.

## Local and CI gate

From `src`, with the lockfile-selected pnpm version:

```sh
pnpm test:unit
pnpm lint
pnpm typecheck
pnpm format:check
pnpm build
```

Also run the migration suites and repository-side staging checks:

```sh
pnpm exec drizzle-kit check
../staging/phase0/tests/test-phase0.sh
../staging/phase1/tests/test-phase1.sh
../staging/phase8/tests/test-phase8.sh
```

The privileged routing test is Linux-only and must not be counted as passing
when Vitest reports it skipped:

```sh
sudo env "PATH=$PATH" WG_EASY_RUN_PRIVILEGED_TESTS=1 \
  node node_modules/vitest/vitest.mjs run --project integration
```

## Security review

The final review must confirm that generated Linux operations use validated
typed argument arrays through the shell-free command runner, private command
input uses restricted temporary files or standard input, and owned-state
verification refuses collisions without touching non-owned state. Custom
WireGuard hooks remain intentionally supported as authenticated operator input;
they are not reused to implement generated common-routing policy.

Client configuration, QR-code, and one-time-link creation routes remain
permission checked. The public one-time-link redemption route accepts only a
bounded URL-safe bearer token and never exposes administrative interface data.
Metrics stay behind the configured metrics authentication boundary and avoid
raw reconciliation errors as labels.

## Staging gate

Use only the dedicated staging host and restricted artifact locations already
defined by Phase 0. Preserve the immutable golden pre-feature snapshot. Restore
it into a new volume, create a fresh supported-lifetime one-time link, and run
the full upgrade on that clone before touching the cumulative staging volume.

The recorded end-to-end result must cover:

- preservation-manifest comparison and foreign-key integrity;
- compatibility-mode and AWG-parameterized interfaces and client exports;
- interface-scoped restart/failure isolation, metrics, CLI QR, expiration,
  one-time links, health, and compatibility API routes;
- cross-interface routing, NAT on/off, ordered failover/failback, block/host,
  restart/crash recovery, collision refusal, and exact owned-state cleanup;
- a repeated health-check/expiration soak with resource and log observations;
- one independent client outside the same-host container lab reaching the
  published staging tunnel endpoint and passing traffic;
- snapshot rollback to the accepted Phase 7 image and a repeat candidate
  upgrade from the restored pre-feature baseline.

Secret configs, tokens, databases, and credentials stay outside Git and must
not be printed into ordinary logs. Record only non-secret checksums, IDs,
digests, and summarized outcomes in the external runbook.

## Release and rollback notes

The production candidate contains schema migrations first introduced in Phase

1. Automatic downgrade to an older schema is unsupported. Production promotion
   is a separate action requiring explicit authorization after Phase 8 acceptance.

Before promotion, record the existing production image digest and Compose
definition and take a consistent `/etc/wireguard` volume snapshot. Deploy the
accepted Phase 8 manifest by digest, observe migration/startup before changing
configuration, and keep both the prior image and snapshot through the agreed
observation period.

Rollback stops the stack, preserves the failed post-migration volume for
diagnosis, restores the matching pre-upgrade volume snapshot, and redeploys the
previous image digest. Never start the older image against the Phase 8-migrated
database.
