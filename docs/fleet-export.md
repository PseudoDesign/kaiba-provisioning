# Authenticated fleet evidence export

`kaiba-provision-export` serves immutable development `ProvisioningRecord`
observations. It cannot issue identities, modify transactions, append audit events
or operate hardware. Development outcomes keep both readiness flags false.
The shared contract is pinned to `pd-codex/kaiba-contracts` commit
`9ebf773d5d07d61d8cb522aea66160d37562e6b1`, version `0.1.0-draft.1`.

## Authority configuration

Control and audit accept two optional flags together:
`--handoff-policy <file>` and `--handoff-evidence-dir <private-directory>`.
They require complete mTLS configuration. Without them the existing routes and
station/lane policy are unchanged. A policy explicitly lists service URI SANs
and transaction IDs; these identities have no permission on command/append routes:

```json
{"grants":[{"principal":"spiffe://kaiba.test/service/fleet","transactions":["example-transaction"]}]}
```

The read surface is `GET /api/v1/handoff/{transaction}/current` and
`GET /api/v1/handoff/{transaction}/evidence/{sha256-hex}`. Reads retain an exact
snapshot in the authority's private evidence directory before returning it.
They do not rewrite the original control or audit store. Evidence references
bind these retained bytes, not a reserialization made by the consumer.

The exporter requires `--config`, `--state`, `--listen`, `--tls-cert`, `--tls-key`
and `--client-ca`. Its configuration contains the trusted export `policy`,
transaction `access` grants, independent `control`/`audit` HTTPS origins and CA
files, its service client certificate/key, and an `artifacts` mapping from pinned
profile/posture/release digests to local files. Those files are verified and
retained at startup. No client request sets authority, tenant, domain or cohort.
The runnable fleet rehearsal generates a complete disposable example configuration.

All services are single writers for their own local state. The exporter holds
an exclusive process lock. Protect the state and configuration directories;
backup retention and multi-host operation require a separate deployment design.

## Export and verification

- `POST /api/v1/exports/{transaction}` performs authenticated control/audit/control
  reads, validates source bindings and required receipts, then persists a record.
- `GET /api/v1/exports/{transaction}/{revision}` retrieves the exact immutable record.
- `GET /api/v1/exports/{transaction}/artifacts/{sha256-hex}` resolves configured
  profile/posture/release bytes within the caller's transaction grant.

Export revisions are monotonic and distinct from coordinator resource versions.
Control, audit and policy changes participate in the observation identity.
Unchanged retries, including after process restart, preserve issued time, bytes
and digest. Failed reads publish no revision; changed input publishes a new one.
Shared-record digests use JCS with the contract's exact-integer number profile.
Evidence digests use original retained bytes. Errors expose categories rather
than authority response bodies.

`security_applied` remains candidate evidence. Quarantine and unresolved states
remain visible; missing or inconsistent audit evidence blocks export. The exporter
retains the authority's complete transaction-filtered audit snapshot and validates
all referenced receipts. This is not a complete global audit-chain proof.

Fleet must independently resolve evidence through its configured control/audit
origins and compare current snapshots before using it. URI locators are not trust
anchors. Historical verification is not current admission. The live observation
is not a distributed atomic transaction; production admission remains disabled.

## Validation and provenance

Focused tests cover mapping, immutable revisions, scoped readers and the existing
station/approver denial boundaries. The complete process rehearsal is owned by
[kaiba-fleet](https://github.com/PseudoDesign/kaiba-fleet), using packaged native
binaries, temporary mTLS roots and PostgreSQL; it needs no kernel or board.

The initial mapping and synthetic workflow fixture were adapted from
`pd-codex/kaiba-controller`'s retained export patch (SHA-256
`286c0063ee9924bb1369a84e8d826574eb965aaa8ccf6a0574ac61b7385b29f1`).
The live scoped interfaces and durable revision allocator are additional work.
The offline helper remains only a fixture-building API, not the deployed exporter.
