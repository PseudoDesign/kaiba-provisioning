# Pilot handoff preflight

The existing-device pilot now has an authenticated observation transport.
`kaiba-pilot-export` serves reviewed `PilotAdoptionRecord` documents using
[kaiba-contracts 046193a](https://github.com/pd-codex/kaiba-contracts/tree/046193a204e576cd1c3c5f0208e2ce3c9ab078bc),
wire family `0.2.0-draft.1`. The old development exporter and its wire family
remain unchanged. This is a software prerequisite for the
[pilot plan](pilot-enrollment.md); the separate [pilot client](pilot-device-client.md) and fleet lifecycle now have
software coverage. Real issuer deployment and device enrollment remain planned.

## Reviewed input boundary

A station observation author prepares one complete adoption record per device,
including authenticated identity/storage evidence, inventory, the device's own
custody and workload reviews, the qualification baseline and all eight FA
outcomes. Missing custody or another hard blocker is an exportable observation,
not a passed admission condition. The exporter does not perform inspection or
establish evidence sufficiency from a digest. Review must establish the meaning
of these bytes before the authority endorses them.

The service takes a **trusted, access-controlled local configuration**, not
uploaded client records. It pins the record's JCS digest, authority, tenant and
domain, and maps every exact-byte EvidenceRef digest to a local file. It verifies
and privately retains those bytes before serving the record. Unknown fields,
missing false conditions, duplicate JSON members, a missing FA outcome, evidence
mismatch and a full-qualification claim fail startup. Evidence is bounded to
1 MiB per file, as are records and HTTP responses. Larger raw captures stay in
private evidence storage; use a reviewed bounded observation derived from them.

Configuration fields:

| Field | Meaning |
| --- | --- |
| `authority_id`, `tenant_id`, `security_domain_id` | Exact deployment-owned record scope |
| `access.grants[]` | Exact mTLS URI `principal` and `transactions` array of permitted transport handles; the existing access helper's field name is reused, but these are observation handles, not provisioning transactions |
| `records.<handle>.path` | Reviewed adoption JSON file |
| `records.<handle>.digest` | SHA-256 of its JCS serialization |
| `records.<handle>.evidence` | Map of EvidenceRef digest to local retained-input file |

Transport handles use the existing narrow ID alphabet; record IDs keep the
contract's broader alphabet and never become filesystem paths. Each handle is
permanently bound to one record ID. Selection changes require restarting the
service with reviewed configuration; there is no record upload, approval, reload
or mutation endpoint. Removing a handle from the configuration denies its reads.

Run the packaged service with complete configuration:

```sh
kaiba-pilot-export --config /private/pilot/export.json \
  --state /private/pilot/export-state --listen 127.0.0.1:8097 \
  --tls-cert /private/pilot/server.crt --tls-key /private/pilot/server.key \
  --client-ca /private/pilot/readers-ca.crt
```

These are example paths, not a deployment command for the current bench. Deploy
with a separately reviewed service account, directories and trust roots. Keep
raw evidence, credentials and real configuration outside Git and build outputs.

## Retention and reads

All routes require verified client TLS and a per-handle grant:

- `GET /api/v1/pilot/records/{handle}/current`
- `GET /api/v1/pilot/records/{handle}/revisions/{revision}`
- `GET /api/v1/pilot/records/{handle}/evidence/{sha256-hex}`

Evidence URIs are opaque references, never remote URLs to fetch. Evidence reads
are scoped to bytes retained for that handle. All responses use `no-store`.
The state directory permits one writer, retains immutable revisions and evidence,
and rejects conflicting bytes, identity changes and revision rollback. Restart
with unchanged inputs returns exactly the same record and issuance time. The
author supplies a new revision for changed observations; an unchanged observation
cannot get a fresh revision/time merely to refresh its apparent age. Previous
revisions remain readable history, never the authoritative current selection.

## Consumer and tests

Fleet's matching `kaiba-pilot-preflight` resolves the current adoption, policy
and decision through separately configured mTLS authorities. It reads immutable
revisions and evidence, then checks current selections again. A result means
**consistent authenticated handoff, `membership: not_enrolled`**. It does not
issue credentials or approve enrollment. The policy authority and independent
consumer belong in `kaiba-fleet`; the development enrollment client remains separate. The
[pilot client](pilot-device-client.md) implements the pilot proof path.

Focused producer checks:

```sh
nix develop --command scripts/check.sh go ./internal/provisioning/pilotexport
nix build .#kaiba-pilot-export
```

Fleet's native `pilot-preflight` Nix check runs the actual exporter and policy
binaries with disposable PKI and two synthetic devices. It checks independent
bindings, unauthorized/third-device reads, source and reference substitution,
retained-evidence corruption, current decision withdrawal, outages and durable
restart. It builds no Pi images or kernels. It is a software handoff test, not a
real-device report or proof of PILOT-02–PILOT-06 runtime enrollment behavior.
