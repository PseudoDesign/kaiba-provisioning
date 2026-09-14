# Stable-campaign recovery preparation

The `v1alpha2` recovery-requirements contract connects the current SD/NVMe GPT
inspection output to an independently supplied stable-campaign staging plan.
It is a descriptive catalog: it does not back up bytes, authenticate device
attachments, approve an operation, or enable a physical writer.

## Bind the captured records

Use canonical JSON from the existing staging-plan construction and explicitly
selected `--envelope-version v1alpha2` inspection. Keep actual captures and
recovery material in the operator's protected evidence directory outside Git.

```console
nix run .#kaiba-rpi5-stable-campaign-recovery-requirements -- \
  --staging-plan /absolute/protected/campaign/staging-plan.json \
  --sd-envelope /absolute/protected/campaign/sd-envelope.json \
  --nvme-envelope /absolute/protected/campaign/nvme-envelope.json
```

The command reads bounded regular JSON files and emits one canonical catalog
plus a newline on stdout. It rejects duplicate arguments, noncanonical JSON,
v1alpha1 captures, swapped or mismatched device legs, and detached plan or
capture bindings. Diagnostics go to stderr; an invalid input produces no
catalog. All three file arguments must be canonical absolute paths.

Each device entry retains its complete v1alpha2 envelope, alongside the
staging-device digest. This preserves the primary-selected SD lineage, its
distinct physical-end backup copy, the NVMe placement policy, exact recovery
range purposes, and their version-specific digests. The catalog is not a
conversion to the legacy v1alpha1 contract; that contract remains supported
separately and continues to reject v1alpha2 inputs.

Go consumers use `NewRecoveryBackupRequirementsV1Alpha2` and
`ParseRecoveryBackupRequirementsV1Alpha2`. After parsing, call
`ValidateAgainst(plan, envelopes)` with the independently supplied records to
check their complete binding. A catalog digest establishes consistency of its
contents, not the provenance of a hardware observation.

## Remaining staging boundary

The catalog retains the fixed outstanding requirements for durable recovery
capture, independent reopened backup readback, fresh attachment revalidation,
explicit operator approval, and a separately reviewed writer. Its backup,
approval, block-device-write, and destructive-staging flags are all false;
`ValidateForDestructiveStaging` always rejects it.

The [first physical baseline](first-physical-baseline.md) requires those
capabilities and independent complete-partition readback before a physical
attempt. Successful catalog construction does not authorize GPT repair,
signing, storage writes, or power operations.

The separate [regular-file sandbox](stable-campaign-sandbox.md) now implements
and tests the recovery/write sequence on synthetic disk copies. Its reports
and rehearsal acknowledgement do not satisfy this contract's physical gates.

## Software validation

```console
scripts/check.sh go ./internal/provisioning/campaignmedia \
  ./cmd/kaiba-rpi5-stable-campaign-recovery-requirements
scripts/check.sh contracts stable-campaign-recovery-requirements
```

The Go tests cover both lineage preservation and malformed, mismatched,
reordered, and transplanted inputs. The focused Nix check validates the
packaged entry point and its declared descriptive boundary. Neither requires
a Pi or signing token.
