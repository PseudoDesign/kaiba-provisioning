# Offline storage development

The offline storage helper runs once at boot to create an encrypted private test
record or reopen and authenticate it on the next boot. It reuses the remote
storage helper's firmware-HMAC counter KDF, LUKS implementation, memory protection
and cleanup. Its automatic boot service and saved-capture assessor are software
capabilities. The [2026-09-20 physical observation](observations/2026-09-20-offline-storage.md)
records original-device offline create/reopen across a guided cold-power cycle;
lock rejection and copied-media protection remain pending.

This is a **development experiment**, separate from the
[qualification harness](device-secret-target-harness.md). It does not run raw-key
reads, signing or post-closure rejection probes and cannot satisfy those checks.
The [lock-rejection evidence decision](device-secret-rejection-evidence.md)
remains open. Both qualification flags remain false even when storage passes.

## One image, two boots

`lib.mkRpi5DeviceSecretOfflineStorage` accepts `experiment`,
`expectedCustomerKeyHash` and `sourceRevision`, like the existing experiment image
constructor. Its experiment contains the same closed public configuration fields
as [remote storage development](device-secret-storage-development.md), with schema
`kaiba.device-secret-storage-offline-development/v1alpha1`.

The module `device-secret-offline-storage` requires a signed read-only verity root,
no development login, no swap or core dumps, and no remote login or network-time
services. It requests the existing boot-time raw-read/key-write restrictions and
loads `dm_crypt`. The constructor disables networking; the helper also checks
runtime link state. Physical network isolation and power-off conditions still need
separate evidence. The image evaluation check requires the exact same kernel
derivation as the baseline native offline image.

The service invokes `--run-reviewed-experiment CONFIG` automatically, with no
phase argument, network fetch or host-supplied secret:

1. The exact backed-up disposable 65 MiB partition must be entirely zero for
   creation. A validated empty journal selects `create`.
2. A completed create journal selects `reopen` on a different boot. It binds the
   same configuration, signed boot-image digest and verity root.
3. Completed, interrupted, mismatched or unexpected journals stop before firmware
   operations. There is no third run, reset, retry or format override.

Each phase permits at most two HMAC derivations and two volatile lock writes:
apply READ/GEN/USAGE restrictions, derive the LUKS and record-authentication keys,
verify storage, then close all five runtime operations. Results distinguish
volume verification, journal completion, mapping cleanup and reported lock state.
The helper has a per-boot one-shot marker; systemd never restarts it automatically.
Failure requires reconciliation, not another power cycle to retry.

A completed remote session cannot be reused here: its journal is consumed, uses a
different schema and binds the inspection image. Preserve that evidence and
prepare a fresh experiment under exact backup/write authority. The boot-time
helper and public configuration must be in a newly reviewed signed image. RAM
uploads to the inspection system disappear at power loss.

## UART results and assessment

The service disables competing serial gettys and console journal forwarding. The
helper emits one bounded line beginning `KAIBA_DEVICE_SECRET_STORAGE_RESULT=`
with schema `kaiba.device-secret-storage-offline-result/v1alpha1` and mode
`offline-development`. Synthetic VM results use `synthetic-offline-development`
and are rejected by the production assessor. Early failures can report phase
`unknown`; they are not successful create or reopen observations.

Use complete bounded captures, including output after the result, collected by a
separately reviewed passive capture procedure. The assessor never contacts the
Pi, captures UART, operates power or grants execution authority:

```console
nix run .#kaiba-offline-storage-assess -- \
  --plan /absolute/private/capture-plan.json \
  --create-capture /absolute/private/create.uart \
  --reopen-capture /absolute/private/reopen.uart
```

The closed plan has `schema_version: kaiba.offline-storage-capture-plan/v1alpha1`,
`boot_image_sha256`, `verity_root_hash`, `volume_uuid` and `nonce_hex`. Digests and
the public nonce are nonzero lowercase 64-character hex strings; the volume UUID
is canonical and nonzero. These bindings must come from the reviewed candidate,
not be inferred from an untrusted capture.

The assessor requires one complete successful record per capture, exact image,
root, volume and nonce bindings, create/reopen ordering, different boot IDs and
all cleanup flags. Missing, duplicated, interleaved, malformed, oversized,
synthetic, failed or mismatched records reject the pair. Raw captures stay private.
Success means `matched-target-reports`, not authenticated audit evidence. It
always reports `cold_power_verified=false`, `physical_isolation_verified=false`,
`hardware_qualified=false`, `lock_rejection_qualified=false` and
`execution_authority=false`. Manual off/isolation acknowledgements remain separate
operator evidence; neither a changed boot ID nor link-down proves cold power.

## Build and execution boundaries

```console
nix develop --command scripts/check.sh contracts \
  device-secret-storage-development device-secret-offline-storage-eval \
  device-secret-offline-storage-vm
```

The VM uses synthetic firmware with real LUKS/device-mapper storage to check
boot-time create/reopen, consumed and incomplete journals, changed bindings,
derivation/unlock/cleanup failures and missing crypt support. It supplies no
hardware or physical-isolation evidence. Native ARM CI runs these software checks
without changing the platform kernel or producing an authorized hardware image.

Before physical use, prepare one exact candidate and signing request, refreshed
backups and bounded media writes, and a boot-selection/return-to-management route
that works across full power removal with NVMe installed. SD-first boot and
`tryboot` alone do not establish that route. A guided manual session needs two
isolated cold boots and a management return; account for PoE, USB data power and
UART back-power. No signing, staging, power cycle or secret operation is implied
by building the package or assessing captures.
