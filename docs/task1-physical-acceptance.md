# Task 1: development hardware completion

This task applies to the retained September 15 online-verifier candidate selected
for this campaign. Its 33-run/37-claim matrix does not establish admission for
the separately selected first-fleet design.

Use the already-owned development Pi for this task. Retain the September 15
signed verifier, release, signing receipts, campaign inputs and valid evidence.
Do not send this board through a fresh-device customer-key/EEPROM commit. Missing
ownership evidence is a blocker, never permission to recreate an ownership run.

## Current implementation and inventory

`scripts/task1-inventory.py` verifies the public descriptor's embedded byte
bindings and inventories its exact referenced configuration, staging plan and
four payloads. It prints a descriptive JSON report and never opens devices.
Run it again after restoring the retained handoff:

```console
python3 scripts/task1-inventory.py
```

The [October 2 inventory](../reviewed-candidates/development-pi5-task1-inventory-20261002.json)
records all six referenced store objects as missing on this host. This does not
establish their absence from private exports or another builder. Subsequent
read-only discovery recovered the retained signed verifier at
`/nix/store/327n9wwix9r7wz9v0m7s46ghzzkcrcv1-kaiba-verifier-signed-98999517-public-evidence`
and the delegated release at
`/nix/store/c8a8p6a20m1g773wq8xhzlv4qq76afjr-kaiba-development-pi5-delegated-release-20260915`.
The verifier's actual image/signature, historical receipt and attestation, and
unsigned manifest/intent/plan were independently revalidated. Its inputs match
the retained [native ARM candidate run](https://github.com/PseudoDesign/kaiba-provisioning/actions/runs/34932062738).
Both build lanes and the completion gate passed. The downloaded archive and
every listed file checksum were checked; its four reviewed public inputs match
this checkout. The selected root image also matches the original payload digest.
Offline verification accepted the positive and replacement delegated manifests,
including their component bytes, and rejected the revoked-key variant. These
are artifact checks, not physical campaign attempts.

The original unsigned native export was imported into a separate user-owned
inspection store. Both output NAR hashes match the original CI records. The
retained offline signing-verification constructor then produced all 12 public
handoff files byte-for-byte, without rebuilding the verifier or signing again.
The system Nix daemon's import restriction was retained; no global trust
setting changed.

The actual 27 public inputs, 10 byte-mutation targets and 20 authenticated
manifest variants reproduce campaign plan digest
`sha256:f913747c6e6959e6e8ce69c7c9974fe0187529eb70355e944c5a3ebcb3b4edbd`.
All four partition payloads now match the retained staging plan:

| Payload | Size in bytes | SHA-256 |
| --- | ---: | --- |
| Boot filesystem | 134217728 | `b8705f1ce178e6da6874db95cb3f7d46c6ed80a3b71a46dc47c036c0c7adff0f` |
| Root data | 2418016256 | `68ebaaad2985e13b445b0d71bc7f3ef16fa064e870ee561f367282f3b4a80313` |
| Root hash | 19050496 | `91c7c34db1449059d2293858415a0552f1c6b471443280f9303cd5efa3469469` |
| Release filesystem | 2548039680 | `dac60b6cb2f8e36b36ab708785b8b332c26ea641705311e0516e21b2793f4d8d` |

The regenerated root hash passes verity verification against the retained root
data, and its complete partition with the planned zero tail matches
`sha256:f27bfe6e09a466ea8d1a8092702db6c30685cba31402033050d00751716cd952`.
The release filesystem matches after copying the same source files densely
before the pinned ext4 packing steps. Sparse source allocation caused the
earlier reconstruction to produce different filesystem bytes; the rejected
copies remain separate. Independent rehashing of the accepted image and its
complete zero tail reproduces
`sha256:3636fc8c71dc2316b05cf81364611d9d03fd30a51b0f66dcd9b5245001abe3fe`.
No candidate digest or store path was overridden.

The existing offline input validator reverified signing/receipts and every
public release component. Its resolver accepted all 27/10 inputs and mutations.
The reconstructed artifact set matches the retained
`sha256:94d48ebe40a7494a294d1ab08b0c8a45b2551bc0a26f68ee65b0d704f75b5088`;
the same tools validated run 1 and run 2 materializations against actual bytes.
The staging-plan constructor also reproduced the exact embedded plan bytes
and original `sha256:ff0c6a94c29e5529bf7112bc58709246aad91dacfabc94ae019343a8b9aa430e`.
These recovered files do not register the six missing original store paths.
The original immutable package/path bindings remain missing. A separate
recovered-path proposal below binds the independently validated bytes to
new explicit immutable paths.

The initial native export identified a manifest generated before Nix stripped
the executable. [PR #99](https://github.com/PseudoDesign/kaiba-provisioning/pull/99)
corrected final-package hashing; its focused checks and x86/native ARM CI passed.
PR #100 added authenticated independent witness validation and passed both build
lanes. [PR #101](https://github.com/PseudoDesign/kaiba-provisioning/pull/101)
then committed the recovered immutable input bindings and merged as
`733bc29ecbf0a003f03b7eebf1cf3e882ba0110d`. The subsequent
[native ARM export](https://github.com/PseudoDesign/kaiba-provisioning/actions/runs/37085920334)
passed from that exact main revision. Its downloaded archive, committed
descriptor, runner/source provenance, final executable manifest and every
exported NAR hash, size and reference were independently verified.

The [recovered staging proposal](../reviewed-candidates/development-pi5-staging-recovered-20261002/README.md)
now has both complete staging runtimes. The accepted ARM assembly retains the
native CI component bytes and exact ARM dependency references. Its seven-object
closure was independently reimported and verified. The combined SD/NVMe and
descriptor archive contains 15 store paths, is 2,561,338,555 bytes and has digest
`sha256:9a6794e3886370194a5f0e9553eb7bd71f8c9783564f4cabd376140a746fde06`.
This packaging preserves the signed candidate, campaign and all payload digests.
The proposed current-NVMe identity still requires physical-plan review; software
merge/export approval does not authorize physical staging.

The operator selected and activated malak as separate runtime/recovery storage.
The [storage worksheet](../reviewed-candidates/development-pi5-staging-recovered-20261002/malak-storage.md)
records the USB-restricted NFSv4 server and completed client/server checks.
All 1,214 runtime files and 1,340 nodes were checked through the Pi mounts, and
the native ARM command ran through its exact fixed paths in a private read-only
Nix view. The global store was preserved. Staging-specific file operations
passed with a synthetic 64 MiB snapshot; its complete digest matched a fresh
client cache and independent server readback of all ten qualification files.
These results qualify backing storage and runtime access, not recovery backups
or hardware claim closure. Revalidate the observed setup before preparation.

The five protected public media receipts were exported, independently rehashed
and reconciled. Their stage/verification receipt digests and paired bindings
are internally consistent, but their historical plans are not this campaign's
plan. The v0.1.6 geometry matches the current SD; v0.1.5 uses a different size.
All records describe media operations with no one-time settings changes or
cold-power observation. They cannot establish original ownership completion or
current campaign acceptance. The bounded root filename inventory found no
ownership directory beneath `/var/lib/kaiba-provisioning`; it does not establish
absence from other retained locations. Original ownership operation and
terminal records still require recovery and independent review. The earlier
receipt-export helper is superseded by this completed export and need not run.

A subsequent operator filename search listed 547 files within the protected
signing/review homes, signing exports and retired registry. It exposed public
signing inventories and files for four signed owned-recovery bundles, but no
original ownership completion record or actual authority TLS server certificate
in that depth-limited listing. These are filename observations; signing and
recovery artifacts do not establish that an ownership operation completed.
The administrator completed two separately retained public exports: the first
copied 36 listed artifacts and inventoried deeper handoffs without following
symlinks; the second copied three newly located public qualification records
and the v0.1.4 boot-signing result. All 40 copies were independently reopened
and rehashed against their protected source observations; both exports report
zero source errors. No private probes, synthetic fixtures or private keys were
exported, and neither helper accessed the Pi or authorized media/power operations.

Offline review verified all four owned-recovery signatures, their fresh EEPROM's
three embedded customer signatures, and exact plan/result/image/metadata
bindings. The v0.1.5, v0.1.6 and v0.1.15 exports each authenticate all five
receipts against an independent registry and the receipt digests from the
separate boot, EEPROM and owned-recovery signing results. The v0.1.4 boot result
was recovered, but its independent registry snapshot remains unlocated; its
full receipt-export validation stays open. This historical limitation does not
invalidate the verified v0.1.15 recovery artifacts. Twenty-five focused negative
checks rejected truncated/altered recovery, wrong keys/plans, and missing,
wrong or altered receipt evidence. No signing, candidate rebuild or updater
replay was repeated. These checks establish artifact validity, not physical
ownership or recovery success.

The historical v0.1.5/v0.1.6 hardware records describe an unset customer key,
no successful mutation and no independent EEPROM hash. Their target fingerprint
matches one independently derived by the existing metadata parser from the
retained September 18 owned readbacks; those readbacks also correlate with the
current authenticated serial suffix, board revision and customer-key hash.
That connects historical observations to this board without proving the
original ownership operation. The v0.1.6 lane record binds its hardware record's
exact digest and describes an operator-attested manual development rehearsal;
it explicitly lacks automated fail-off and electrical measurements. Its earlier
topology does not qualify the current shared USB hub. Approved campaign hardware
and witness bindings, original ownership and current safe-off remain open.

The complete public review is retained at
`/home/codex-remote/kaiba-private/task1-physical-acceptance-20261002/public-recovery-review-closeout-20261003`.
Its 163-file manifest includes all exports, 111 exact verification source files,
review results and tool provenance, under digest
`sha256:d350bdcce0c4647fa971b6e7549efd8a507a7b417bce5fc401686f5e2b917d8e`.
The separate historical target-correlation manifest is
`sha256:ceeab969629fbce377aa3f4819ab845466794ca6fdd950f4e7da8d60e04e9a90`.
See the [October 3 status record](../reviewed-candidates/development-pi5-staging-recovered-20261002/status-20261003.json)
for exact export and retention bindings. Keep original preparation manifests
and all reconciliation records; do not rerun the completed one-shot collectors.

The operator authorized and performed a power cycle with UART capture active.
The capture identified serial `e03fbfb95a4265ae`, revision `a04171`, and the
`kaiba-rpi5-provisioner` OS. Its secure-boot image digest matches an independently
hashed and RSA-verified retained development provisioner. The current SSH key
was compared byte-for-byte with the UART fingerprint before USB SSH access,
following the [development-access procedure](raspberry-pi-5-development-target-access.md).
Host `usb0` uses the operator-added temporary `10.0.0.1/24` peer address. The
Pi is on hub port 2 and the debug probe on port 3. Each later boot needs a new
UART comparison because the target's SSH host key is ephemeral. The earlier
LAN address `192.168.8.208` is not the authenticated USB endpoint.

Read-only inventory found these setup blockers:

- The system reported March 17–18, 2026, while the RTC reported January 1, 1970;
  neither is suitable for the retained CA's September 15–October 16 validity
  interval. RTC/power-retention qualification remains open.
- The retained authority endpoint `192.168.8.249:8443` refused the TLS connection.
  Its actual server certificate and availability remain unverified. The
  documented server expiry is October 15, 2026 at 04:07:11 UTC.
- The observed bootloader release is `a8698392` dated September 12, 2026.
  Approved EEPROM/profile bindings and repeated owned readback remain open.
- The identified bootloader-public-key provider exposes 264 bytes with SHA-256
  `b8818acea4e71173903ee003e33ed37e969def7d2ea67bec15c0b73cb36c3895`, matching
  the development customer key. Historical September 18 RPIBOOT metadata and
  its original stdout/stderr hashes also match this board and key. The later
  post-update record explicitly lacks an independent EEPROM hash. The current
  running-OS observation is correlation evidence; neither it nor the later
  update records establish original ownership completion. No private OTP
  rows were read.
- NVMe now has five partitions, including `KAIBA_LUKS_DEV` and
  `KAIBA_OFFLINE_DEV`, under disk GUID `b268f110-7d11-47c7-9bcc-2c4b480e4404`.
  The existing provisioner's read-only tool captured and revalidated a fresh
  v1alpha2 envelope, including hashes of all six recovery ranges. Its disk
  identity differs from the retained plan's `bb5289ea-2c0b-424f-a4c7-23c8fdf1ebae`,
  so that original cross-binding must reject it. A separate file-only proposal
  uses the observed GUID and rerenders GPT under plan digest
  `sha256:fab535df53ce4204d99e787c449e072971f0d88eac504a63ee67a470a7d1c766`.
  An independent contract check confirms the proposed NVMe identity/ranges
  match the capture, while campaign, payloads, partitions and geometry match
  the retained selection. Operator review is required before adopting it.
  No GPT was repaired or written, and no recovery backup bytes were captured.
- The SD's fixed host selector is absent while the card is in the Pi. Its
  inactive host attachment, fresh v1alpha2 capture and protected backups remain
  open. No complete SD/NVMe recovery catalog can yet be produced.

The [access snapshot](../reviewed-candidates/development-pi5-task1-access-20261002.json)
is descriptive. Raw UART, board observations and the original native artifact
were retained outside Git in
`/home/codex-remote/kaiba-private/task1-physical-acceptance-20261002`, with private
permissions and independently reopened copy hashes. The `recovered-public`
subdirectory retains 80 public verifier, plan/input and matching media files;
its retention manifest digest is
`sha256:88f0960ee98063f0db427e5b9fed153b62279063dc948f829ffdfa9ad2acd463`.
The `owned-state-correlation` subdirectory retains 14 public metadata/observation
files with manifest digest
`sha256:ad3a5be6629fc2bbc7bc89afb4f2fdc400bdc26bac86020178b89748d77b55ad`.
The `payload-and-gpt-completion` subdirectory retains the matching release
image and six supporting public records, with manifest digest
`sha256:8e7187da9e67260b8f620e3dd15fe387b2d1d5e9fb74c258e416bf09dccd5e26`.
The `planning-reconciliation` subdirectory retains 16 validation and proposed
plan records, with manifest digest
`sha256:ed695aeb1ccc4d577c99e19e64e5061bbf7714680a2c64c1ecd451e9b612901f`.
The `native-staging-export-36c910c` subdirectory retains 16 export, provenance
and independent-validation files, with manifest digest
`sha256:e95d19c1771ce6e39a4e424619368936166f638d2f58ca69fc09720dee56e25f`.
The `staging-package-preparation-c4b9dcf` subdirectory retains 16 package,
archive, provenance and validation files, with manifest digest
`sha256:52ce4d75fd5ee9c36c67057d93dc0731dba1e45a8e6b1e820d6fc20eea9bea73`.
Its review-file copies record the proposal before the later storage worksheet
and task/access documentation updates.
The `native-staging-export-733bc29` subdirectory retains the final native export
with manifest digest
`sha256:0ffbe9c3b7a0c6cd7bd9cc7466af37b7927119f81c0e8ff88171e3607dcdfe63`.
The `complete-staging-runtime-733bc29` subdirectory retains the verified complete
runtime archive with manifest digest
`sha256:e8c89d8c22ee7b1c41d89ad5ebaba6fef85f3924af77251b1afbbea81958281b`.
Its never-activated draft storage packet is superseded by the separate retained
activation/completion packets. The `storage-qualification-closeout-733bc29`
subdirectory retains seven final readback, historical receipt and reconciliation
files, with manifest digest
`sha256:ed2cd5c58acf2ce800f09428f36ae70fb2aee298b1c209522118ed3d98c013b5`.
The [October 3 status](../reviewed-candidates/development-pi5-staging-recovered-20261002/status-20261003.json)
binds completed preparation and outstanding physical gates.
All copies were reopened, compared and synchronized with their directories.
This access observation
does not establish complete cold-power removal, safe-off behavior, EEPROM/OTP
readback or a campaign run. No media staging or EEPROM/OTP operation was
performed. Task 1 and physical claim closure remain open.

## Independently reviewed witness interface

`kaiba-rpi5-stable-campaign-qualify` adds a separately versioned interface for
authenticated collector and independent-reviewer testimony. It preserves the
existing v1alpha2 execution envelope and consistency-only checker, including
the legacy fail-closed `RequirePlannedClaimClosure` API.

The new library prepares an opaque expectation by resolving all 27 public
inputs and 10 mutation targets, cross-checking the baseline/materialization,
rendering the fixed GPT layout, and hashing the actual four run payloads plus
their complete zero tails. Device fingerprint and approved-profile digest must
come from independently reviewed inventory. Descriptor labels, a hostname and
a device path do not authenticate the board or a native build.

The admission authority selects a fresh random capture ID and a bounded
session before collection. Its session binds the exact board, profile,
expectation, campaign, run, and capture. Public trust keys are configured
independently of submissions and scoped to collector/reviewer roles and
specific witness kinds. A key cannot hold both roles. Neither this tool nor
the library generates production witness keys or performs signing.

For each required witness, collect the exact supporting public bytes listed
by `prepare`. The collector and independent reviewer sign the same statement
using different role-specific preimages. The reviewer must verify the
requirement's substance: release/signature/build provenance, physical capture
provenance and completeness, signed authority exchanges, actual acceptance
and rejection of the identical replay, and observed released-stage behavior.
Opaque supporting transcripts are not automatically verified as firmware or
authority signatures by this interface. A signed unrelated success message is
not a substitute for the required source roles.

Validation rechecks the complete raw evidence and expected verifier trace,
independently resolved policy/manifest digests, exact media hashes, every
supporting file's size/hash, both signatures, scope and session time. It also
checks the expected/observed command line and byte equality of replayed proofs,
bootstrap requests, authorization transcripts and pre/post handoff FDT
invariant projections. FDT inputs must be the reviewed canonical invariant
projection, not raw DTBs whose unrelated runtime properties can differ.

The resulting assurance is `authenticated-independent-review-testimony`.
It authenticates named reviewers' conclusions and capture provenance under
the configured trust policy. It does not provide hardware attestation,
automatically prove the truth of an operator observation, authorize execution,
or assert production/enrollment readiness. `ReviewCampaign` accepts exactly
33 opaque validated run reports, totaling 37 reviewed claims, for one frozen
board/profile/baseline/layout/trust policy. It never sets `security_applied`.

## Command interface

The Nix package exports the same command on native x86 and ARM Linux:

```console
nix build --no-link .#kaiba-rpi5-stable-campaign-qualify
nix run .#kaiba-rpi5-stable-campaign-qualify -- prepare \
  --request /absolute/protected/campaign/qualification-request.json
```

The request is canonical JSON in this field order:

| Field | Value |
| --- | --- |
| `plan`, `baseline`, `materialization`, `layout` | Absolute regular-file paths to the campaign plan, baseline artifact set, selected run materialization and baseline staging layout |
| `public_inputs` | Map of the exact 27 plan names to independent source files |
| `byte_mutation_targets` | Map of the exact 10 plan targets to positive source files |
| `payloads` | Map of all four roles to this run's actual payload files |
| `device_fingerprint`, `profile_digest` | Independently reviewed SHA-256 inventory bindings |
| `result` | Absolute path to the v1alpha2 execution result; empty during preparation |
| `raw` | Required raw-role to file-path map; empty during preparation |
| `witnesses` | Signed witness paths in the exact order emitted by preparation; empty during preparation |
| `supporting` | Supporting source-name to file-path map; empty during preparation |

Map keys use Go's canonical JSON ordering. Empty maps/arrays should encode as
`{}`/`[]`. Parent symlinks, symlink files, FIFOs, devices, oversized files and
changing file metadata are rejected. Sources stay stable throughout hashing.

`prepare` emits the expectation and each required witness's source names. It
does not authenticate build provenance, collect observations or authorize
staging. Create the independent session/trust files using the exported
`Session`/`TrustPolicy` Go types. An unsigned witness envelope can have an
empty signatures array while its public signing preimage is prepared:

```console
nix run .#kaiba-rpi5-stable-campaign-qualify -- preimage \
  --witness /absolute/protected/campaign/witness.json --role collector
```

Repeat for `independent-reviewer` with the independent signer. Signatures are
64-byte Ed25519 values encoded as lowercase hexadecimal; trust public keys
are 32-byte lowercase hexadecimal. A statement contains `schema_version`,
`session`, `result_digest`, `kind`, `conclusion`, `collected_at`, `reviewed_at`
and `evidence` in that order. The sole accepted conclusion is
`independently-reviewed-satisfied`. Evidence entries contain `name`, `digest`
and `size_bytes`; they cover the exact complete submitted public bytes.

```console
nix run .#kaiba-rpi5-stable-campaign-qualify -- validate \
  --request /absolute/protected/campaign/qualification-request.json \
  --session /absolute/protected/authority/session.json \
  --trust-policy /absolute/protected/authority/witness-trust.json \
  --admission-directory /absolute/protected/authority/capture-admissions
```

Session and trust inputs belong to the admission authority, not the submitter.
The existing admission directory must be mode 0700 and owned by the admission
process. Protect it from submitter modification and retain it across restarts.
Successful validation durably consumes the capture nonce using exclusive
creation and file/directory synchronization. A duplicate or uncertain
reservation is never reset. If stdout is lost after admission, preserve the
inputs and reservation for independent reconciliation; do not erase the
ledger or repeat physical operations. The command emits no report on failure.

## Remaining physical sequence

1. Recover the retained complete handoff and original ownership evidence;
   verify signatures, native CI provenance, current owned board identity,
   EEPROM state, approved profile and storage authorization.
2. Review the exact lane, UART, safe-off and load-tested power topology. Check
   the actual authority certificates and Pi RTC; the retained server
   certificate's documented expiry is October 15, 2026.
3. Bind fresh SD/NVMe v1alpha2 envelopes to the reviewed plan. Use separate
   host-bound staging candidates for both legs to capture and independently
   reopen every required recovery range, including both SD GPT lineages.
4. Present the concrete previews, verified backups, immutable packages and
   stop/recovery procedure for existing explicit execution approval. Then
   execute once and independently read back all four complete partitions.
5. Run the positive baseline and authority-offline rejection on identical
   verified media. Capture before power-on and retain released-OS, command
   line, FDT, exact replay, authority and physical-power witnesses.
6. Complete the existing 33-run matrix, signed owned recovery, negative
   boot/recovery sources, repeated customer-key/EEPROM readback and dm-verity
   rejection tests. Preserve ambiguous outcomes for reconciliation/quarantine.
7. Restore and independently verify baseline media. Independently review
   the full campaign plus owned-state evidence, receipts and control/audit
   state. The existing seven-operation terminal contract alone determines
   whether `security_applied` can be recorded.

## Validation

Run focused Go checks for `campaignqualification`, the qualification command,
`stablecampaign`, `campaignmedia`, and `campaignpacket`. The existing native
packet integration check also constructs the new expectation from real test
artifact bytes and compares its complete partition hashes independently.
Synthetic signature tests cover every run/claim, missing and altered captures,
wrong board/profile/run/capture, forged or role-reused keys, expired sessions,
wrong command lines, nonidentical replay/FDT inputs and concurrent durable
nonce admission. These checks establish software behavior, not physical gates.
