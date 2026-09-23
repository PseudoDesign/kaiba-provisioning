# Ace adoption and first fleet bootstrap

Status: **selected implementation direction; production profile draft**.
Ace is the first production target. The existing development Pi becomes the
provisioning station; malak hosts the initial authorities and separate signer.
After admission, Ace hosts the first fleet services. This plan defines work and
acceptance gates, not a hardware result or an executable authorization.

The [delivery scope](delivery-scope.md), [FA-01–FA-08](fleet-admission-policy.md)
and [enrollment handoff](enrollment-handoff.md) remain authoritative. Offline
local operation and copied-storage protection remain required; offline rejection
of older correctly signed software remains outside the selected requirements.

## Profile draft and initial evidence

Use `ace-fleet-infrastructure-v1` as the working profile label. This is a design
label, not a registered runtime profile. Before execution, compile the selected
values into reviewed, versioned inputs with exact digests; before admission,
establish their effective state on the bound device. A hostname or serial number
alone does not authenticate that device.

| Profile field | Direction | Decision or evidence still required |
| --- | --- | --- |
| Subject and role | Adopt the existing Ace Pi 5 as the first fleet infrastructure host. | Authenticated inventory, exact board/storage binding, existing workloads and data-retention decision. |
| Boot ownership | Use an approved production customer root, separate from development signing trust. | Effective customer-key/secure-boot state; exact approved root, custody and recovery. Do not assume the board is unfused. An incompatible fused root blocks this profile. |
| System software | Native signed boot and dm-verity; immutable system code separated from mutable service data. | Exact firmware, release, boot sources, root hash, update/recovery images and permitted-image qualification. |
| Storage secret | Propose retaining Ace's existing OTP device secret under `ACE-EX-01` below. | Custody/history review, independence, supported HMAC operations and applicable secret/lock evidence. This path omits device-secret programming; boot-root changes have separate authority. |
| Protected state | Qualify firmware-HMAC-derived LUKS2 unlock for operational credentials and private service data. | Migration/partition plan, derivation purpose, key slots, recovery, cold reopen, copied-media rejection and plaintext escape checks. |
| Operational identity | Generate a fresh device key in protected state; fleet assigns the canonical identity. | Production issuer/audience configuration, bound proof, final-restart verification and activation. The OTP secret is not the fleet identity. |
| Final access and locks | Apply the production boot/debug/EEPROM settings and approved operational management access. | Exact values and post-restart observations; remove provisioning-only access before admission. |
| Service role | Run fleet API/inventory on Ace after admission; separate device, service and operator credentials. | Least-privilege service roles, persistent data and backup/restore policy. CA private keys, release-signing keys and station-admin credentials stay outside Ace. |

The [deployment repository's encryption upgrade guidance](https://github.com/PseudoDesign/nix-pseudo-design/blob/82c39216c933a038058de0024b7e5dc085b31d63/README.md#encryption-scheme-upgrades)
documents legacy HKDF unlock for Ace; its
[shared module](https://github.com/PseudoDesign/nix-pseudo-design/blob/82c39216c933a038058de0024b7e5dc085b31d63/modules/hardware/rpi5-luks.nix)
defaults to `legacy-hkdf-v1`. That source describes intended configuration,
not fresh hardware evidence. Inventory must establish the running path. Changing
the option alone is not a safe migration or proof of firmware-HMAC boot.
Keep the adoption configuration specific to Ace; changing shared defaults must
not migrate Mako or other hosts as a side effect.

Retain existing encrypted data and unlock metadata until their disposition and
recovery are reviewed. A new image, filesystem layout or keyslot removal requires
its own exact migration and restoration plan. Do not run the destructive fresh
installer against an adopted volume. Reuse applicable experiments by exact
hardware/software/mechanism binding; a temporary-container comparison cannot
establish Ace's shipping boot, credentials or recovery behavior. No private
captures, device identifiers or new experiment results are published by this plan.

## ACE-EX-01: existing device-secret reuse

Proposed scope: **accept the existing device secret's creation outside Kaiba's
new-device ceremony and omit repeat secret programming for this one target**.
The OTP secret used to derive an unlock credential, the LUKS volume/key slots,
the secure-boot customer root and the operational fleet key are distinct inputs.
An already programmed storage secret does not establish boot ownership and must
not cause an invented successful ownership or secret-programming operation.

The proposal is not yet an accepted per-device exception. Its review record must
bind the exact authenticated target, profile revision, observed prestate,
applicable release/mechanism, scope, rationale, historical evidence and unknowns,
custody assessment, approver, approval time, validity and invalidation conditions.
Changing the target, secret history or relevant protection assumptions requires
review again. Store references and outcomes, never secret bytes or a raw-key
read masquerading as inventory.

Acceptance of `ACE-EX-01` does not waive FA-04. Establish independent secret
material, the intended unlock path, required locks, protected credential storage,
offline reopen, copied-media rejection and authorized recovery. Document possible
retained or exposed key material; adding locks does not undo prior disclosure.
Known conflicting ownership, duplicated secrets or unresolved exposure that
defeats the selected protection blocks this profile. If accepting a risk would
waive an FA condition, it requires a separate explicit policy decision; it cannot
be presented as compliance with this unchanged first-fleet policy.

Track observation outcomes and exception decisions separately. An accepted
historical-process exception is not a passed hardware check. It cannot clear
missing evidence, quarantine, pending enrollment or production-readiness flags.

## Station and authority placement

| Host | Planned responsibility | State and trust boundary |
| --- | --- | --- |
| Development Pi | Touchscreen browser, loopback station relay, campaign controller and fixed-lane physical executors for Ace. | Dedicated station configuration, persistent private journal and scoped station/lane credentials. The browser accepts only reviewed inputs and actions. |
| malak | Initial control/audit/export authorities, fleet registration/inventory service and separately isolated production issuer/signing integration. | Persistent stores, exact grants, independent operator/approver identity, explicit trust roots and protected backups. Signing custody remains separate from the station. |
| Ace | Provisioning target, then operational fleet member and service host. | Protected device credentials plus separately scoped service identities and encrypted database state. Hosting services does not grant self-admission or signer authority. |

These are new deployment roles, not permission to repurpose existing development
credentials or live services. The development Pi's boot root need not become
Ace's root, but the station is a trusted authority in this model: review its OS,
allowed software, administrative access, credential custody and recovery. Replace
the RAM-backed inspection setup with a dedicated persistent station deployment
before relying on its journal across reboot. Preserve existing experiments and
media until a separate migration plan covers their disposition.

Bind USB/UART/power selectors to the new Pi-to-Ace lane. A selector previously
valid on malak is not transferable. Qualify power control and backfeed behavior
under the existing [lane requirements](production-readiness.md#lane-power-and-topology);
manual development mode does not acquire production status through this plan.
Station software and disposable service tests can proceed while this gate is
open. Select the production power arrangement before its physical campaign.

Reuse the [guided campaign proposal](https://github.com/PseudoDesign/kaiba-provisioning/pull/65)
for the screen: target, current step, bounded inputs, recorded result, next action
and diagnostic export. The controller owns progress, records intent before each
operation and reconciles uncertain outcomes after restart. Selecting an exception
on the screen is not approval. An approved record must be resolved and verified
by the authority; the UI cannot override a blocked condition.

## Bootstrap and transfer to Ace

Use one production authority/inventory initially hosted on malak. Select its real
issuer, trust roots, namespace, roles and policy before issuing production
credentials. The disposable rehearsal CA, test audience and development client
mode remain test-only; changing a hostname does not promote them to production.

1. Prepare and qualify Ace using the station and external authorities. Bind the
   adopted prestate and approved reuse decision to the new provisioning record.
2. Generate the new operational key on Ace's protected volume. Complete fresh
   bootstrap proof and staged issuance; routine fleet access remains denied.
3. After the final required restart and hardware observations, verify the
   installed key and current admission prerequisites. Atomically activate the
   exact tuple on the external authority, then check fleet authentication.
   Complete FA-08 and the final report from these results; do not require that
   future completion report as a prerequisite for its own activation.
4. Enable the approved fleet API/inventory service release on Ace. Include its
   reviewed binaries in the initial protected system image, disabled until this
   step; mutable service data must not select arbitrary executable code. A later
   code change follows the approved update and evidence-revalidation procedure.
   Preserve the same logical authority, issuer trust, identities, revisions and
   membership history. Provision distinct server/service credentials; do not reuse Ace's
   device credential as a service administrator or CA key.
5. Test backup restoration, quiesce the old writer, take and verify the final
   durable snapshot, transfer it to protected state, and make one instance
   authoritative. Verify pending/revoked denial, existing identity continuity,
   retries and new enrollment against the transferred service before retiring
   bootstrap credentials and access on malak.

Plan cutover so two writable registries cannot admit conflicting identities. A
failed transfer keeps or restores one authoritative writer. Once Ace accepts new
writes, rolling back to a stale malak snapshot is not recovery: reconcile current
state first and preserve revocations and issuance history. Keep protected backups
and an external operator recovery route usable when Ace is unavailable. Loss of
fleet connectivity must not disable devices' normal protected local functions.

Fleet CA and release-signing private keys remain external after this transfer.
The service on Ace requests issuance under an independently scoped identity.
The initial production CA integration and its custody policy are still open work.

## Implementation slices and ownership

The steps below are planned. Each should be independently reviewable; finish its
software rehearsal before scheduling dependent physical work. No implementation
PR can close an unperformed physical check.

| Slice | Deliverables and owner | Acceptance and dependency |
| --- | --- | --- |
| 1. Inventory and profile binding | Provisioning: authenticated, read-only Ace inventory; explicit secret-reuse review record; exact production profile draft and gap report. Deployment configuration is maintained in `nix-pseudo-design`. | Distinguish observations from intended values, preserve unknowns and authenticate the target. Read metadata only; no raw secret reads, HMAC/signing calls or mutations hidden in inventory. Root eligibility, data disposition and custody decisions block dependent changes. |
| 2. Adoption record and consumer policy | `kaiba-provisioning`: durable adoption prestate, approved-decision references and evidence export. `kaiba-contracts`: reviewed shared semantics/version and conformance. `kaiba-fleet`: independent verification and production admission policy. | No fabricated fresh-device operation. Wrong-target, expired, altered or unknown exceptions and absent evidence are rejected. Producer and consumer pin the same reviewed contract. Can proceed with synthetic fixtures while hardware decisions remain open. |
| 3. Station and bootstrap deployment | Provisioning supplies ARM packages and fixed executors; `nix-pseudo-design` composes the station and bootstrap hosts; `kaiba-fleet` supplies the service and issuer interface. | Browser/station/controller/service restart recovery, durable stores, authenticated roles and fixed-lane checks pass. Production issuer/custody and power qualification gate real execution, not package/service development. |
| 4. Ace protection and enrollment | Provisioning supplies the exact signed release, migration/recovery packet and acceptance campaign; fleet performs pending verification and activation. | All required device checks, encrypted credential cold reopen and negative/recovery cases pass for the selected profile/release. Activation rejects a blocked/quarantined or conflicting tuple. Depends on slices 1–3 and operation-specific authority. |
| 5. Fleet service transfer | Fleet owns registry/issuer semantics; `nix-pseudo-design` owns Ace service deployment and protected data; provisioning retains its report. | Single-writer cutover and backup/restore preserve exact identities, receipts, revocation and pending states. Ace's service release is covered by its approved boot/update policy. Depends on Ace's admission and transfer rehearsal. |

The current [control creation contract](../internal/provisioning/controlplane/validation.go)
requires an all-zero **customer boot-key** prestate; that field says nothing
about an OTP storage secret. Inventory determines whether a genuine fresh
boot-root operation is applicable to Ace. If Ace already owns the approved boot
root, implement an explicit adopted-owned path rather than feeding invented
zero prestate into this API or pretending the ownership operation ran. In both
cases retain signed boot, owned readback, recovery, repeated readback, negative
boot/recovery and root-integrity evidence. Fresh-device behavior stays intact.

The current [exporter](fleet-export.md) only produces development candidate
evidence; the [device client](device-enrollment-client.md) is development-only.
The [protected-state extension](https://github.com/PseudoDesign/kaiba-provisioning/pull/64),
guided campaign and [fleet client rehearsal](https://github.com/PseudoDesign/kaiba-fleet/pull/2)
are reusable software work, not production eligibility. Integrate their exact
reviewed revisions; a PR merged into another feature branch is not necessarily
present on `main`. Do not bypass their development guards for this campaign.

Shared contract changes belong in
[kaiba-contracts](https://github.com/pd-codex/kaiba-contracts); fleet consumption
belongs in [kaiba-fleet](https://github.com/PseudoDesign/kaiba-fleet). Runtime
schemas and exception/adoption fields are not introduced by this document.
Use versioned migration and producer/consumer conformance rather than adding
unrecognized fields to the existing closed contracts.

## Automated acceptance and the operator's report

Use disposable PKI, real packaged services and durable temporary stores for
software checks. Synthetic hardware records must be marked as fixtures. Keep
these tests independent of kernel builds, token signing and a connected board.

| Scenario | Required result |
| --- | --- |
| Existing secret versus boot ownership | Reuse never repeats OTP device-secret programming. Fresh boot-root and already-owned fixtures take their distinct reviewed paths with separate authority for any boot-root programming; neither invents history. |
| Adoption decision validation | Unknown, expired, revoked, wrong-target/profile/release or altered decisions block admission. Acceptance of history alone cannot change an observed failure into success. |
| Evidence and identity | Missing audit/source binding, uncertain mutation, copied evidence, substituted key, replay or wrong audience fails. A hostname cannot choose the canonical fleet identity. |
| Screen and controller restart | Current step and required input return from durable authority state. Stale views disable actions; double taps and lost replies cannot repeat physical operations. |
| Enrollment restart and failure | Persisted device identity survives a permitted restart; pending credentials are denied. Lost issuance/activation responses reconcile the same tuple without duplicate identities. |
| Service transfer and restore | Preserve exact tuples, issuer references, evidence and revocations; prevent concurrent writers and stale-state rollback. A restored pending/revoked member stays denied. |
| Development/production separation | Existing development fixtures, keys, client mode and incomplete profiles cannot activate as production. Unrecognized contract versions fail closed. |

Hardware acceptance remains the applicable FA-01–FA-08 procedure, including
actual offline cold boot, private data access, root/boot/recovery rejection,
secret/lock observations and copied-storage/identity checks. Reuse prior evidence
only where its applicability is recorded. A process restart or a changed boot ID
does not prove removal of power or network paths.

The retained report must bind the authenticated device, station/lane, campaign,
profile, release, source revisions, authority observations and evidence references.
For each FA condition, record the observed outcome (`not_evaluated`, `passed`,
`failed`, `blocked` or `quarantined`), its evidence, unresolved reason and next
action. Separately record exception disposition (`proposed`, `accepted`,
`rejected`, `expired` or `revoked`) and its exact approval reference. These are
planned report semantics, not additions to the current wire schema.

Reports can be exported at every stop, including failure. A completed test
campaign can still produce a blocked admission report. The screen shows
**enrolled** only after authoritative FA-08 completion and the successful access
check. Diagnostic details contain the longer identifiers and provenance; ordinary
steps ask only for the inputs and physical actions needed to proceed. Public
publication of real-device evidence remains distinct from a private report export.

Reduce human work by building and rehearsing first, reusing applicable artifacts,
batching exact signing inputs when authorized, and exchanging receipts and
results through the services. Install the station once and use its fixed lane;
do not make routine tests depend on drive shuttling or re-signing unchanged
images. Human presence remains necessary for the chosen signer and any reviewed
physical step that the qualified station cannot perform itself.

## Decision gates before execution

| Open decision | Resolving work | Milestone blocked |
| --- | --- | --- |
| Ace boot-root eligibility and exact production signer | Read-only effective-state inventory; select customer root/custody and prepare recovery against it. | Ownership changes, signing and final profile approval. |
| Existing secret custody and `ACE-EX-01` | Review original provisioning history and retained-key risk; bind the approved reuse decision to the actual target. | Storage-secret adoption and production admission. |
| Data disposition and HMAC storage migration | Inventory current volumes/key slots without reading secrets; select retained data, backups, exact layout, fallback retirement and restoration tests. | Media/keyslot changes and protected-state qualification. |
| Final protections and permitted software/recovery | Select exact boot/debug/EEPROM policy and signed image set; demonstrate effective enforcement. | Final hardware acceptance. |
| Station persistence, physical lane and power | Select durable storage and fixed connections; qualify safe power control and host recovery. | Production physical campaign. |
| Production enrollment trust and contract adoption | Select issuer, endpoints, roles, namespace and policy; complete shared contract/producer/consumer review and tests. | Production credentials and activation. |
| Ace service release, backup and cutover | Bind approved service code/configuration, rehearse single-writer migration and independent recovery. | Fleet service transfer. |

The first next step is slice 1's read-only inventory and concrete profile/exception
review. Slices 2 and 3 can develop against fixtures in parallel. Every signing,
media, firmware, OTP/secret, power and deployment operation still needs its
applicable scoped execution authority; selecting Ace does not renew or replay
an earlier one-use experiment.
