# Architecture and trust boundaries

Kaiba separates public artifact construction, signing authority, transaction
authority, physical execution, and evidence retention. The separation is part
of the safety model: no single browser action or generic command is intended to
select arbitrary hardware and obtain signing and mutation authority.

The architecture's components and contracts are implemented as a reference
development system and extensively software-tested. A configured end-to-end
composition is not exported by the standalone flake, and the repository does
not contain evidence qualifying the complete physical system as a production
lane. See [production readiness](production-readiness.md).

## Boundary map

| Boundary | Repository components | Authority held | Important limits |
| --- | --- | --- | --- |
| Public build and verification | `flake.nix`, `nix/*.nix`, release and media verifiers | Construct and verify immutable public artifacts | No private key, PIN, OTP, EEPROM, or arbitrary device authority |
| Signing host | `kaiba-provision-signing-gate`, signing client/wrapper, YubiKey adapter, Ubuntu signing deployment | Use the fixed development signing identity for exact unexpired grants | Unix-socket service; host root remains trusted; same-grant retry is denied after an incomplete attempt |
| Control authority | `kaiba-provision-control` and `kaiba-provision-lane-workflow` | Own transactions, claims, approvals, intent, evidence, quarantine, and terminal state | Does not own a generic physical command or device selector |
| Independent audit | `kaiba-provision-audit` | Append ordered, secret-free events and issue hash-chain receipts | Stores digests and structured references rather than raw evidence or credentials |
| Station bridge | `kaiba-provision-authority-bridge` | Authenticate stable control and audit state and expose the current closed request locally | Separate control and audit server trust roots; no caller-supplied executable payload |
| Physical lane | `kaiba-provision-lane-guard`, physical RPIBOOT adapter, operator prompt | Execute one build-bound operation against one configured lane | Root-only, execute-once journal, fixed USB/UART/power paths, mutations disabled unless explicitly configured |
| Operator acknowledgement | `kaiba-provision-lane-operator` and the module-owned no-argument wrapper | Confirm the exact prompt selected by the guard | Cannot choose operation, target, boot mode, GPIO, UART, or payload |
| Target media | `mkRpi5ProductionMedia` writer/verifier outputs and `config/hardware/` | Write or read one plan-specialized whole device | Device and hostname are configuration-bound; canonical plans do not accept an arbitrary runtime path |
| Target system | `secure-boot-target.nix`, signed boot image, dm-verity root | Emit bounded boot/root evidence over the reviewed interface | Development access and UART policy remain development controls; anti-rollback is absent |
| Evidence retention | attempt receipts, audit receipts, signing receipts, redacted qualification evidence | Preserve correlation and review material | Observation is not device attestation; raw probe output stays outside Git |

## Public artifacts and signing

The public side constructs unsigned boot/root artifacts, release intent,
signing plans, EEPROM inputs, recovery inputs, RPIBOOT bundles, media plans, and
verification contracts. Digest bindings connect those objects to an exact
release and expected target state. The repository exposes verification and
finalization tools independently of the live signing service.

The development signing chain is instantiated by
`lib.mkDevelopmentYubiKeySigning`. It fixes the signer and cohort identities,
PIV selector, public key, provider modules, socket, registry, and durable state
in the Nix output. The Ubuntu deployment loads a root-owned, tmpfs-backed PIN
through a systemd credential and grants the signing user only the required
PC/SC actions. A grant completed on its first attempt performs the artifact
signature and a separate receipt-attestation signature. An incomplete grant
leaves durable intent and requires a new independently approved ceremony; it is
not retried under the same grant.

The checked-in signer material is a public trust anchor and an independent
development review. It grants neither current signing authority nor production
approval. The operational sequence is described in the
[signed-boot](raspberry-pi-5-signed-boot-workflow.md) and
[signing-ceremony](ubuntu-rpi5-development-signing-ceremony.md) guides.

## Control, audit, and station authority

The Ubuntu authority deployment uses mutual TLS and separate control and audit
server roots. Its fixed development identities separate the station/lane role
from the approver role. Installation is deliberately inert: service startup,
network firewall changes, credential transfer, and a live smoke test remain
explicit operator boundaries.

The workflow prepares an authority-free draft before approval. Operation
names, classifications, boot modes, sequence numbers, and prestate chaining are
compiler-owned. Approval and the per-operation intent are then bound to the
same plan digest, release, station, lane, target fingerprint, fence epoch, and
server-observed validity window. The bridge supplies only the currently valid
request to the privileged guard.

The browser simulation and live-interface foundation are different programs
and assets. The simulation is loopback-only, in-memory, and has no live
backend. The exported `kaiba-provision-station` also binds only to loopback,
installs a disabled backend, rejects `--enable-mutations`, and does not fall
back to simulation. A deployment-specific authority/hardware integration is
not exported. See the [station interface guide](provisioning-station-kiosk.md)
and proposed [production-station architecture](provisioning-station-production.md).

## Fixed development campaign

The plan compiler accepts exactly this ordered campaign:

| Sequence | Operation | Classification | Required boot mode |
| ---: | --- | --- | --- |
| 1 | `program_customer_key_and_eeprom` | Irreversible | RPIBOOT |
| 2 | `cold_power_cycle` | Reversible | Normal |
| 3 | `owned_readback` | Read-only | RPIBOOT |
| 4 | `test_owned_recovery` | Reversible | RPIBOOT |
| 5 | `post_recovery_readback` | Read-only | RPIBOOT |
| 6 | `test_negative_boot` | Reversible | RPIBOOT |
| 7 | `test_root_integrity` | Reversible | RPIBOOT |

The initial state must be a fresh target with an all-zero customer-key hash and
power off. The release must expect a distinct nonzero customer-key hash. A
caller cannot insert, omit, reorder, or reclassify operations.

## Physical and media bindings

The hardware catalog currently contains two development configurations:

- `malakRaspberryPi5SacrificialDevelopmentUsbSd` binds hostname `malak` to one
  USB reader `/dev/disk/by-path` and independently protects `/dev/nvme0n1`.
- `raspberryPi5SacrificialDevelopmentPiLocalNvme` binds hostname
  `kaiba-rpi5-provisioner` to `/dev/nvme0n1`; it is intended for a Pi or isolated
  lane booted from separate media.

The media constructor binds a signed release, exact 512-byte-sector geometry,
GPT/FAT/root/dm-verity content, and separate writer/verifier programs. Its tests
exercise regular-file and synthetic device contracts; they do not constitute a
live-media, cold-power, or boot-enforcement qualification. See
[target-media staging](target-media-staging-prototype.md).

The stable-verifier campaign GPT inspector is a separate evidence-only
boundary. Its default v1alpha1 path retains the original rejection of an
image-sized GPT accompanied by a GPT signature at the physical end. An
explicit v1alpha2 path can instead record the selected reciprocal lineage and
a strictly valid physical-end backup with the exact older reviewed root
extents, distinct disk and boot-partition GUIDs, and shared root-data/root-hash
GUIDs. Both paths open only the fixed inactive selector read-only, perform
sequential re-read verification, and emit canonical hashes on standard output.
Neither path repairs a GPT, writes recovery bytes, authenticates the physical
attachment, proves quiescence, or authorizes destructive staging.

The one-off stable-campaign provisioner is also separate from the production
media artifact contract. Its signed command line binds dm-verity to fixed Pi 5
SD paths `/dev/mmcblk0p2` and `/dev/mmcblk0p3`; its dedicated manifest and boot
integrity schemas are intentionally ineligible for the ordinary target-NVMe
release and capsule flows. The campaign NVMe is not part of the provisioner's
mount or swap graph. The unsigned 96 MiB `boot.img` is explicitly a signing
input, never an SD partition image. Only the separate post-sign constructor can
verify its `boot.sig` and materialize the 128 MiB outer FAT image for SD p1.
Physical placement still requires a separate identity-bound write and full
partition readback procedure.

Relay power is the production-shaped lane mode: the NixOS module fixes the GPIO
device and line and enforces an inactive action before startup and after exit.
The physical relay still requires separate normally-off electrical
qualification. Manual power is an explicit development-only mode using
authenticated connect/disconnect prompts; it has no automated fail-off
guarantee and no relay fallback.

## Failure and recovery semantics

The lane guard persists an attempt and boot-transition journal before treating
an outcome as evidence. Replaying an exact durable terminal result may verify
or republish its receipt, but it must not reach hardware again. A persisted
`started` state, failed terminal write, timeout, lost target, or otherwise
ambiguous outcome requires the reconciliation path.

Reconciliation uses separately acquired read-only authority and direct
observation. It may conclude applied, not applied, or unknown. Unknown and
unproven safe-off outcomes remain quarantined. Claim renewal is limited to the
same compiler-derived state; it cannot revive expired authority or rebase a
reviewed proposal. The complete operator sequence belongs in the
[live-provisioning guide](raspberry-pi-5-live-provisioning.md).
