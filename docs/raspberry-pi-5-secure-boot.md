# Raspberry Pi 5 secure-boot model

This document defines the security model that the Kaiba provisioning contracts
are designed to enforce for a Raspberry Pi 5 Model B. It is a design and review
guide, not permission to program EEPROM, OTP, boot media, or debug settings.

> [!IMPORTANT]
> The checked-in evidence proves a read-only qualification of one sacrificial
> development board. It does not prove that the board has been fused, that the
> signed release has booted on hardware, or that the seven-operation mutation
> campaign has completed. The current development policy stops at
> `security_applied`; it explicitly blocks `enrollment_ready`.

For the repository's implemented boundary and remaining blockers, read
[Production readiness](production-readiness.md). For the proposed path beyond
that boundary, read the
[production security follow-on](raspberry-pi-5-production-security-follow-on.md).

## Native boot chain

Raspberry Pi 5 uses the BCM2712 boot ROM and an EEPROM bootloader rather than
UEFI Secure Boot. The intended chain is:

```text
immutable BCM2712 Boot ROM
  -> Raspberry-Pi-signed and customer-counter-signed EEPROM second stage
  -> customer-authorized EEPROM bootloader and configuration
  -> boot.img verified by boot.sig with the customer RSA-2048 key
  -> authenticated kernel, initramfs, DTB, overlays, configuration, and cmdline
  -> initramfs validates the persistent dm-verity root
  -> read-only NixOS system
```

The customer key in Raspberry Pi documentation is the Kaiba cohort boot root.
The board stores the hash of its public key in OTP. Its private half must never
be present on the target, the provisioning station, in Git, in the Nix store,
or in CI.

The stages have distinct responsibilities:

1. Boot ROM authenticates the EEPROM second stage. In owned secure-boot mode it
   also requires the customer counter-signature.
2. The verified EEPROM code checks that the embedded customer public key
   matches the hash programmed in OTP.
3. The bootloader verifies the complete FAT `boot.img` through `boot.sig`.
4. The signed initramfs validates the persistent root data against the signed
   dm-verity root hash before starting the real system.

All enabled boot sources must enforce the same policy. Rejecting a bad image on
one source is insufficient if the configured `BOOT_ORDER` can continue into an
unsigned legacy or recovery path.

## Claims the design can support

After a complete, successful hardware campaign, the development design is
intended to show that:

- unsigned, altered, and wrong-key EEPROM or boot images do not execute;
- every byte that controls the kernel-to-root transition is authenticated;
- persistent NixOS system bytes are read-only and checked by dm-verity;
- the exact customer-key hash, EEPROM digest, release manifest, target,
  transaction, station, lane, and fence epoch are bound before mutation;
- one immutable approval authorizes only the fixed operation plan;
- ambiguous physical outcomes cannot become blind retries; and
- an owned device has a prebuilt, customer-signed recovery path.

These are target claims until the corresponding physical evidence exists.
Software checks prove contract behavior, reproducible construction, signature
verification, and simulated failure handling; they do not prove hardware
enforcement.

## Claims the design does not support

Native Raspberry Pi secure boot does not by itself provide:

- strong offline OS anti-rollback;
- TPM-style measured boot, PCRs, quotes, or remote attestation;
- confidentiality for persistent data;
- protection after an authorized kernel is compromised;
- recovery of unreplicated local data after board or storage loss;
- in-place replacement of the customer key; or
- resistance to invasive extraction, fault injection, side channels, or
  denial of service.

An older image correctly signed by the same customer key can still be accepted
by the native chain. Availability rollback such as a one-shot A/B fallback is
not the same as a monotonic security decision. The development posture
therefore cannot advance from `security_applied` to `enrollment_ready`.

Optional root-equivalent access for development targets is documented in
[Development target access](raspberry-pi-5-development-target-access.md). It is
off by default and is not a production security control.

## Development posture

The normative machine-readable posture is
[`policies/raspberry-pi-5-development-posture-v1alpha1.json`](../policies/raspberry-pi-5-development-posture-v1alpha1.json).
It approves one sacrificial development unit and is deliberately not a
production profile.

| Control | Development value | Production consequence |
| --- | --- | --- |
| Boot order | `0xf216`, read right-to-left as NVMe, SD, network/TFTP, restart | Must be replaced by a qualified production policy |
| Boot UART | `1` | Unreviewed and a production blocker |
| Automatic EEPROM self-update | Disabled | Does not prevent separately authorized RPIBOOT writes; production policy is undecided |
| VideoCore JTAG | Unlocked | Production blocker |
| EEPROM hardware write protection | Unlocked | Production blocker |
| Persistent root | Read-only dm-verity | Physical enforcement has not been qualified |
| Mutable state | tmpfs only; no swap, persistent journal, core dumps, or persistent device secrets | Production requires a separate confidential-state design |
| Recovery | Narrow customer-signed RPIBOOT bundle | Not production-qualified |
| Rollback | Unimplemented | Blocks enrollment |

Boot-media serials, WWIDs, models, and `/dev/disk/by-id` values are not trust
inputs. The station uses a reviewed, host-bound selector only to determine the
target of an explicitly authorized write. Trust in the resulting system comes
from the signed boot and dm-verity chain, not from the medium's self-reported
identity.

## Keys and public artifacts

The development release lineage keeps signing authority separate from public
construction and verification:

| Object | Role |
| --- | --- |
| Customer private key | Authorizes EEPROM, normal boot, and narrow recovery; held in the development YubiKey PIV `9c` profile |
| Reviewed public key | Reproducible trust anchor and source of the Raspberry Pi customer-key hash |
| Release intent | Cohort-level authorization for exactly five signing inputs and the required final release roles |
| Signing plans and grants | Bind one artifact role, digest, release lineage, reviewer attribution, and expiry |
| Artifact signatures | Public Raspberry Pi-compatible signatures |
| Receipt attestations | Second signatures over the canonical grant, request, backend identity, artifact result, and signing time |
| Signed-release publication | Content-addressed, independently verified 18-role release graph |
| Per-device lane plan | Later authorization binding the complete release to one target, transaction, station, lane, fence epoch, and expiry |

A valid release signature is not authority to write a block device or change a
board. Release authorization must precede and remain separate from per-device
execution authorization. See the
[signed-boot workflow](raspberry-pi-5-signed-boot-workflow.md).

## Irreversible ownership boundary

The fresh-board RPIBOOT configuration's `program_pubkey=1` operation programs
the customer public-key hash into OTP. This is not the ordinary `config.txt`
inside a boot filesystem. Once the matching hash is programmed, the board is
owned by that key and cannot be returned to a factory-fresh state or migrated
in place to another customer root.

Before any irreversible operation, the transaction must already bind and
independently verify:

- the exact target fingerprint and a fresh, all-zero customer-key prestate;
- the nonzero expected customer-key hash;
- the signed EEPROM firmware and complete configuration;
- normal `boot.img` and `boot.sig` plus the dm-verity root binding;
- a fresh-board commit bundle;
- a customer-signed owned readback and narrow recovery bundle;
- negative-boot and root-integrity test bundles;
- the boot-order, debug, recovery, update, and rollback policies; and
- the operator, reviewer, station, lane, transaction, fence, and time bounds.

The pre-ownership probe and stock recovery payload cannot be assumed to execute
after ownership. The owned recovery path must be built and verified first.

## Fixed development campaign

The plan compiler fixes seven operations; clients cannot insert, omit, rename,
reorder, or reclassify them.

| # | Operation | Class | Required boot mode |
| ---: | --- | --- | --- |
| 1 | `program_customer_key_and_eeprom` | irreversible | RPIBOOT |
| 2 | `cold_power_cycle` | reversible | normal |
| 3 | `owned_readback` | read-only | RPIBOOT |
| 4 | `test_owned_recovery` | reversible | RPIBOOT |
| 5 | `post_recovery_readback` | read-only | RPIBOOT |
| 6 | `test_negative_boot` | reversible | RPIBOOT |
| 7 | `test_root_integrity` | reversible | RPIBOOT |

The initial state must be `fresh`, fully `powered_off`, and carry an all-zero
customer-key hash. Every step has an expected prestate and poststate chained to
its neighbors. A terminal `security_applied` record is derived only after all
seven durable evidence records match the plan.

The relay-backed path is production-shaped because it can establish a
normally-off failure state. Manual power is a development-only deviation: it
records authenticated operator acknowledgements and USB observations, but it
does not prove an electrical edge or automatic fail-off.

## Failure rule

The lane guard journals an attempt before dispatching hardware. A completed
record can be reloaded and republished without reaching hardware again. A
`started` record, failed terminal journal write, timeout, missing receipt, or
other ambiguous result is never a reason to repeat the mutation.

Preserve the journal and physical evidence, place the target in a known safe
state if that can be done without another mutation, and enter the reviewed
reconciliation path. If ownership or EEPROM state cannot be established, the
only acceptable terminal result is quarantine.

See [Live provisioning](raspberry-pi-5-live-provisioning.md) for the authority,
claim, acknowledgement, evidence, and reconciliation workflow.

## Evidence needed before any production claim

A complete sacrificial-board campaign must include, at minimum:

- pre- and post-operation target identity and OTP/EEPROM state;
- cold-boot proof for the approved signed image;
- rejection of altered, unsigned, and wrong-key images on every enabled boot
  path;
- owned recovery success and unauthorized recovery failure;
- dm-verity corruption preventing the system root from mounting;
- exact final boot-order, UART, JTAG, self-update, and EEPROM protection
  readback; and
- confirmation that exported artifacts and evidence contain no signing key,
  OTP secret, derived storage secret, or active credential.

The production follow-on adds delegated release keys, server-enforced
freshness, encrypted mutable state, A/B updates, device authentication, and a
production-only key hierarchy. None of those controls should be inferred from
the development contracts. Its separate acceptance campaign must demonstrate
rejection of an obsolete but correctly signed release before any anti-rollback
or production freshness claim.

## External mechanism references

These references explain the hardware mechanisms. They are discovery inputs,
not automatically approved dependencies; implementation work must pin and
review exact revisions.

- [Raspberry Pi secure boot](https://github.com/raspberrypi/usbboot/blob/master/docs/secure-boot.md)
- [Raspberry Pi bootloader configuration](https://www.raspberrypi.com/documentation/computers/raspberry-pi.html#configuration-properties)
- [Linux dm-verity](https://www.kernel.org/doc/html/latest/admin-guide/device-mapper/verity.html)
