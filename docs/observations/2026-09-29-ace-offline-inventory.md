# Ace metadata inventory: 2026-09-29

A fixed [read-only inventory](../offline-qualification-inventory.md) completed
on the existing Ace host at station time `2026-09-29T04:42:04Z`. The offered
ED25519 key was compared with the owner's explicitly supplied fingerprint
before connection. SSH used the matching key in a private task-specific trust
file, retained strict checking, and did not modify the station's ordinary
known-hosts file. No remote file, firmware, OTP, storage, service or boot
configuration was changed.

| Item | Observation |
| --- | --- |
| Board | Raspberry Pi 5 Model B Rev 1.1, `aarch64` |
| Kernel | `6.18.42` |
| Running NixOS closure | `/nix/store/f4q82s6kzy6y4q943y9v9nsm64c9s0xp-nixos-system-ace-26.05.20260807.ee48b14` |
| Public bootloader version | `2026/09/12 00:07:08`, revision `a86983925695a7e63166327d7c002d64040ed31d` |
| Root | `/dev/mapper/pool-rootfs`, ext4, `rw,relatime` |
| Storage types | FAT partitions; LUKS partition; LVM member and ext4 logical volume |
| Bootloader device-tree `signed` property | Not observed; read exited 1 |
| Bootloader device-tree `boot-mode` bytes | `00 00 00 06`; no enforcement claim inferred |
| TPM interfaces | Neither `/dev/tpm0` nor `/dev/tpmrm0` observed; no TPM class entries returned |
| Clock | Target UTC matched station timestamp to the displayed second; NTP synchronization reported `yes` |
| Services | systemd-timesyncd active |
| Other queried services | nginx, dogsitting, crtvar, SPIRE server/agent and chronyd not observed; systemctl exited 4 |

Compared with [Mako](2026-09-29-mako-offline-inventory.md), Ace has the same
reported board revision, newer firmware, and fewer observed application
services. It is the better initial host for reversible identity integration
and read-only native-mechanism research. This is a suitability inference from
limited inventory, not a complete workload audit or permission to interrupt
existing data or services.

The observation does not establish secure-boot ownership or enforcement. The
signed-boot property was absent, and no OTP words or secret slots were read.
Writable encrypted storage does not demonstrate protection from old image or
security-state replay; current NTP status does not establish offline time
continuity. No OFF-01 through OFF-12 gate is closed. A physical campaign still
needs the selected native mechanism, exact profile, permitted legacy/recovery
images, retained data and recovery plan, and independently observable test
results. TPM presence and suitability remain unestablished.

Private station retention contains the complete transcript, inventory
projection, and exact collector source. Public evidence bindings are:

```text
collector_sha256=sha256:bd07e76793fecef23686745a0488fda10603f64c56333f78dc3b5d8fc97735c4
raw_evidence_sha256=sha256:67bb43c1a016fadbcd3b0090aac5dbb32d0ddad302f62732c965ab3831498d79
```

These hashes identify retained bytes; they do not replace physical evidence
or attest the running boot chain. SSH keys, fingerprints, raw transcripts and
private access details are excluded from this public summary.
