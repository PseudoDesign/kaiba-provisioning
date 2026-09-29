# Mako metadata inventory: 2026-09-29

A fixed [read-only inventory](../offline-qualification-inventory.md) completed
on the existing Mako host at station time `2026-09-29T04:38:13Z`. SSH used the
station's existing trusted host key. No remote file, firmware, OTP, storage,
service or boot configuration was changed.

| Item | Observation |
| --- | --- |
| Board | Raspberry Pi 5 Model B Rev 1.1, `aarch64` |
| Kernel | `6.18.42` |
| Running NixOS closure | `/nix/store/nf6pj4bqp2gp4j9rf4d23bfgsh6lcbjf-nixos-system-mako-26.05.20260807.ee48b14` |
| Public bootloader version | `2025/11/05 17:37:18`, revision `57db150d63864d47e6c9071f6b086a5401eb4e92` |
| Root | `/dev/mapper/pool-rootfs`, ext4, `rw,relatime` |
| Storage types | FAT partition; LUKS partition; LVM member and ext4 logical volume |
| Bootloader device-tree `signed` property | Not observed; read exited 1 |
| Bootloader device-tree `boot-mode` bytes | `00 00 00 06`; no enforcement claim inferred |
| TPM interfaces | Neither `/dev/tpm0` nor `/dev/tpmrm0` observed; no TPM class entries returned |
| Clock | Target UTC matched station timestamp to the displayed second; NTP synchronization reported `yes` |
| Services | nginx active, dogsitting activating, systemd-timesyncd active |
| Other queried services | SPIRE server/agent, crtvar and chronyd not observed; systemctl exited 4 |

This supports using Mako for a reviewed, reversible SPIRE integration test.
It is an existing service host, so an eventual service change must account for
those workloads. The writable encrypted root and network-synchronized clock
are not the new autonomous production profile. No OFF-01 through OFF-12 gate
is closed by this inventory; signed-boot enforcement, native monotonic state,
TPM binding, state replay protection and offline time continuity remain open.

The separate [Ace inventory](2026-09-29-ace-offline-inventory.md) records a
matching Pi 5 revision, newer firmware and fewer observed application
services. That makes Ace the more suitable first research host for the native
mechanism; Mako remains a candidate for reversible integration and later
independently reviewed cross-device comparisons.

Private station retention contains the complete transcript and inventory
projection. Public evidence bindings are:

```text
collector_sha256=sha256:8b5762f807beebd122e8aebce3fd8a26b99fd60594a7201f3b26cf1b70e72110
raw_evidence_sha256=sha256:f46beea433c8fb002937bb3964b010a11249a119c9efd50dc8fb3ded39599682
```

These hashes identify the retained bytes; they do not authenticate secure
boot or replace independent physical observations. Raw transcripts, host keys
and access details are excluded from this public summary.
