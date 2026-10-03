# Raspberry Pi firmware notices

The firmware distributed in this release is copyright 2024 Raspberry Pi
(Trading) Ltd. The complete, unmodified upstream [rpi-eeprom LICENSE](rpi-eeprom-LICENSE)
is included here, with its copyright notices, conditions and disclaimers,
including the uIP and QR Code generator notices.

The `firmware-2712/*` entry in that file assigns the custom firmware terms to
these Raspberry Pi 5 payloads. The BSD-3 entry covers the upstream tools;
it does not replace the custom firmware terms. Those terms restrict use to
developing for, running or using a Raspberry Pi device and prohibit endorsement
using the copyright holder's or contributors' names without prior permission.

## Published files

Paths below are relative to `releases/rpi5-v0.1.6`. Both copies of
`pieeprom.bin` have identical contents.

| Distributed file | SHA-256 | Origin and processing |
| --- | --- | --- |
| `signed-inputs/eeprom-signed/bootcode5.bin` | `73dab9a01c139b7d995ac9a4055ee0d15551d7f8dbf1c2605bae584ef7126e0c` | Unchanged copy of `firmware-2712/latest/recovery.bin` |
| `signed-inputs/eeprom-signed/pieeprom.bin` | `d69f3454d838bd23bd9730ecbcebf0ca2f2353ceadca0d56abd2f54e1b82d19e` | Configured and signed EEPROM image derived from `firmware-2712/default/pieeprom-2026-05-26.bin` |
| `signed-inputs/owned-recovery-signed/bootcode5.bin` | `6ebcc382649a5d18095fa3f31a348e95ddfc6ca04df4a81fd7188afae956e95b` | Customer-counter-signed recovery derived from `firmware-2712/latest/recovery.bin` |
| `signed-inputs/owned-recovery-signed/pieeprom.bin` | `d69f3454d838bd23bd9730ecbcebf0ca2f2353ceadca0d56abd2f54e1b82d19e` | Same configured and signed EEPROM image as the fresh-board input |

The reviewed source is
[`raspberrypi/rpi-eeprom` revision `05d94be4554ce44a057bfce8d0dd37d951703dab`](https://github.com/raspberrypi/rpi-eeprom/tree/05d94be4554ce44a057bfce8d0dd37d951703dab),
tag `v2026.05.17-2711-0138c0`. The original EEPROM image has SHA-256
`fee8bee6a738a1a61004f0770f15534de7a48a2a199dc4c7af7ed73ab04f18dd`;
the original recovery has SHA-256
`73dab9a01c139b7d995ac9a4055ee0d15551d7f8dbf1c2605bae584ef7126e0c`.
These pins are recorded in the historical `2026-05-26` policy in
[`nix/eeprom-release-pins.nix`](../../../nix/eeprom-release-pins.nix).
The included license is copied verbatim from that source's `LICENSE`
(Git blob `cdeafb462db4ac43aade488dd8f0c6f4442b6139`, SHA-256
`594b7565fd3ccf8acd4711a2ec1b199181aafbc3426d0bacaa50ef40edbf7c4a`).

The operational payload carries this directory alongside its manifest. Its
`fresh-commit/pieeprom.bin` uses the signed EEPROM above;
`fresh-commit/bootcode5.bin` and `fresh-readback/bootcode5.bin` use the unchanged
recovery; `owned-readback/bootcode5.bin` uses the customer-counter-signed recovery.
Retain these notices with copies of the published firmware or operational payload,
including when extracting an individual RPIBOOT directory.

## Permission question

The custom terms grant binary redistribution "without modification". The
configured and signed EEPROM and customer-counter-signed recovery involve changes
to the upstream bytes. Inclusion of these notices does not establish permission
to redistribute those variants. Clarify with Raspberry Pi how the grant applies
to the supported configuration and signing workflow before further redistribution.
