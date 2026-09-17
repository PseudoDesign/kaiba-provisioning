# Pi 5 EEPROM update for firmware-crypto locks

The development firmware candidate is now the Pi 5 **2026-09-12** EEPROM,
revision `a8698392`, build epoch `1789171628`. This prepares public firmware,
EEPROM signing inputs and owned-recovery signing inputs. Signing, installation
and physical qualification remain pending.

The previous May 26 candidate predates the **June 17 fine-grained crypto locks**
required by the [device-secret harness](device-secret-target-harness.md).
Upstream documents per-key read, generation, signing, HMAC and usage locks,
including `lock_device_key_write=1` for generation and usage. Updating the source
pin does not establish that these locks work on a selected board. The EEPROM
release manifest explicitly records `hardware_qualified: false`.

## Fixed source and compatibility review

The selected source is
[`raspberrypi/rpi-eeprom` `2fee426f27b6c54d3f5b6f36efd9a2fe1286a45d`](https://github.com/raspberrypi/rpi-eeprom/tree/2fee426f27b6c54d3f5b6f36efd9a2fe1286a45d),
with Nix hash `sha256-EB4hvvPNSs0ykZ86VJLvCq5hBYwAZX/BmZ2leZyEBaM=`.
This is a commit pin, with no claimed release tag. Its
[release notes](https://github.com/raspberrypi/rpi-eeprom/blob/2fee426f27b6c54d3f5b6f36efd9a2fe1286a45d/firmware-2712/release-notes.md)
promote September 12 to the default channel on September 15. They also describe
the September 10 move of crypto functions into protected RAM, with the same API.

| Public input | Size (bytes) | SHA-256 |
| --- | ---: | --- |
| Default `pieeprom-2026-09-12.bin` | 2097152 | `b49adc90c380f3b9bec9e1ab21111571d7cfdbfe8f2dc5974f294bdb3eb7c39a` |
| Latest `recovery.bin` | 105420 | `f0cda4652fede0838e5b61c50979cf1f3c537ff0d652a77c9078495054d0e7b3` |
| Extracted `bootcode.bin` | 25984 | `9563d201f467d83bfc3c6ad0a9904002a4802cac183544aaaa0439c0443aa167` |
| Extracted `bootsys` | 78356 | `1d93abd789d8978054cfa48577956299fcc9faa3b4a343201cf4afc4f45cc9f5` |

The pinned `versions.txt` still labels September 12 `latest`, and May 26
`default`. The verifier requires the exact September build/revision entry with
that recorded index label, the September default-path image, the promotion
note, and hashes for both provenance files. It does not rewrite upstream data or
accept an arbitrary channel. `firmware.versions_index_channel` records this
reviewed discrepancy separately from the selected image's channel.

The A/B-aware `update-pieeprom.sh` remains pinned to usbboot `42ca5093`.
The new EEPROM source supplies its helper programs. Compared with the old
helpers, `rpi-eeprom-config` changes subprocess diagnostics/cleanup;
`rpi-eeprom-digest` propagates callback failures and adds an optional target-SoC
field; `rpi-sign-bootcode` adds signature extraction. The pinned updater does not
request the new target-SoC field. The key converter is unchanged. The manifest
records that these helpers differ from the updater's old EEPROM submodule.
Software signing and replay checks exercise the selected combination.

## Build and review

These commands fetch and construct public files; they perform no signing or
hardware operations:

```console
nix build --no-link --print-out-paths \
  .#rpi5-eeprom-release .#rpi5-eeprom-release-signing-inputs \
  .#kaiba-provision-sign-eeprom
nix develop --command scripts/check.sh contracts \
  rpi5-eeprom-release rpi5-eeprom-signing rpi5-signed-release \
  signing-receipts-integration
```

The release contains `release.json`, original firmware, extracted components,
provenance and the exact updater/helpers. The signing-input output contains
four public preimages: EEPROM bootcode, bootsys, configuration and owned recovery.
It uses the existing [development EEPROM configuration](../config/rpi5-prototype-eeprom/boot.conf).
The signing client is bound to the new release digest and existing approval gate;
building it grants no signing authority.

The current release uses
[`rpi5-eeprom-release/v1alpha2`](../schemas/rpi5-eeprom-release-v1alpha2.schema.json).
The May manifest and v1alpha1 schema are preserved. Historical packages are
`rpi5-eeprom-release-2026-05-26` and `kaiba-provision-sign-eeprom-2026-05-26`;
the old manifest digest remains
`sha256:318dbaafa730aa25d655fdd89b29c5636c7dceb7e1a100e6ad7d8a22df79e1a5`.
The [v0.1.6 signed inputs](../releases/rpi5-v0.1.6/) are unchanged. Existing
plans/results must stay with their original release and toolchain. Full legacy
constructor compositions can select `eepromReleaseVersion = "2026-05-26"` when
importing `nix/packages.nix` with the pinned packages and library.

## Physical continuation

After review and CI, prepare a separate, exact EEPROM/owned-recovery signing
request with the existing customer key, then verify the signed outputs and
receipts offline. The boot-image signature authenticates separate bytes: an
unchanged experiment `boot.img` does not need a replacement signature solely
because this EEPROM pin changed. Its boot-only approval does not authorize
EEPROM signing. Full-release intents and receipts remain bound to their exact
artifact set and cannot be mixed across versions.

Before installation, prepare an owned-device recovery packet that binds the
selected board, existing ownership, signed EEPROM/configuration, authenticated
recovery, power steps, readback and return route. Installation needs its own
execution authority. This is an owned-device update, not a fresh-board ceremony.
No customer-key fuse, OTP secret, usage value or permanent protection changes
are part of this repository update.

After installation, observe the exact running firmware identity and signed SD
boot, then test the required volatile-lock behavior under its reviewed scope.
Rebuild any boot-bound execution packet after a restart. Key availability and
any one-time key generation remain separate decisions; an undefined usage value
is not proof that a key is absent. HMAC/LUKS behavior, lock enforcement, allowed
older/recovery image exposure and copied-media protection still need their
specified physical evidence. Offline rollback rejection remains outside the
first-fleet requirements.
