# Raspberry Pi 5 provisioning probe

The `kaiba-provision` package provides the implemented, non-persistent first
stage of the Raspberry Pi 5 provisioning workflow. It can inspect imported
vendor metadata or acquire metadata from exactly one Raspberry Pi 5 Model B on
a fixed RPIBOOT USB lane. `kaiba-provision qualify` compares two private live
observations and emits a whitelist-redacted qualification record.

The result is correlation and partial preflight evidence. It is not device
authentication, remote attestation, proof of supply-chain provenance, a
complete determination that a board is unprovisioned, or authority to change
the board. Probe results always retain:

```text
mutation_eligible: false
full_unprovisioned_state: not_established
```

The checked device-class profile is `stable` because its read-only
classification contract passed the documented hardware qualification. That
status does not authorize EEPROM, OTP, storage, or other target mutation.
The checked qualification artifact still records `profile.status:
experimental` because it predates the status-only promotion. It remains
acceptable only through the tested promotion rule: the current profile is
`stable` and its status-independent `policy_digest` exactly matches the
recorded value. Any policy-digest change requires new qualification evidence.
See the [evidence boundary](../tests/evidence/README.md).

## Safety boundary

Live probing is read-only with respect to persistent target state, but it is
not passive. The station uploads Raspberry Pi-signed recovery firmware to
volatile RAM through the BCM2712 RPIBOOT protocol. The vendor's
[Raspberry Pi recovery documentation] describes the ordinary recovery payload
as an EEPROM updater; this package instead constructs and checks an immutable
metadata-only bundle containing exactly:

```text
bootcode5.bin  # pinned recovery.bin
config.txt     # exactly: recovery_metadata=1
```

It does not use the vendor `recovery5` updater directory and does not include
`pieeprom.bin`. Adding an EEPROM image, programming directive, erase directive,
or operator-selected payload would cross this probe's safety boundary.

The package checks the patched `rpiboot` executable, both bundle files, and the
complete file set before USB access. It invokes the pinned binary directly,
without a shell, `sudo`, loop mode, overlay, or file-based metadata output:

```text
rpiboot -p <exact-usb-path> -d <immutable-probe-bundle>
```

Metadata is captured from standard output. Do not add `rpiboot -j`: that would
create a second, serial-derived private file outside the wrapper's bounded
capture path.

The metadata-only path can legitimately omit `EEPROM_HASH`, `SIGNATURE_MODE`,
and `ADVANCED_BOOT`. Absence means “not observed”; it must never be interpreted
as a zero, disabled, matching, or otherwise safe value. Adding
`pieeprom.bin` merely to obtain `EEPROM_HASH` is forbidden because it would
turn the recovery session into an EEPROM update attempt.

This unsigned-by-the-customer recovery path is usable only before a customer
secure-boot key is fused. The [Raspberry Pi 5 secure-boot procedure] requires a
customer counter-signature afterward. An owned board therefore needs a
separately approved, customer-counter-signed readback bundle. This profile must
not be widened to accept an owned key hash. See the
[secure-boot design](raspberry-pi-5-secure-boot.md) for that lifecycle boundary.

## Build and station configuration

From a clean checkout of the standalone repository:

```console
nix --accept-flake-config flake check -L
nix --accept-flake-config build .#kaiba-provision \
  --out-link result-kaiba-provision
```

The profile and qualification schema used by the package are available under
its immutable output:

```console
PROVISION_PACKAGE="$(readlink -e result-kaiba-provision)"
PROFILE="$PROVISION_PACKAGE/share/kaiba/device-profiles/raspberry-pi-5-model-b-v1alpha1.json"
QUALIFICATION_SCHEMA="$PROVISION_PACKAGE/share/kaiba/schemas/rpi5-hardware-qualification-v1alpha1.schema.json"
```

The NixOS module is disabled by default. Pin this repository as its own flake
input; there is no nested provisioning leaf:

```nix
{
  inputs.kaiba-provisioning = {
    url = "github:PseudoDesign/kaiba-provisioning/<PINNED_REVISION>";
    inputs.nixpkgs.follows = "nixpkgs";
  };
}
```

A station configuration can import the module explicitly:

```nix
{ inputs, pkgs, ... }:

{
  imports = [ inputs.kaiba-provisioning.nixosModules.provisioning-probe ];

  services.kaiba-provisioning-probe = {
    enable = true;
    package =
      inputs.kaiba-provisioning.packages.${pkgs.stdenv.hostPlatform.system}.kaiba-provision;
    operators = [ "provisioner" ];
  };
}
```

The module installs the package, creates the `kaiba-provision` group, adds only
the named existing users, and grants that group mode `0660` access to USB
vendor/product `0a5c:2712`. It does not create a daemon. Group membership is a
privileged station role because it permits raw access to an attached BCM2712
target, not merely permission to execute a read-only command.

Use one permanently labelled physical lane and one target. Bind the transaction
to a stable sysfs topology path such as `1-2.3`; a changing
`/dev/bus/usb` device number is not a lane identity. The standalone repository
does not provide a ready-to-flash qualification-station image. The operator is
responsible for using a reviewed, pinned station host with private evidence
storage and no unintended target-mutation tools.

## Run a probe

For a live probe, completely remove every target power source, enter RPIBOOT
mode, and run:

```console
"$PROVISION_PACKAGE/bin/kaiba-provision" probe \
  --profile "$PROFILE" \
  --lane-id lane-1 \
  --usb-path 1-2.3
```

The command rejects an absent target, more than one eligible BCM2712 target,
or a target at a different path. Successful parsing writes exactly one JSON
object to standard output. Operational diagnostics go to standard error.

Treat every live result as private inventory data. It includes a timestamp,
lane and USB path, serial, factory UUID, MAC addresses, and a stable target
fingerprint. Store it outside the checkout on approved encrypted storage or a
bounded volatile filesystem, under a private directory and mode `0600`. Never
pipe a raw result into logs or commit it.

Offline mode parses a captured vendor metadata object and performs no USB or
subprocess operation:

```console
nix run .#kaiba-provision -- probe \
  --profile ./profiles/device-classes/raspberry-pi-5-model-b-v1alpha1.json \
  --metadata /absolute/private/path/device-metadata.json
```

Use `--metadata -` to read the object from standard input. Imported evidence
does not carry live tool, bundle, lane, transport, or target-continuity
provenance.

Probe exit status is:

| Status | Meaning |
| --- | --- |
| `0` | Device class and every currently observable baseline condition pass |
| `1` | Unexpected internal failure |
| `2` | Invalid command or device profile |
| `3` | Acquisition, integrity, continuity, or metadata-format failure |
| `4` | Evidence describes an incompatible device class |
| `5` | Device class matches, but an observable baseline condition failed or is indeterminate |

Class and policy failures still produce structured output. An acquisition or
parsing failure does not fabricate an observation.

## Evidence interpretation

The adapter normalizes the factory UUID, user serial, board revision and its
decoded fields, board attributes, boot ROM, Ethernet/Wi-Fi/Bluetooth MACs,
customer-key hash, and VideoCore JTAG state. When supplied, it also normalizes
signature mode, advanced-boot state, and an EEPROM hash. Unknown vendor fields
make the baseline indeterminate until the pinned adapter and profile understand
them. Operation results such as `EEPROM_UPDATE=success` or
`SECURE_BOOT_PROVISION=success` in probe output are a mutation safety violation,
not proof that the probe succeeded.

The target fingerprint is a domain-separated SHA-256 digest over the factory
UUID, user serial, and raw board revision. It correlates observations within a
transaction. It is not proof of private-key possession. USB paths, MAC
addresses, and EEPROM hash are excluded because they are transport observations
or mutable values.

The current profile accepts new-style revision codes for BCM2712 Raspberry Pi 5
Model B only. A Pi 500 or Compute Module 5 shares the processor family but does
not match this class. Its observable fresh-device baseline requires:

- an all-zero customer secure-boot key hash; and
- unlocked VideoCore JTAG.

The probe cannot establish device-private-key rows, unrelated customer OTP,
EEPROM contents or write protection, an authentic installed EEPROM hash,
attached-storage authorization, all debug paths, inventory ownership, prior
transactions, or recovery-firmware authenticity. Those checks remain deferred
and must be closed separately before any mutation proposal.

## Two-probe hardware qualification

Qualification requires a clean, frozen source revision, a station built from
that revision, two live observations separated by complete target power
removal and RPIBOOT re-entry, and matching normal-boot checks before and after.
Any change to the profile policy, adapter, pinned acquisition inputs, or live
path requires a new qualification.

Use this sequence:

1. Record the exact clean source revision and canonical station system closure.
   Confirm both supported architectures passed the relevant checks.
2. Before RPIBOOT, boot the candidate normally from labelled, known-good media.
   Record an observable success criterion, then shut down and remove every
   power source.
3. Run probe 1 and retain its private result.
4. Remove all power, observe USB disconnection, reconnect the same candidate in
   RPIBOOT mode on the same labelled lane, and run probe 2.
5. Compare the two results with normal boot still `pending`. A valid consistent
   preflight exits `7`; a valid quarantine result exits `6`.
6. Boot normally from the same medium and repeat the original success
   criterion. Run the qualifier again with `unchanged` or `failed`.

A minimal private workspace setup is:

```console
umask 077
PRIVATE=/absolute/private/kaiba-hardware-qualification
install -d -m 0700 "$PRIVATE"

SOURCE_REVISION="$(git rev-parse HEAD)"
SYSTEM_CLOSURE="$(readlink -e /run/current-system)"
test -z "$(git status --porcelain=v1 --untracked-files=all)"
test -n "$SYSTEM_CLOSURE"
```

Capture the two live results without `sudo` when the NixOS module's group
boundary is in use:

```console
"$PROVISION_PACKAGE/bin/kaiba-provision" probe \
  --profile "$PROFILE" --lane-id lane-1 --usb-path 1-2.3 \
  > "$PRIVATE/probe-1.json"
chmod 0600 "$PRIVATE/probe-1.json"

# Fully power-cycle the target and re-enter RPIBOOT on the same lane.

"$PROVISION_PACKAGE/bin/kaiba-provision" probe \
  --profile "$PROFILE" --lane-id lane-1 --usb-path 1-2.3 \
  > "$PRIVATE/probe-2.json"
chmod 0600 "$PRIVATE/probe-2.json"
```

Do not continue after either probe returns nonzero. Preserve diagnostics and
quarantine immediately if they report a mutation safety violation.

Run the preflight comparison:

```console
"$PROVISION_PACKAGE/bin/kaiba-provision" qualify \
  --profile "$PROFILE" \
  --first-result "$PRIVATE/probe-1.json" \
  --second-result "$PRIVATE/probe-2.json" \
  --source-revision "$SOURCE_REVISION" \
  --system-closure "$SYSTEM_CLOSURE" \
  --power-cycle-confirmation complete \
  --pre-probe-normal-boot confirmed \
  --normal-boot-confirmation pending \
  > "$PRIVATE/comparison-preflight.json"
```

The expected exit is `7` with status `incomplete`. Exit `6` means stop and
quarantine. Exit `2` or `3`, malformed output, or schema-invalid output means
abort and investigate; tooling failure by itself is not proof that the device
is safe.

After repeating the normal-boot success criterion, create the final record:

```console
"$PROVISION_PACKAGE/bin/kaiba-provision" qualify \
  --profile "$PROFILE" \
  --first-result "$PRIVATE/probe-1.json" \
  --second-result "$PRIVATE/probe-2.json" \
  --source-revision "$SOURCE_REVISION" \
  --system-closure "$SYSTEM_CLOSURE" \
  --power-cycle-confirmation complete \
  --pre-probe-normal-boot confirmed \
  --normal-boot-confirmation unchanged \
  > "$PRIVATE/hardware-qualification.json"
```

Use `--normal-boot-confirmation failed` if the criterion fails. A passing final
record exits `0`; a valid failed/quarantine record exits `6`.

Validate the final record from a clean checkout of the same revision:

```console
nix develop --command check-jsonschema \
  --schemafile schemas/rpi5-hardware-qualification-v1alpha1.schema.json \
  "$PRIVATE/hardware-qualification.json"
```

Only the final whitelist-redacted record is eligible for reviewed publication
as `tests/evidence/sacrificial-pi-5.json`. Update the canonical
`tests/report-input.json` snapshot in the same reviewed closeout. Never
publish either raw probe, the incomplete preflight, arbitrary vendor
extensions, serials, UUIDs, MAC addresses, lane paths, or private operator
context. The final record still contains stable pseudonymous digests and must
receive a publication review.

Stop and quarantine if any persistent observation changes, the target
fingerprint differs, a mutation result appears, or normal boot changes. Hardware
qualification cannot be performed or inferred by CI.

[Raspberry Pi recovery documentation]: https://github.com/raspberrypi/usbboot/blob/master/recovery5/README.md
[Raspberry Pi 5 secure-boot procedure]: https://github.com/raspberrypi/usbboot/blob/master/secure-boot-recovery5/README.md
