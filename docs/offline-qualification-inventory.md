# Offline qualification inventory

Status: **implemented metadata collector; no offline qualification**.

The [owner-fleet follow-on](delivery-scope.md#approved-follow-on-owner-fleet-identity-and-autonomous-boot)
needs exact hardware and running-system inventory before selecting a native OTP
or TPM rollback mechanism. The fixed
[`inventory.py`](../scripts/offline-qualification/inventory.py) collector reads
public metadata from the existing `ace` or `mako` host over authenticated SSH.
It does not deploy a profile or perform a qualification campaign.

## Collection boundary

The only destinations are `adam@ace.local` and `adam@mako.local`, matching the
existing Pi host configuration. SSH requires an already trusted host key,
non-interactive authentication, and disables agent, X11 and port forwarding.
An unknown or changed host key stops collection; establish trust through the
existing administrative procedure before retrying. The collector never scans
for another target or accepts a new host key automatically.
If the owner supplies a trusted fingerprint, first compare the offered key
against that exact fingerprint and retain the matching key in a private task
file. `--known-hosts /absolute/private/known_hosts` uses that explicit trust
anchor with strict checking and leaves the user's normal trust store unchanged.

The fixed target commands read model, architecture, kernel, current NixOS
closure, root mount and storage types, two bootloader device-tree properties,
TPM interface presence, UTC/NTP status, and activity of a small service list.
The only sudo command is `vcgencmd bootloader_version`, which reads the public
firmware version. No OTP dump, raw key read, cryptographic operation, lock
change, TPM operation, firmware update, reboot, disk write or service change is
part of collection. Unsupported commands and inaccessible properties remain
`not-observed`; an empty successful result never becomes zero or disabled.

Existing complementary tools remain separate:

- [`kaiba-provision probe`](raspberry-pi-5-provisioning-probe.md) can obtain
  bounded RPIBOOT metadata without persistent changes. It uploads recovery
  firmware into RAM, and its unfused-board profile must not be reused for an
  owned Pi without the reviewed owned-board readback path.
- The metadata companion described in the
  [slot inventory observation](observations/2026-09-17-device-secret-metadata.md)
  reads slot count, status and usage without requesting secret contents. Those
  fields do not establish a monotonic counter, slot suitability or key secrecy.
- [`native-offline-evidence.nix`](../nix/modules/native-offline-evidence.nix)
  checks the reviewed candidate's read-only dm-verity mapping and public file
  digests. It does not establish a rollback floor.

## Retain private evidence

Run from the provisioning station, choosing a new absolute directory outside
the checkout and Nix store:

```console
python3 -B scripts/offline-qualification/inventory.py \
  --target mako --output-dir /tmp/kaiba-offline-inventory-mako-session
```

Collection executes no remote file write. It retains `raw.txt`,
`inventory.json`, and the exact `collector.py` source locally with mode `0600`,
in a new directory with mode `0700`.
Keep them private and move them into approved evidence retention before the
temporary filesystem is cleared. Existing outputs are never overwritten.
The complete, closed transcript has per-command exit codes; its SHA-256 and
the exact collector source SHA-256 accompany the projection. Captures are
bounded to 16 KiB per field, 256 KiB total and a 45-second SSH lifetime.

The local draft envelope is
`kaiba.offline-qualification-inventory/v1alpha1`. Its `observations` contain
either `state: observed` and `value`, or `state: not-observed` and `exit_code`.
Service activity uses systemctl's nonzero inactive-state result where
applicable; it is not proof a service is installed or correctly configured.
The station collection time and target-reported UTC are separate fields.
This envelope is internal to provisioning; no shared contract version or
consumer pin changes.

The projection is a target self-report over an authenticated host connection,
not boot attestation. Digests bind retained bytes; they do not authenticate
the truth of a compromised target's output. Review any public summary
separately; the collector leaves `publication_authorized` false and does not
export serials, SSH keys, addresses, OTP contents or private configuration.

## Qualification remains open

An absent signed-boot property does not prove secure boot is disabled. An
absent TPM interface does not prove no chip is attached. NTP synchronization
does not establish time continuity through network loss or extended power-off.
An encrypted writable root does not prove a verified boot chain, device-bound
key release or replay-resistant security state.

Every collected report keeps `hardware_qualified`,
`boot_chain_authenticated`, `offline_rollback_qualified`,
`clock_continuity_qualified`, and `execution_authority` false;
`fleet_admission` remains `unevaluated`. These are limits of the evidence, not
negative test results about the device. The twelve
[offline qualification gates](https://github.com/PseudoDesign/kaiba-infra/blob/codex/spiffe-spire-next-steps/docs/offline-qualification.md)
still require the exact profile, permitted old/recovery images, state-commit
protocol, independent observations, and applicable physical campaign.

Run the isolated software checks with:

```console
python3 -B -m unittest discover -s tests/offline-qualification -p 'test_*.py' -v
scripts/check.sh contracts offline-qualification-inventory
```

The [Mako](observations/2026-09-29-mako-offline-inventory.md) and
[Ace](observations/2026-09-29-ace-offline-inventory.md) observations record live
collections and their limits.

The subsequent [temporary native SPIRE smoke](ace-spire-smoke.md) uses Ace's
exact inventoried system and pinned software. Its
[passing runtime observation](observations/2026-09-29-ace-spire-smoke.md)
records software behavior only; the inventory's boot, rollback and time gates
remain open.

For the later persistent identity pilot, the separate
[read-only warm-reboot observer](identity-reboot-observation.md) compares the
intended generation, public identity, trust-bundle/enrollment digests and
existing services across two captures. It rejects stale preboot probe output
and performs no reboot or host mutation. A passing comparison remains software
acceptance evidence; the physical and offline qualification gates stay open.
