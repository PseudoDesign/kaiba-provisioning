# Raspberry Pi 5 initramfs stable-verifier spike

## Status and boundary

The repository now contains the software contracts and Nix assembly boundary
for the first stable-verifier spike. It does not contain a reviewed Raspberry
Pi 5 firmware/kernel pin, a root-signed hardware artifact, or live Pi evidence.
The software contract check builds fixture artifacts and evaluates the
initramfs module, while the VM checks exercise representative failure and
authenticated handoff paths under QEMU. They make no claim that NVMe, RP1
networking, kexec handoff, or failure behavior has passed on Pi hardware.

This slice uses a Linux systemd initramfs as the exclusive verifier gate.
U-Boot and FIT verification are outside this implementation.

## Trust and data flow

The stable boot artifact contains the Pi firmware tree, verifier initramfs,
verifier binary, inline-root-signed policy, root public key, explicit test
authority CA, and immutable source provenance. Routine delegated releases live
in a separate read-only NVMe directory and contain exactly:

```text
cmdline.txt
device-tree.dtb
dm-verity.json
initramfs
kernel
release-manifest.json
root.img
slot.txt
overlays/<lowercase-name>.dtbo  # zero or more; [a-z0-9][a-z0-9_-]{0,63}
```

For this first cut, signed `device-tree.dtb` is the fully resolved device tree
passed to kexec. Allowlisted overlay files are authenticated provenance and
test inputs only; the verifier does not apply them dynamically. A release that
needs overlays must resolve them into `device-tree.dtb` before signing.

The verifier copies every later-consumed handoff component into an immutable,
sealed in-memory snapshot while hashing it. `root.img` is the bounded
exception: it stays disk-backed because it is not passed to kexec and the
released initramfs must enforce its signed dm-verity metadata. Overlay handles
are closed after hashing and are not exposed to the handoff API.

At boot, the initramfs mounts the NVMe release directory read-only, obtains
DHCP on the configured RP1 interface, and invokes
`kaiba-rpi5-stable-verifier`. The verifier receives the policy, root public
key, expected cohort/slot/epoch/version, explicit authorization URL and CA,
selected authority key ID, expected authorization audience, release directory,
logical non-production identity, and pinned kexec path as separate argv
entries. Core arguments cannot be overridden through the module's
`extraArguments` option.

The module fixes the executable name and accepts only a package declaring the
static, initramfs-only, non-production verifier contract. Authorization and
bootstrap timeouts remain the verifier's bounded defaults for this cut and
cannot be changed through `extraArguments`.

Systemd disables its initramfs shell and emergency access. A verifier return,
whether successful or failed, forces poweroff; a valid path is therefore
expected to leave the first stage only by executing the authenticated kexec
handoff.

## Exported Nix interfaces

| Interface | Purpose |
| --- | --- |
| `nixosModules.stable-verifier-spike` | Installs the verifier and public trust inputs in a systemd initramfs, mounts `KAIBA_RELEASE` read-only, configures bounded networking, and creates the fail-closed verifier unit |
| `mkRpi5StableVerifierUnsignedBoot` | Builds a deterministic `boot.img` from an exact caller-supplied firmware tree plus public verifier inputs; requires an exact Pi platform revision and NAR hash |
| `mkRpi5StableVerifierTestSD` | Verifies an externally produced canonical Raspberry Pi `boot.sig` under the selected RSA-2048 root public key, then emits the outer FAT boot filesystem containing only `boot.img`, `boot.sig`, and `config.txt` |
| `mkRpi5DelegatedReleaseSpike` | Copies the fixed release roles and optional `.dtbo` overlays into an exact, read-only `nvme-release/` payload; runtime signature validation remains the verifier's responsibility |
| `mkRpi5StableVerifierSpikeRig` | Groups a verified test-SD filesystem artifact with its delegated NVMe release payload without writing a device |

All constructors are authority-free. They reject symlinks and unexpected
paths, scan inputs for recognizable PEM/OpenSSH private keys, and publish
negative capability metadata such as `hardwareObserved = false` and
`productionReady = false`. The test-SD output is a FAT filesystem image, not a
whole-device image or permission to write an SD card.

The stable policy contains its root signature inline. `boot.sig` is a distinct
Raspberry Pi signature over the complete `boot.img`; it must be created outside
Nix and is cryptographically checked before the test-SD artifact is assembled.
Private signing material must never be passed to a constructor.

The flake also exports static `kaiba-rpi5-stable-verifier`,
`kaiba-rpi5-verifier-test-authority`, and `kaiba-rpi5-one-boot-prove`
executables. All three are explicitly non-production. The test authority takes
its TLS and authority private keys only from runtime paths; no key is embedded
in its package. The one-boot proof client consumes the handoff's ephemeral
private key, removes that key before its outbound TLS request, and cannot sign
authority responses.

## QEMU VM checks

The flake exposes two complementary VM checks. On x86_64, QEMU and the NixOS
test driver remain native to the host while an AArch64 builder (local binfmt or
a remote builder) produces the guest closure:

```console
nix build .#checks.x86_64-linux.stable-verifier-initramfs-vm --no-link -L
nix build .#checks.x86_64-linux.stable-verifier-aarch64-kexec-vm --no-link -L
```

The real-kexec check is also exported as
`checks.aarch64-linux.stable-verifier-aarch64-kexec-vm` for native AArch64
builders.

`stable-verifier-initramfs-vm` is an aggregate that forces both x86_64
initramfs scenarios:

- `fail-closed` boots the actual generated systemd initramfs with no initrd
  backdoor, attaches an ext4 release device, checks that the release is mounted
  `ro,nosuid,nodev,noexec`, rejects an invalid root-policy signature, emits the
  structured `release-verification-failed` event, never reaches stage 2, and
  powers off.
- `signed-handoff` boots the same module against a deterministic signed release
  and a separate test-authority VM. It covers TLS server validation,
  out-of-band bootstrap registration, signed policy and delegated-release
  verification, fresh authorization, retained kernel/initramfs/DTB descriptors,
  and the fixed kexec argument shape. A fake kexec executable prevents a host
  kexec syscall; its return must emit `kexec-execute-failed` and force poweroff.
  Its deterministic authority and signing keys are intentionally public test
  fixtures in the Nix store, copied into owner-only runtime paths before use;
  they are not secrets and must never be reused outside this VM check.

`stable-verifier-aarch64-kexec-vm` runs an AArch64 QEMU `virt` machine. It
creates the signed release inside the disposable VM using QEMU's runtime DTB,
performs the authorization exchange with the actual verifier and test
authority, and makes real kexec syscalls into a minimal second kernel/initramfs.
The handoff forces the legacy `kexec_load` syscall so the authenticated DTB is
consumed on AArch64; a signed test-only DT property is then checked by the
second initramfs.
Current arm64 `kexec-tools` also needs `CAP_SYS_ADMIN` to read `/proc/iomem` for
that legacy load. The spike grants it explicitly to the verifier service while
blocking mount-family syscalls. Replacing this broad temporary capability with
a narrowly scoped loader broker or loader implementation remains follow-on
hardening.
The verifier service mirrors the initramfs module's capability bounding,
no-new-privileges, device, namespace, and syscall controls while doing so,
although it starts after the first VM has reached stage 2. Its writable fixture
directory and co-located test authority mean this mechanical kexec check does
not prove the initramfs module's read-only release mount or authority-process
isolation. Authority private-key files are removed once the authority has
loaded them; the separate-authority x86 check covers the process/VM boundary.
The second stage confirms the authenticated command line and the presence and
modes of the authorization, one-boot private key, dm-verity metadata, and slot
handoff files; it then removes the one-boot key and powers off. Test-only
private keys are generated or copied only into disposable VM runtime storage.

These checks test software behavior, not Raspberry Pi 5 hardware. In
particular, QEMU only observes the signed dm-verity metadata handoff; it does
not create or enforce a real dm-verity mapping. Neither check exercises Pi
firmware, the Pi boot ROM/EEPROM path, RP1 storage or networking, NVMe behavior,
or Pi-specific kexec reliability. The physical sacrificial Pi 5 campaign below
remains required before making any hardware or production-readiness claim.

## Supplying the Pi platform

This flake intentionally does not add a floating `nixos-raspberrypi` input.
Before a hardware build, select and review one immutable upstream commit, lock
its NAR hash, and use that same source to produce the Pi firmware tree, vendor
kernel, modules, DTB, and initramfs. Pass its exact revision and NAR hash to
`mkRpi5StableVerifierUnsignedBoot`; changing either changes the declared boot
provenance.

The caller must extend `initrdKernelModules` with the exact RP1 storage and
network drivers supplied by that pinned kernel. The default contains only
`nvme` and is an evaluation-safe baseline, not a hardware-qualified driver
list.

## Remaining hardware gate

The spike is not validated until the unfused sacrificial `a04171` Pi completes
the positive, delegated-key replacement, mutation, replay, one-boot-key, and
DTB/command-line observation matrix described in the
[production security follow-on](raspberry-pi-5-production-security-follow-on.md).
In particular, successful Nix builds do not establish that Pi 5 kexec is
reliable. Failure of authenticated handoff is a recorded blocker; it does not
authorize an unsigned fallback or a production-readiness claim.

Machine-readable evidence uses the fixed
`kaiba.provisioning.rpi5-stable-verifier-campaign/v1alpha1` profile. A
`validated` result requires one passing result for every test below. Every
outcome carries the same fixed-order matrix; tests not reached in a stopped
campaign use the `blocked` code. Test results are closed codes rather than
free-form output, and raw observations remain outside the publishable evidence
envelope behind their record digests.

- approved release boots;
- offline authorization is rejected;
- authorization replay is rejected;
- component-byte mutations are rejected;
- a replacement delegated key boots;
- dm-verity corruption is rejected;
- the authenticated kernel command line is observed;
- manifest-field mutations are rejected;
- the one-boot key is bound and usable once;
- released OS code cannot reuse the bootstrap operation;
- the authenticated resolved device tree is observed;
- revoked, unsigned, and wrong-key releases are rejected.
