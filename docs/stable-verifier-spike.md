# Raspberry Pi 5 initramfs stable-verifier spike

## Status and boundary

The repository now contains the software contracts and Nix assembly boundary
for the first stable-verifier spike. A development Pi has completed the narrow
file-mode self-kexec and SMP differential described below, but the repository
does not contain a completed, publishable Raspberry Pi 5 verifier qualification
result or a production-approved root-signed hardware artifact. The software
contract check builds fixture artifacts and evaluates the initramfs module,
while the VM checks exercise representative failure and authenticated handoff
paths under QEMU. Neither those VM results nor the narrow physical diagnostic
establish NVMe, RP1 networking, the complete signed-verifier handoff, or its
failure behavior on Pi hardware.

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

In the default `legacy-explicit-dtb` mode, signed `device-tree.dtb` is the fully
resolved device tree passed to kexec. Allowlisted overlay files are
authenticated provenance and test inputs only; the verifier does not apply
them dynamically. A release that needs overlays must resolve them into
`device-tree.dtb` before signing.

The verifier also contains an explicitly selected
`experimental-file-live-fdt` path. The release DTB is still authenticated as a
manifest component, but that mode neither opens nor passes it at the handoff
boundary. Before generating a one-boot key or contacting the authorization
service, it bounded-reads the fixed `/sys/firmware/fdt` path and validates the
kernel-owned live Pi 5 tree against the authenticated release command line.
The initramfs module uses a typed mode option, defaults to legacy, prevents
`extraArguments` from overriding the selection, and omits `CAP_SYS_ADMIN` in
file mode. Selecting that mode also fails module evaluation unless exactly one
copy of the reviewed non-null arm64 in-place patch is present, its structured
policy option is enabled, and no package or patch-level structured or legacy
configuration competes with it. This candidate is present for controlled
diagnostics; the hardware constructor does not select it by default. Directly
invoking the verifier binary with this mode is outside the supported boundary:
only the guarded Nix module couples the selection to the reviewed kernel
policy.

`mkRpi5DelegatedReleaseSpike` enforces the current Pi 5 kexec-input contract
before copying a release. The signed tree must identify a Pi 5 BCM2712, describe
more memory than the vendor base tree's known 640 MiB placeholder using
non-overlapping regions, map the enabled `serial10` PL011 to physical address
`0x107d001000`, and select it from
`/chosen/stdout-path` as `serial10:115200n8`. The signed command line must
contain exactly one `console=ttyAMA10,115200n8` and exactly one
`earlycon=pl011,0x107d001000,115200n8`. Firmware-only `serialN` and `uartN`
console aliases are rejected because firmware does not run again to rewrite
them during kexec. To keep the validator's token boundaries identical to the
kernel's for this fixed spike, the command line is restricted to printable
ASCII arguments separated by one ASCII space, without quoting, escapes,
noncanonical whitespace, or the kernel `--` argument terminator. Its textual
payload is limited to 2,047 bytes so the pinned arm64 kernel's 2,048-byte
`COMMAND_LINE_SIZE` always has room for the terminating NUL. This validation
establishes the input shape; it does not establish that a physical Pi accepts
the handoff.

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
| `mkRpi5StableVerifierTestSD` | Verifies an externally produced canonical Raspberry Pi `boot.sig` under the separately supplied Pi firmware-signing public key, then emits the outer FAT boot filesystem containing only `boot.img`, `boot.sig`, and `config.txt` |
| `mkRpi5DelegatedReleaseSpike` | Validates the resolved Pi 5 DTB and explicit debug-UART command line, then copies the fixed release roles and optional `.dtbo` overlays into an exact, read-only `nvme-release/` payload; runtime signature validation remains the verifier's responsibility |
| `mkRpi5StableVerifierSpikeRig` | Groups a verified test-SD filesystem artifact with its delegated NVMe release payload without writing a device |
| `mkRpi5ReleasePayloadQemuVirt` | Runs the exact manifest-bound release kernel and initramfs on generic AArch64 QEMU `virt`, with a QEMU-generated DTB and a QMP shutdown witness; this is a diagnostic constructor, not Pi 5 emulation |
| `mkRpi5KernelQemuVirtBeacon` | Reuses the exact manifest-bound release kernel with a generated static-BusyBox beacon initramfs under generic AArch64 QEMU `virt`, isolating kernel/machine compatibility from release userspace |
| `packages.*.kaiba-rpi5-kexec-input-validate` | Checks the resolved Pi 5 DTB and command-line contract used by the delegated-release builder |
| `packages.aarch64-linux.kaiba-rpi5-self-kexec-diagnostic` | Prepares, and only after a separate explicit confirmation executes, the development Pi 5 self-kexec isolation experiment described in its runbook |

The boot and release assembly constructors are authority-free. They reject
symlinks and unexpected paths, scan inputs for recognizable PEM/OpenSSH private
keys, and publish negative capability metadata such as
`hardwareObserved = false` and `productionReady = false`. The test-SD output is
a FAT filesystem image, not a whole-device image or permission to write an SD
card. The QEMU and self-kexec interfaces are diagnostics and perform no signing
or authorization operation.

The stable policy contains its release-policy-root signature inline. `boot.sig`
is a distinct Raspberry Pi signature over the complete `boot.img`; it must be
created outside Nix and is checked against the separately supplied Pi
firmware-signing public key before the test-SD artifact is assembled. This
preserves the design's separation between the rarely used Pi customer key and
the release-policy hierarchy. Private signing material must never be passed to
a constructor.

The flake also exports static `kaiba-rpi5-stable-verifier`,
`kaiba-rpi5-verifier-test-authority`, `kaiba-rpi5-one-boot-prove`, and
`kaiba-rpi5-kexec-input-validate` executables. All are explicitly
non-production. The test authority takes its TLS and authority private keys
only from runtime paths; no key is embedded in its package. The one-boot proof
client consumes the handoff's ephemeral private key, removes that key before
its outbound TLS request, and cannot sign authority responses.

## QEMU VM checks

The flake exposes complementary VM checks. The generated-initramfs scenarios
run on x86_64:

```console
nix build .#checks.x86_64-linux.stable-verifier-initramfs-vm --no-link -L
```

The real-kexec checks build and boot native AArch64 NixOS closures and are
exported only for native AArch64 builders:

```console
nix build .#checks.aarch64-linux.stable-verifier-aarch64-kexec-vm --no-link -L
nix build .#checks.aarch64-linux.stable-handoff-aarch64-kexec-file-vm --no-link -L
```

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

`stable-handoff-aarch64-kexec-file-vm` isolates the experimental kernel
mechanism from the Pi-specific verifier policy. It patches the generic AArch64
guest kernel with the same in-place-only policy, presents four virtual CPUs,
and boots stage one with `maxcpus=1 cma=128M`. Through the repository's actual
`stablehandoff.PrepareInitramfs` and experimental `Plan.Load`/`Plan.Execute`
path, the positive node requires a sealed credential-bearing initramfs,
inherited `/proc/self/fd` inputs, a service limited to `CAP_SYS_BOOT`, an exact
128 MiB CMA reservation, and no userspace DTB. It requires
`kexec_file_load ... head:0x4`, arm64 `head: 4` (`IND_DONE`), and
`kern_reloc: 0` diagnostics. Its minimal static-BusyBox second stage must see
CPUs 0 through 3 online, the exact replacement command line and credential
archive, and a canary placed in the QEMU-generated first-stage boot DTB and
inherited through the kernel-generated file-mode FDT before powering off. A
second node boots with `cma=0` and requires the same kernel policy to refuse
the relocating load without calling `Plan.Execute`. A successful check shows
that this controlled generic arm64 environment can restart secondaries that
were never onlined in stage one and that its tested relocation fallback fails
closed. It does not run the Pi-only live-FDT validator or authorization client
because QEMU `virt` correctly fails the Pi 5 platform identity contract. The
validator has focused unit coverage, the mode wiring and kernel-policy
requirement have Nix evaluation coverage, and authorization has the existing
legacy-mode integration coverage; their end-to-end composition in
experimental mode still requires physical execution.

These checks test software behavior, not Raspberry Pi 5 hardware. In
particular, the verifier integration check only observes the signed dm-verity
metadata handoff; it does not create or enforce a real dm-verity mapping. None
of these checks exercises Pi firmware, the Pi boot ROM/EEPROM path, RP1 storage
or networking, NVMe behavior, or Pi-specific kexec reliability. The physical
sacrificial Pi 5 campaign below remains required before making any hardware or
production-readiness claim.

### Exact-payload diagnostic and its limits

`mkRpi5ReleasePayloadQemuVirt` is a parameterized diagnostic constructor, not a
default flake check. It verifies the manifest digests and boots byte-identical
copies of a supplied release's kernel and initramfs. QEMU's generic AArch64
`virt` machine is not a Raspberry Pi 5: the diagnostic deliberately replaces
the release DTB with QEMU's runtime DTB and selects QEMU's PL011 as
`console=ttyAMA0` with an early console at `0x09000000`. Success requires both
a QMP guest-shutdown event and a clean QEMU exit. Setting
`requireGuestPoweroff = false` selects evidence mode, which retains structured
logs and returns an artifact when that requirement is not met.

The current campaign payload produced no PL011/UART console bytes and no QMP
guest shutdown in that evidence mode. This is a negative diagnostic
observation, not a Pi 5 result and not proof that the release initramfs ran. It
shows only that the exact kernel/initramfs pair did not reach either configured
witness in that generic-QEMU experiment; the kernel, QEMU machine
compatibility, early boot, and initramfs boundary remain unresolved by that
run.

The follow-up `mkRpi5KernelQemuVirtBeacon` differential kept the exact campaign
kernel (`sha256:93abfecfcba24b799da5f633fa8853648de06660a9b4302564ea65e28c6baa08`)
but replaced release userspace with a validated static-BusyBox beacon
initramfs. It likewise produced no PL011 bytes and no QMP shutdown within 90
seconds. This moves the generic-QEMU boundary earlier than release userspace:
that environment does not currently demonstrate entry into this Pi kernel, so
it cannot be used to judge the campaign initramfs. It still says nothing about
kernel entry on BCM2712 hardware.

### Diagnostic isolation ladder

Use the checks and hardware diagnostic in this order so that each result has a
bounded interpretation:

1. Run `stable-verifier-initramfs-vm` to test the generated initramfs module,
   authenticated release/authorization flow, immutable handoff descriptors,
   failure closure, and fixed kexec arguments without issuing a real kexec.
2. Run `stable-verifier-aarch64-kexec-vm` to test a real legacy AArch64
   `kexec_load` transition under generic QEMU `virt`, using QEMU's runtime DTB
   and the test's minimal second stage. This proves generic mechanics only.
3. Run `stable-handoff-aarch64-kexec-file-vm` to test a direct, fail-closed
   `kexec_file_load` transition from a one-CPU first stage into a four-CPU
   second stage, retaining a live-FDT canary under generic QEMU `virt`.
4. Instantiate `mkRpi5ReleasePayloadQemuVirt` for the exact release to probe
   whether its kernel/initramfs can reach a PL011 or QMP shutdown witness on
   generic `virt`. Preserve negative evidence; do not translate it into a Pi
   hardware claim.
5. Instantiate `mkRpi5KernelQemuVirtBeacon` with the same exact release kernel
   and a known static AArch64 BusyBox. Reaching its unique PL011 marker and a
   clean QMP shutdown distinguishes kernel/QEMU compatibility from release
   initramfs behavior; silence still does not imply a Pi 5 failure.
6. On the sacrificial development Pi, use the
   [self-kexec diagnostic](../scripts/diagnostics/rpi5-self-kexec/README.md) to
   test the running kernel with the live firmware DTB and a minimal beacon
   initramfs. Preparation is non-executing; the disruptive handoff requires a
   separate explicit confirmation and trusted UART capture.
7. Only after the lower-level transition is understood, retry the complete
   signed verifier path with a delegated release that passes the resolved-DTB
   and explicit-console validator.

The observed self-kexec beacons establish only that this Pi can perform the
narrow transitions recorded below with the running kernel and the applicable
live-FDT handoff. Silence, a Linux early-console trace without the beacon, and a
beacon each narrow the boundary differently as described in the runbook. None
alone completes the signed-release campaign.

### Development Pi file-handoff observations

On 2026-09-10, the development-key-fused `a04171` Pi completed the bounded
`file-live-fdt` self-kexec diagnostic with the running 6.18.42 development
kernel, a minimal static-BusyBox beacon initramfs, and a target DTB generated
by file mode from the running kernel's initial firmware tree. The first kernel
reported `head:0x4` and `kern_reloc=0`
for the loaded image, crossed `kexec_core: Starting new kernel` and `Bye!`, and
the second kernel reached `/init`. The beacon reported
`KAIBA_RPI5_SELF_KEXEC_RESULT:second-stage-init-reached` before a clean
poweroff. The retained raw UART log has SHA-256
`0dae5021d2e933bc9071464f4c8cabf161b972936ae976cd5bdc36f0d98daa47`.
The exact retained live DTB (81,022 bytes, SHA-256
`0d304ba74e6321c94222545d76bb19c90de26fe4992335cc038f7cb17b0fd5fa`)
and second-stage command-line file (165 bytes, SHA-256
`eea2ef94a591b99966f5f76bb59bbf87faf8bc3b05ede969628d398e05e76ef0`)
also pass the repository's `kaiba-rpi5-kexec-input-validate` implementation.
That replay shows that the new parser accepts the observed platform inputs; it
does not add a second hardware execution result.

This is positive evidence for the arm64 `kexec_file_load` direct handoff on
this board. It is not yet a verifier qualification result. The experiment
changed both the syscall/relocation path and the DTB source relative to the
failed signed-verifier handoff, so it does not distinguish a legacy relocation
failure from an explicit-DTB failure. CPUs 1 through 3 timed out while coming
online in that run, so a separate first-stage CPU-state differential was
required before attributing the result to persistent second-kernel SMP
failure.

On 2026-09-11, that differential completed with classification `SMP_PASS`. The
signed diagnostic first stage contained exactly one `maxcpus=1`: CPUs 0 through
3 were present, CPU0 was online, and CPUs 1 through 3 were offline. The fixed
second-stage command line contained no `maxcpus`; it reached
`KAIBA_RPI5_SELF_KEXEC_RESULT:second-stage-init-reached` with CPUs 0 through 3
already online both before and after the diagnostic. It made no CPU-online
attempts and reported no CPU-online failures. This rules out the hypothesis
that the file-mode handoff depends on secondary CPUs having been initialized by
the first kernel.

The raw campaign evidence remains outside Git under campaign ID
`rpi5-maxcpus1-physical-20260911-84808df9` in the operator's protected local
state directory.
The prepared archive has SHA-256
`ea40524631ff819b37860a5ae14b61f75576f643ff33031d7d9b75233080b401`,
the execution UART segment has SHA-256
`da7a2a38fdb05490272a843ac402dfc8c735aeeded7f8511075f11ef676f35e6`,
and the full UART capture has SHA-256
`36017e8f69e330ed10edbd65a4773a4ccaa9b1a744f10e267d975fd43b62786a`.
After the diagnostic powered off, the known-good development boot partition was
restored bit-for-bit, read back as
`dd4f2832b40000bbcc7eb67d3302f83edebcf388fa52b956ec8df2f0c001056b`,
and smoke-tested on the Pi.

The successful differential removes SMP initialization as the current blocker;
it does not make `kexec_file_load` the stable verifier's default handoff or
complete the physical verifier gate. A candidate file-mode verifier must still
validate the live firmware DTB under stable platform policy, reserve enough CMA
for the complete release kernel and augmented initramfs, fail closed rather
than silently falling back to the legacy relocation path, and pass the complete
signed-verifier hardware matrix below.

## Supplying the Pi platform

The flake pins `nixos-raspberrypi` revision
`7e39508bcf9c1da82cf11c1e22f74f9d9fd0fe10` with source NAR hash
`sha256-KT/OleUMpSKsWgi0eTuqS/0GD4ucPQcvLgmvlw8ZuCM=`. It supplies the matched
Pi 5 vendor kernel `6.18.34-unstable_20260604` and firmware `1.20260521` used by
`mkRpi5StableVerifierHardwareSystem`. The firmware tag resolves to upstream
`raspberrypi/firmware` commit
`09267f5354d40519d82fbd2193b9e211ec304055`, which the constructor exports as
the evidence-facing firmware revision. The hardware constructor imports the Pi
5 base module, selects direct `kernelboot-legacy-unsupported` firmware loading
without U-Boot, evaluates the stable-verifier initramfs, and exposes a
deterministic firmware tree for the unsigned-boot constructor. Changing the
platform revision or NAR hash changes the declared boot provenance and
requires renewed review and hardware qualification.

The generic `mkRpi5StableVerifierHardwareSystem` retains its reviewed legacy
default. The dedicated
`mkRpi5StableVerifierFileLiveFDTHardwareSystem` constructor fixes the physical
candidate to `experimental-file-live-fdt`; its evaluation check requires the
in-place-only arm64 patch, exact `cma=128M`, `CAP_SYS_BOOT` without
`CAP_SYS_ADMIN`, and no userspace DTB argument. U-Boot comparison is deferred
and is not part of this first-cut verifier campaign.

The reviewed kernel builds the BCM2712 PCIe host, NVMe, and RP1 `macb` Ethernet
drivers into the kernel. The hardware composition retains `nvme` in
`initrdKernelModules` so a future reviewed platform that modularizes it cannot
silently omit it. Any platform-pin change requires the storage and network
driver disposition to be reviewed again.

The authenticated verifier firmware tree also applies the fixed `dwc2`
peripheral-mode overlay used by the development target's USB gadget management
lane. In file/live-FDT mode that resolved firmware tree crosses the kexec
boundary, allowing post-handoff evidence collection on the existing USB link;
the verifier itself continues to obtain authorization only through its pinned
RP1 Ethernet interface.

The vendor kernel enables only `kexec_file_load` by default. That syscall
cannot consume the verifier's separately authenticated device tree, so the
hardware composition also enables `SUSPEND` (which makes arm64
`ARCH_SUPPORTS_KEXEC` available) and `KEXEC` for the current legacy default.
The hardware-evaluation check asserts the resulting
`CONFIG_PM_SLEEP_SMP=y`, `CONFIG_ARCH_SUPPORTS_KEXEC=y`, and `CONFIG_KEXEC=y`
settings. Removing any of them makes the legacy handoff unavailable.

For the experimental file path, the pinned kernel carries a narrow arm64 patch
that enables `CONFIG_ARM64_KEXEC_FILE_REQUIRE_IN_PLACE`. A normal
`kexec_file_load` is rejected with `EOPNOTSUPP` unless arm64 has terminated the
load with `IND_DONE`, the same predicate its execution path uses to bypass the
relocator. Legacy loads and crash kernels retain their existing behavior. This
kernel control is required because the upstream userspace ABI does not expose
an authoritative direct-load result and an ordinary CMA allocation failure can
otherwise fall back silently to relocation. `head:0x4` remains useful evidence,
not the enforcement mechanism.

The boot command line reserves exactly `cma=128M`; the vendor configuration's
32 MiB default is smaller than the complete release kernel plus augmented
one-boot initramfs. The in-kernel requirement remains fail closed if the
reservation is unavailable or fragmented despite that sizing.

## Remaining hardware gate

The spike is not validated until the development-key-fused sacrificial
`a04171` Pi completes
the positive, delegated-key replacement, mutation, replay, one-boot-key, and
DTB/command-line observation matrix described in the
[production security follow-on](raspberry-pi-5-production-security-follow-on.md).
In particular, successful Nix builds do not establish that Pi 5 kexec is
reliable. Failure of authenticated handoff is a recorded blocker; it does not
authorize an unsigned fallback or a production-readiness claim.

Machine-readable evidence uses the fixed
`kaiba.provisioning.rpi5-stable-verifier-campaign/v1alpha1` planning profile.
The current `v1alpha2` execution envelope contains `planned_claims`, not
fulfilled claims, pass/fail, outcome, or disposition fields. Its public
evidence checker establishes only
`unauthenticated-record-consistency-only`, and the explicit planned-claim
closure API always fails closed until claim-specific authenticated witnesses
and independently derived sealed expectations are implemented. Therefore no
current execution envelope can be called a validated campaign result.

The code-derived witness-requirement matrix makes that gap explicit for every
planned claim. Shared requirements include independently resolved run
artifacts, exact media readback, a provenanced cold-power observation, and an
authenticated complete verifier trace. Separate claim requirements cover the
released-OS command line, live-FDT invariant continuity, exact one-boot-proof
replay rejection, exact bootstrap-signed request replay rejection, stale
authorization replay, and runtime dm-verity rejection. These are outstanding
requirements only; the matrix has no observed, satisfied, pass, outcome, or
closure field.

Those 14 result identifiers are logical groups, not a promise of 14 physical
boots. The fixed campaign plan derives exactly 33 one-based physical runs and
37 logical claims: the positive baseline supplies five claims, while each
single-difference negative fixture has its own run and evidence record.
Component mutation covers every fixed release component, manifest mutation
covers one representative occurrence of every security-relevant manifest
field class, and dm-verity corruption covers both data and hash inputs. The
manifest cases exercise the shared parser and signature boundary; they do not
claim one physical run for every repeated component, overlay, or signature
array element.

`mkRpi5StableVerifierCampaignRun` materializes those 33 fixed runs from the
sealed positive-baseline artifact set. It accepts only that typed baseline and
a one-based run index, derives the corresponding run and mutation from the
campaign plan, and creates a new four-partition payload set in the Nix store.
The three no-mutation runs preserve all four baseline payload digests. Of the
30 negative runs, 28 change only the release-filesystem payload, one changes
only root data, and one changes only the root-hash payload. Every other payload
must remain byte-identical to the baseline. The manifest-replacement cases also
prove that every non-target file's contents in the release filesystem are
unchanged; the byte-XOR cases prove the selected file or direct-media target
changed at exactly one byte.

The materializer re-resolves all 27 public inputs and 10 mutation targets before
emitting a domain-separated, digest-bound run materialization record. This is a
deterministic build-time relationship over newly created files only. It cannot
write a block device, contact signing hardware, perform a private-key operation,
execute a run, observe hardware, or close a campaign claim. The original
positive-baseline `ArtifactSet` remains immutable and mutation-free; staging and
physical readback require separate, approval-gated capabilities that are not
implemented in this cut.

`kaiba-rpi5-stable-campaign-plan` constructs descriptive plan data from exactly
27 named public inputs and 10 named byte-mutation targets. It rejects symlinks,
rejects non-regular inputs before reading their contents, and rejects reuse of
one opened `(device, inode)` identity across input roles. It computes mutation
digests without modifying source files and emits canonical create-only JSON.
Artifact-role labels remain caller declarations: the tool does not prove that
the supplied bytes came from the reviewed release tree, artifact set, media,
or hardware, and its output does not authorize signing, staging, physical
execution, or claim closure. Its private-key PEM marker check is scoped
defense-in-depth, not proof that opaque caller files contain no private
material. `kaiba-rpi5-stable-campaign-gpt-inspect` is a
separate read-only prerequisite. It requires the leg's fixed hostname string,
but that string comparison is not host authentication. It resolves only the
leg's fixed selector, requires a whole and inactive attachment with the exact
capacity and logical sector size, rejects mounts, swap, and active block-graph
holders, then pins the resolved device read-only with an exclusive open and
advisory lock. The boot-local attachment identity and opened descriptor are
revalidated before and after both sequential range-read passes. The expected
disk GUID remains explicitly operator-asserted and unauthenticated in this cut.

The inspector generates its capture identifier internally, accepts no output
path, and emits only the canonical digest-bound envelope plus one newline on
standard output; diagnostics go to standard error. Its re-read covers the GPT
and listed fixed payload recovery ranges, not every physical byte, and the two
passes are not an atomic snapshot or proof of physical quiescence. Hashing whole
payload ranges means opaque bytes that happen to contain private material can
enter the process's hashing buffer, although the tool neither interprets nor
exports those bytes and performs no private-key operation. The envelope always
has `destructive_staging_ready=false` and accepts no staging-plan or approval
input. A separate path-free recovery-requirements contract now cross-binds
exactly one SD envelope and one NVMe envelope to the sealed staging plan and
enumerates every required recovery range. Durable backup capture, independent
readback, live-device attachment proof, operator approval, and write authority
remain absent or hard-false, and no campaign writer exists in this cut.

The development SD now has two distinguishable GPT histories. The primary at
LBA 1 and its declared image-sized backup form one reciprocal selected
lineage. The physical-end header and entry array form a CRC-valid canonical
backup copy from an older full-device lineage: its partition entry numbers,
types, ranges, attributes, and names match the selected lineage, while its
disk and partition GUIDs are distinct. Because LBA 1 belongs to the selected
lineage, the older physical-end object is recorded precisely as a valid
standalone backup copy, not as a currently reciprocal primary/backup pair.

The legacy v1alpha1 inspector continues to reject every GPT signature at the
physical end. The read-only v1alpha2 path must be selected explicitly with
`--envelope-version v1alpha2`. It accepts that state only after strictly
checking the physical-end header and entry-array CRCs, canonical 128-by-128
geometry and LBAs, complete partition semantics, and the exact
same-layout/distinct-identifier relationship. It hashes the physical-end
header and entry array from the same read pass used for parsing, binds them to
separate recovery-range purposes and a domain-separated lineage digest, and
repeats the complete read before output. `--disk-guid` still asserts only the
selected LBA-1 lineage and is not device authentication. v1alpha2 performs no
GPT repair, chooses no migration, stores no recovery bytes, and keeps
`destructive_staging_ready=false`; tools such as `sgdisk -e` or automatic
partition-table repair remain outside this campaign path. The existing
v1alpha1 recovery-requirements contract does not consume this new envelope;
adding a v1alpha2 downstream recovery contract is a separate reviewed slice,
so physical execution still pauses after read-only capture.

The earlier signed-verifier attempt replaced only its 128 MiB SD boot
partition. The running development image still has the release tree on the NVMe
`KAIBA_RELEASE` partition and the authenticated root-data and hash partitions
on the SD card. Readback confirmed root-data digest
`68ebaaad2985e13b445b0d71bc7f3ef16fa064e870ee561f367282f3b4a80313`;
the used hash-tree bytes have digest
`91c7c34db1449059d2293858415a0552f1c6b471443280f9303cd5efa3469469`,
and the complete padded hash partition has digest
`f27bfe6e09a466ea8d1a8092702db6c30685cba31402033050d00751716cd952`.
That happens to match the retained development release, but it is not a safe
assembly rule. The formal campaign must construct, cross-bind, stage, and read
back the boot, root-data, hash-tree, and release-tree artifacts as one reviewed
media set before the first positive boot.

The campaign is bound to development customer-key hash
`sha256:b8818acea4e71173903ee003e33ed37e969def7d2ea67bec15c0b73cb36c3895`.
The board was fused before this campaign; `otp_changed: false` and
`eeprom_changed: false` attest that this campaign performed no further OTP or
EEPROM mutation. They do not describe an unfused board.

This non-production spike does not bootstrap trusted wall-clock time. Before a
physical test, the development Pi RTC must already fall within the explicit
test-authority TLS certificate's validity interval. An unset Pi RTC causes the
TLS client to fail closed. A production design must obtain authenticated time
without weakening X.509 validity checks; manually setting the RTC is only a
laboratory prerequisite for this campaign.

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
