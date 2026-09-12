# Raspberry Pi 5 self-kexec diagnostic

This development-only kit answers one narrow question: can the running Pi 5
kernel transfer control into the selected kernel image with the current
firmware-resolved hardware description and a minimal initramfs? The default
`legacy-explicit-dtb` mode uses legacy `kexec_load` and explicitly supplies the
captured live DTB. The opt-in `file-live-fdt` differential uses
`kexec_file_load`; the running kernel clones its initial firmware DTB because
the file syscall cannot accept a DTB from userspace. On NixOS,
`/run/booted-system/kernel` binds the kernel selection to the booted system. An
explicit `--kernel` is an operator assertion and must be independently matched
to the running kernel before interpreting the test as self-kexec.

It deliberately excludes the stable verifier, release signatures, authority,
network, NVMe release, dm-verity, YubiKey, and released operating system. A
successful beacon therefore isolates those layers from the Pi-specific kexec
transition. It is not production tooling or evidence that a release is trusted.

## Safety boundary

The default operation only prepares and inspects. It copies the selected kernel,
captures `/sys/firmware/fdt`, builds a tiny deterministic initramfs, records the
boot ID and tool versions, and writes payload hashes. It calls `kexec --version`
to record tool provenance but never asks kexec-tools to load, unload, or execute
an image.

Execution requires both `--execute` and the literal confirmation token for the
mode persisted during preparation. `--mode` is deliberately preparation-only;
an operator cannot change loading mechanisms while executing an already
reviewed bundle. Before loading anything, the script verifies:

- it is root on a Raspberry Pi 5 Model B running AArch64;
- the prepared directory is root-owned mode `0700` and has no incomplete mark;
- every handoff payload still matches `PAYLOAD_SHA256SUMS`;
- the boot ID, kernel release, architecture, command line, and current live FDT
  still match preparation;
- `/sys/kernel/kexec_loaded` is zero, so no existing image will be replaced;
- the running configuration supports the selected syscall (`CONFIG_KEXEC=y`
  for legacy or `CONFIG_KEXEC_FILE=y` with `CONFIG_KEXEC_SIG` unset for file
  mode), `kernel.kexec_load_disabled` is zero, any finite reboot-load limit
  leaves capacity for load and fail-closed unload, and the process has effective
  `CAP_SYS_BOOT`;
- a non-blocking host-wide lock under `/run` is held across load and execution,
  while an atomic per-bundle claim prevents two uses of the same bundle;
- the recorded `kexec` and static BusyBox executables still have their recorded
  SHA-256 digests; and
- this bundle has never had an execution attempt.

The load is a distinct load-only phase. Execution is attempted only after the
load command succeeds and `/sys/kernel/kexec_loaded` reports one. If loading or
execution returns, the script uses the same syscall family to attempt to unload
its image. An unexpected power loss remains possible, so use only the
sacrificial development Pi with no valuable writable filesystem mounted.

## Prepare

Install GNU `cpio`, `kexec-tools`, and a statically linked BusyBox with `chroot`
and `zcat` applets. The tool copies BusyBox into the otherwise library-free
initramfs tree and executes `/bin/busybox true` through BusyBox's `chroot`
applet; this behaviorally rejects a dynamically linked candidate without
requiring `file(1)` or a magic database. The same exact BusyBox path and digest
are persisted and verified before execution, and its `zcat` applet reads a
compressed `/proc/config.gz` without depending on a garbage-collectable host
`gzip`. Preparation preflights the selected syscall's kernel configuration,
sysctls, and effective capability before it creates the bundle. Set up the
trusted UART capture before execution. From this directory, prepare a new
root-owned directory during the boot that will perform the default legacy
experiment:

```console
sudo ./kaiba-rpi5-self-kexec-diagnostic.sh \
  --work-dir /var/tmp/kaiba-rpi5-self-kexec-001
```

Prepare the file-syscall differential separately. It must use a new directory:

```console
sudo ./kaiba-rpi5-self-kexec-diagnostic.sh \
  --work-dir /var/tmp/kaiba-rpi5-self-kexec-file-001 \
  --mode file-live-fdt
```

On NixOS, the script normally discovers `/run/booted-system/kernel`. On another
distribution, it checks `/boot/vmlinuz-$(uname -r)` and
`/boot/Image-$(uname -r)`. If none is authoritative, pass the exact running
kernel and static BusyBox explicitly:

```console
sudo ./kaiba-rpi5-self-kexec-diagnostic.sh \
  --work-dir /var/tmp/kaiba-rpi5-self-kexec-001 \
  --kernel /absolute/path/to/the/running/Image \
  --busybox /absolute/path/to/static/busybox \
  --kexec /absolute/path/to/kexec
```

Review `PAYLOAD_SHA256SUMS`, `mode.txt`, `command-line.txt`, and
`observations/`. The mode is included in `PAYLOAD_SHA256SUMS`. If `dtc` is
installed, preparation also retains a decoded copy of the live DTB. The handoff
command line is fixed to:

```text
console=ttyAMA10,115200n8 earlycon=pl011,0x107d001000,115200n8 ignore_loglevel keep_bootcon loglevel=8 initcall_debug nokaslr rdinit=/init kaiba.self_kexec_beacon=1
```

## Execute once

Keep SSH only as a convenience; trusted UART is the observation channel. Then
execute the already-reviewed bundle:

```console
sudo ./kaiba-rpi5-self-kexec-diagnostic.sh \
  --work-dir /var/tmp/kaiba-rpi5-self-kexec-001 \
  --execute \
  --confirm EXECUTE-DEVELOPMENT-RPI5-SELF-KEXEC
```

That token is valid only for a bundle whose hashed mode is
`legacy-explicit-dtb`. The load uses legacy `kexec_load` with an explicit live
DTB and userspace `--debug` logging. It deliberately does not pass ARM64
kexec-tools' `--serial` option. Version 2.0.32 reads a UART's `iomem_base` into
a 10-byte buffer; the Pi 5 value `0x107d001000` does not fit and is truncated.
Supplying that bad address to purgatory could make the diagnostic itself fault
or hang before kernel entry. Preparation records the sysfs value and requires
it to equal the fixed early-console address.

```text
--debug --kexec-syscall
```

Execute a separately reviewed `file-live-fdt` bundle with its distinct token:

```console
sudo ./kaiba-rpi5-self-kexec-diagnostic.sh \
  --work-dir /var/tmp/kaiba-rpi5-self-kexec-file-001 \
  --execute \
  --confirm EXECUTE-DEVELOPMENT-RPI5-FILE-LIVE-FDT-SELF-KEXEC
```

This forces `--kexec-file-syscall` and deliberately omits `--dtb`. ARM64
kexec-tools 2.0.32 accepts `--dtb` in file mode but silently ignores it. The
kernel instead clones the flattened device tree from its own
`initial_boot_params`, replaces `/chosen/bootargs` and initrd addresses,
removes stale reservations, refreshes random seeds, and packs the result. Thus
this mode starts from the same firmware-resolved boot DTB but does not pass the
captured `inputs/live.dtb` bytes unchanged.

The initramfs prints `KAIBA_RPI5_SELF_KEXEC_BEACON:v1`, its command line, model,
and live-DTB digest, then reports `second-stage-init-reached`. After that
success boundary, a development-only CPU diagnostic records the kernel's
present, online, and offline CPU sets; tries to online each offline secondary
CPU with a ten-second best-effort userspace timeout; records post-attempt CPU
sets; and emits at most 80 relevant CPU, SMP, PSCI, or secondary-CPU dmesg
lines. It then preserves the existing behavior of syncing and powering off
after five seconds.

The CPU UART records use these stable markers:

```text
KAIBA_RPI5_SELF_KEXEC_CPU_DIAGNOSTIC:v1
KAIBA_RPI5_SELF_KEXEC_CPU_PRESENT:<cpulist|unavailable|empty>
KAIBA_RPI5_SELF_KEXEC_CPU_ONLINE_BEFORE:<cpulist|unavailable|empty>
KAIBA_RPI5_SELF_KEXEC_CPU_OFFLINE_BEFORE:<cpulist|unavailable|empty>
KAIBA_RPI5_SELF_KEXEC_CPU_ONLINE_ATTEMPT:cpuN
KAIBA_RPI5_SELF_KEXEC_CPU_ONLINE_SUCCESS:cpuN
KAIBA_RPI5_SELF_KEXEC_CPU_ONLINE_FAILURE:cpuN
KAIBA_RPI5_SELF_KEXEC_CPU_ONLINE_FAILURE_DETAIL:cpuN:<reason>
KAIBA_RPI5_SELF_KEXEC_CPU_ONLINE_SKIPPED:cpuN:<reason>
KAIBA_RPI5_SELF_KEXEC_CPU_ONLINE_AFTER:<cpulist|unavailable|empty>
KAIBA_RPI5_SELF_KEXEC_CPU_OFFLINE_AFTER:<cpulist|unavailable|empty>
KAIBA_RPI5_SELF_KEXEC_CPU_DMESG_BEGIN
KAIBA_RPI5_SELF_KEXEC_CPU_DMESG:<kernel-message>
KAIBA_RPI5_SELF_KEXEC_CPU_DMESG_END
```

An `ATTEMPT` that returns to PID 1 has exactly one `SUCCESS` or `FAILURE`
marker. A failure detail distinguishes a failed or userspace-timed-out sysfs
write from a write that returned but left the CPU offline. `timeout -s KILL`
cannot terminate a write stuck in uninterruptible kernel sleep, so an external
UART/power deadline is still required for a truly bounded physical campaign.
A secondary already online, lacking an online interface, or exposing a
malformed state gets a `SKIPPED` marker. Missing sysfs snapshots are diagnostic
data, not fatal errors. After all returning attempts, PID 1 continues to the
existing forced-poweroff path; if poweroff itself returns, it continues
emitting `KAIBA_RPI5_SELF_KEXEC_POWEROFF_RETURNED` rather than exiting and
panicking.

## Physical SMP differential

The 2026-09-11 development-Pi experiment intentionally started the first
kernel with `maxcpus=1` but left the diagnostic's fixed second-stage command
line unchanged. This distinguishes secondary CPUs that were left offline by
the first kernel from secondary CPUs that fail specifically during the kexec
boot. It does not change the stable verifier default or qualify an image for
release. The following procedure records the reproducible campaign shape.

1. Retain the exact original signed development boot-filesystem image and its
   digest, and confirm that it is the artifact that will be used for
   restoration. Do not edit the existing signed `boot.img` in place: its
   authenticated configuration and command line are covered by `boot.sig`.
2. Build a fresh deterministic development `boot.img` from reviewed inputs
   with exactly one first-stage change: add `maxcpus=1` to its authenticated
   kernel command line. Do not add it to this diagnostic's
   `command-line.txt` or change the fixed second-stage command line.
3. Perform a separately approved non-production signing operation for that
   exact new `boot.img`, producing its matching `boot.sig`. Verify the
   signature, signing receipt, and artifact digests before assembling and
   writing a fresh boot-filesystem image containing the signed pair.
4. Read back and verify the complete written boot partition before inserting
   it in the development Pi. A loose edited cmdline plus the old `boot.sig` is
   invalid and is not an acceptable test input.
5. Boot with trusted UART capture active. Before preparation, require
   `/proc/cmdline` to contain exactly one `maxcpus=1`, require CPU0 to be
   online, and record the present, online, and offline CPU lists.
6. Prepare a fresh `file-live-fdt` bundle during that boot, review its payload
   hashes, and verify its hashed `command-line.txt` does not contain
   `maxcpus=`.
7. Before execution, arm an external two-phase watchdog. Start a 180-second
   entry deadline immediately before the operator issues the one-shot
   `--execute` command; do not wait for a UART trigger. Cut power if trusted
   UART has not emitted `KAIBA_RPI5_SELF_KEXEC_CPU_DIAGNOSTIC:v1` by then. Once
   that CPU marker appears, replace the entry deadline with a 90-second
   completion deadline and cut power if the Pi has not powered off. These are
   the bounds for an earlier handoff hang and an uninterruptible CPU-online
   write; the in-initramfs timeout alone is not a complete campaign bound.
8. Execute the reviewed bundle once with the file-mode confirmation token and
   preserve the complete UART log and prepared directory.
9. While the Pi is powered off, restore the retained original signed
   boot-filesystem image before any later normal boot. Read it back and verify
   the complete original digest, including its original `boot.img` and
   `boot.sig` pair.

The completed run was classified `SMP_PASS`. Stage one had exactly one
`maxcpus=1`, CPUs 0 through 3 present, CPU0 online, and CPUs 1 through 3
offline. The fixed stage-two command line had no `maxcpus`, reached
`second-stage-init-reached`, and reported CPUs 0 through 3 online both before
and after the CPU diagnostic, with no online attempts or failures. The
known-good boot partition was then restored bit-for-bit, read back with SHA-256
`dd4f2832b40000bbcc7eb67d3302f83edebcf388fa52b956ec8df2f0c001056b`,
and smoke-tested.

Raw evidence remains outside Git under campaign ID
`rpi5-maxcpus1-physical-20260911-84808df9` in the operator's protected local
state directory.
The prepared archive, execution UART segment, and full UART capture have
SHA-256 digests
`ea40524631ff819b37860a5ae14b61f75576f643ff33031d7d9b75233080b401`,
`da7a2a38fdb05490272a843ac402dfc8c735aeeded7f8511075f11ef676f35e6`,
and `36017e8f69e330ed10edbd65a4773a4ccaa9b1a744f10e267d975fd43b62786a`
respectively. This result removes first-stage secondary-CPU initialization as
the explanation for the earlier observation. It remains a narrow handoff
diagnostic, not a signed-verifier qualification result.

The result categories are:

- **SMP pass:** stage two reaches `second-stage-init-reached`, reports CPUs 0
  through 3 online, and reports no CPU-online failures.
- **Hotplug recovery:** boot-time SMP leaves a secondary offline, but every
  attempted secondary reports `CPU_ONLINE_SUCCESS` and the final online list is
  `0-3`. Preserve the dmesg evidence; this is diagnostic progress, not a stable
  verifier qualification pass.
- **Persistent SMP failure:** any secondary remains offline after a returned
  attempt, emits `CPU_ONLINE_FAILURE`, or has an `ATTEMPT` with no result before
  the external deadline. This keeps file mode experimental.
- **Earlier handoff failure:** stage two does not reach the result marker. Read
  the UART boundary using the categories below before attributing it to SMP.

## Reading the result

- `kexec --debug` records the userspace load layout before execution. The next
  expected trusted-UART output is Linux `earlycon`; this version intentionally
  has no purgatory UART witness because of the parser defect above.
- `Bye!` without Linux `earlycon` output leaves the relocation/kernel-entry/DTB
  boundary unresolved; a separately reviewed kexec-tools parser fix would be
  needed to subdivide it with purgatory output.
- Linux output without the beacon narrows failure to initramfs discovery or
  PID 1.
- `CPU_ONLINE_SUCCESS` shows that Linux hotplug recovered a secondary that did
  not come online during normal SMP bring-up. `CPU_ONLINE_FAILURE` plus its
  bounded dmesg evidence distinguishes a persistent CPU-start problem from the
  otherwise successful kernel and initramfs handoff. The CPU diagnostic is
  observational development evidence, not a workaround used by the stable
  verifier.
- In legacy mode, the beacon proves the platform can self-kexec this kernel with
  the captured live-DTB bytes. In file mode, it proves self-kexec with the
  kernel-generated derivative of the initial firmware DTB. The signed verifier
  failure must then differ in its kernel, DTB handling, initramfs, command line,
  or pre-handoff machine state.
- A beacon from `file-live-fdt` after silence in `legacy-explicit-dtb`
  implicates the legacy userspace segment, explicit-DTB, or purgatory path.
  Silence in both modes points toward their shared device shutdown,
  machine-kexec jump, target-kernel entry, or console boundary.
- A successful file-mode load without execution proves only that kexec-tools
  and the running kernel accepted the kernel, initramfs, command line, and
  kernel-generated DTB segments. It does not prove transfer, early UART, or PID
  1. LSM or IMA policy may still reject a load even when kernel signature
  verification is compiled out.

Preserve the external UART log together with the prepared directory and hash
both before changing the experiment.
