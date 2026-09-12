# Raspberry Pi 5 development target access

The secure-boot target module contains an optional USB-gadget SSH path for
diagnosing one sacrificial Raspberry Pi 5 after it boots the reviewed
development system. This path is disabled by default and deliberately grants
root-equivalent access. It is a development escape hatch, not a production
management design, hardware attestation mechanism, or provisioning authority.

> [!DANGER]
> Enabling development access gives the configured `codex` SSH identity
> passwordless `sudo` for `ALL` commands. Possession of that client private key
> is possession of root-equivalent authority over the running target. A session
> can change runtime state, falsify target-local evidence, access attached
> devices, or invoke any mutation mechanism present in the composed image. Do
> not enable this option in a production image or treat evidence collected after
> login as independent proof of secure-boot enforcement.

The source of truth is the
[`secure-boot-target` NixOS module](../nix/modules/secure-boot-target.nix). The
[secure-boot model](raspberry-pi-5-secure-boot.md),
[live-provisioning guide](raspberry-pi-5-live-provisioning.md), and
[production-readiness assessment](production-readiness.md) define the wider
development boundary.

## Default-off boundary

`kaiba.secureBootTarget.developmentAccess.enable` is a `mkEnableOption`, so it
defaults to `false`. With the option off, the target module does not enable
OpenSSH, create the `codex` account, enable `sudo`, load USB gadget Ethernet, or
open TCP port 22. The generated target policy records
`development_access.enabled = false`.

When the option is enabled, the module fixes the access surface rather than
accepting runtime selectors:

| Property | Implemented value |
| --- | --- |
| Transport | USB gadget Ethernet through `dwc2` and `g_ether` |
| Gadget parameters | `dev_addr=02:4b:41:49:42:41`, `host_addr=02:4b:41:49:42:42` |
| Target interface | `usb0`, static `10.0.0.2/24`, no DHCP |
| SSH listener | `10.0.0.2:22` only; firewall admission is scoped to `usb0` |
| Login | One exact Ed25519 public key for user `codex`; public-key authentication only |
| Direct root login | Disabled |
| Privilege escalation | `codex` may run `ALL` commands through passwordless `sudo` |
| Target host key | Ed25519 key under `/run/kaiba-development-ssh/`; regenerated after every boot |
| Fingerprint channel | Printed to the configured `serial0` console at 115200 baud after `sshd` starts |
| Development home | `/var/lib/kaiba-codex`, on the target's tmpfs-backed `/var` |

The fixed listener and firewall rule limit the default network path; they do
not sandbox the logged-in user. Passwords remain locked, but passwordless sudo
makes the admitted key root-equivalent.

## Compose a development image

The repository exports `nixosModules.secure-boot-target`, but it does **not**
export a general-purpose preconfigured target image or a ready-to-run
`nixosConfigurations.<name>` output. A reviewed consumer flake must combine the
module with the Raspberry Pi board support, dm-verity root, signed boot
artifacts, exact source revision, cohort key hash, and an explicit image output.
Do not invent a root-flake image name or reuse a historical monorepo build
command.

One deliberately narrow exception is the stable-campaign development
provisioner. An internal, revision-bound build graph constructs the fixed
`kaiba-rpi5-provisioner` system and its deterministic unsigned boot, root-data,
and root-hash artifacts. It installs only the AArch64 read-only GPT inspector,
keeps `/` on dm-verity, disables swap and GPT auto-discovery, and carries the
NVMe driver without configuring the inspected NVMe as storage. The headless
profile excludes the unrelated Wi-Fi, audio, GPU, and general Linux firmware
bundle; USB gadget Ethernet, UART, SD, and NVMe operation do not require those
host-loaded blobs. It closes over
the exact development customer key, SSH public key, boot size, firmware set,
SD layout, and storage binding in this repository; its only argument is the
canonical source revision. The revision-parameterized constructors are not
exported: callers cannot use a dirty/path flake to mint an artifact that claims
an arbitrary clean revision.

On a clean Git revision, the same closed development artifact set is exposed
as
`packages.x86_64-linux.kaiba-rpi5-stable-campaign-provisioner-unsigned`.
Malak builds the AArch64 Pi payload through the fixed x86_64-to-AArch64 build
configuration. The package is intentionally absent for dirty source trees so
an unsigned bundle cannot claim an ambiguous source revision. It remains
unsigned and development-only: build completion does not authorize signing,
media writes, or a hardware campaign.

This exception deliberately does not claim the general unsigned-artifact-set
contract. Its dedicated provisioner manifest marks the 96 MiB `boot.img` as a
signed-boot input with storage format `fat-boot-ramdisk-not-partition` and keeps
`physical_staging_ready=false`; writing that file directly to SD p1 would omit
`boot.sig` and is forbidden. The manifest binds the reviewed SD disk and p1-p3
partition GUIDs and capacities, binds the verified root to
`/dev/mmcblk0p2` and its hash tree to `/dev/mmcblk0p3`, pads their artifacts to
the development SD's exact 2,418,016,256-byte and 19,922,944-byte partition
capacities, and names them under `sd/`. That topology binding prevents an
attached campaign NVMe with colliding GPT identifiers from becoming the
provisioner's root. The normal signed-release, unfused-capsule, and target-NVMe
staging paths must reject this dedicated schema; do not route the provisioner
bundle through them. After the exact inner image is approved and signed, use
only `lib.mkRpi5StableCampaignProvisionerSignedBootFilesystem` to verify the
canonical signature under the reviewed development public key and construct
the distinct 128 MiB outer FAT p1 image containing exactly `boot.img`,
`boot.sig`, and `config.txt`.

No media writer is included in this cut. A physical staging handoff must bind
the exact removable reader identity, whole-device size, selected SD disk and
partition GUIDs, exact partition capacities, the post-sign outer-boot manifest
and digest, and both root artifact digests before one operator confirmation. It
must write only SD partitions 1 through 3 and independently hash every complete
partition on readback. The attached campaign NVMe is the read-only inspection
subject, never a staging target.

The access-specific portion of that consumer configuration is:

```nix
{
  imports = [
    inputs.kaiba-provisioning.nixosModules.secure-boot-target
  ];

  kaiba.secureBootTarget = {
    enable = true;
    # Raw lowercase SHA-256 hex, without a "sha256:" prefix.
    expectedCustomerKeyHash = "<64-lowercase-hex-characters>";
    sourceRevision = "<exact-reviewed-source-revision>";

    developmentAccess = {
      enable = true;
      authorizedKey =
        "ssh-ed25519 <base64-public-key> codex-rpi5-development-2026-09-07";
    };
  };
}
```

The authorized key must be one exact Ed25519 public-key line whose comment
matches `codex-rpi5-development-` followed only by digits and hyphens. Key
options, another key, an arbitrary comment, or a trailing newline do not match
the module assertion. Only the public key belongs in the Nix configuration;
the private key must remain outside Git, the Nix store, build logs, images, and
evidence exports.

Changing the public key changes the composed system and signed artifact inputs.
Review and rebuild that lineage rather than attempting to patch the immutable
target after boot. Follow the
[signed-release workflow](raspberry-pi-5-signed-boot-workflow.md) for the public
artifact boundary and the
[execution plan](raspberry-pi-5-secure-boot-execution-plan.md) before any
hardware campaign.

## Prepare a bounded client session

Generate a new client key in an approved private directory. The example comment
conforms to the module's required form:

```console
umask 077
session_root=/absolute/private/kaiba-rpi5-development-access
install -d -m 0700 "$session_root"
ssh-keygen -t ed25519 -a 100 \
  -f "$session_root/codex-rpi5-development" \
  -C codex-rpi5-development-2026-09-07
```

Confirm that the private key path is absent before running `ssh-keygen`; never
approve an overwrite prompt. Copy only the single-line `.pub` value into the
reviewed consumer configuration. Treat the corresponding private key as a
short-lived root credential for this one development image and campaign.

On the development host, configure only the intended USB gadget interface with
a peer address such as `10.0.0.1/24`. Do not add a default route, bridge, NAT,
forwarding, DHCP service, or connection sharing. Resolve the interface by the
reviewed physical topology and the expected gadget MACs; do not assume that a
particular host interface name identifies the Pi.

Keep the target disconnected from other power and data paths required to be
absent by the lane plan. USB access does not replace the power, target,
transaction, or fence checks in the [live lane](raspberry-pi-5-live-provisioning.md).

## Bind SSH to the current boot

The boot-evidence decoder is pinned to the representation observed with the
development Pi's EEPROM BOOTLOADER release `086b83e3` dated 2026-05-26. Its
`/proc/device-tree/chosen/bootloader/boot_img_sha256` property is exactly 64
bytes: the raw 32-byte SHA-256 digest followed by 32 NUL bytes reserved by the
firmware. The decoder deliberately rejects the formerly assumed 32-byte raw,
64-byte ASCII-hex, and 65-byte ASCII-hex-plus-NUL forms, as well as any nonzero
reserved suffix. An EEPROM change that alters this representation therefore
emits `malformed-boot-image-hash` and blocks SSH until the new firmware behavior
is observed and reviewed; it is not silently treated as a signature failure.

The host key is intentionally generated under `/run`, so ordinary persistent
`known_hosts` continuity does not apply. Before opening SSH, require the earlier
`KAIBA_SECURE_BOOT_EVIDENCE=pass` UART record and compare its boot-image digest
with the immutable signed release through the lane's normal evidence path. The
target then emits a separate access line after `sshd` starts:

```text
KAIBA_DEVELOPMENT_SSH=ready user=codex address=10.0.0.2 host_key=SHA256:<fingerprint>
```

Observe that line through the already reviewed UART path. Then capture the
presented key into a new session-only file and display its fingerprint:

```console
known_hosts="$session_root/known_hosts.this-boot"
test ! -e "$known_hosts"
ssh-keyscan -T 5 -t ed25519 10.0.0.2 > "$known_hosts"
chmod 0600 "$known_hosts"
ssh-keygen -E sha256 -lf "$known_hosts"
```

Compare the `SHA256:` value byte-for-byte with the UART value before connecting.
An absent UART marker, more than one candidate device, a changed physical path,
an unexpected key type, or any fingerprint mismatch is a stop condition. Do not
use `StrictHostKeyChecking=no`, accept an interactive first-seen key, or copy an
old host key forward to a new boot.

After the comparison succeeds, connect with only the intended client key and
per-boot host-key file:

```console
ssh \
  -i "$session_root/codex-rpi5-development" \
  -o IdentitiesOnly=yes \
  -o UserKnownHostsFile="$known_hosts" \
  -o StrictHostKeyChecking=yes \
  codex@10.0.0.2
```

The UART marker correlates the SSH server key with the current physical boot
under the lane's UART assumptions. It is not a CA-issued device identity,
remote attestation, or proof that all running software is uncompromised. The
production identity and freshness design remains proposed work; see
[device identity](device-identity.md) and the
[production security follow-on](raspberry-pi-5-production-security-follow-on.md).

## Root-equivalent operation

The `codex` account is a locked system account, but its sudo rule is deliberately
unrestricted:

```text
codex ALL=(ALL) NOPASSWD: ALL
```

The NixOS representation uses an `ALL` command rule with `NOPASSWD`; the text
above expresses its effective authority, not a separately installed sudoers
file. Commands such as `sudo -i` are therefore expected to work. This is not a
least-privilege wrapper around one diagnostic action.

The immutable dm-verity root and tmpfs-backed `/var` make ordinary operating
system changes ephemeral, but root can still alter the running kernel and
network state, overwrite `/run` evidence, interact with exposed devices, and
use any writable or mutation-capable interface included by the consumer image.
Do not interpret a read-only root as containment of a root session.

Use the session only for an approved diagnostic objective. Record the source,
image, target, UART fingerprint, client public-key fingerprint, operator,
start/end time, and commands allowed by that objective without recording secret
key material. Re-establish security claims from a clean boot and independent
lane observations after the session; target-local output produced while the
root-equivalent login was available is not independent acceptance evidence.

## Enter RPIBOOT deliberately

With development access enabled, the image includes `kaiba-enter-rpiboot`. It
requires effective UID 0, requests the firmware USB-boot reboot mode through
`vcmailbox`, syncs, and reboots:

```console
sudo kaiba-enter-rpiboot
```

The SSH connection and gadget network are expected to disappear. The helper
does not choose or upload an RPIBOOT payload, verify current device authority,
issue an approval, or authorize EEPROM/OTP mutation. Invoke it only when the
separate transaction and physical-lane workflow already requires that boot
transition. Do not use it as an ad hoc recovery or retry path after an ambiguous
operation.

## Close the session

At the end of the approved work:

1. exit all root and SSH sessions;
2. preserve only reviewed, secret-free diagnostics at their stated assurance
   level;
3. power the target off through the approved lane procedure;
4. remove the host's temporary USB address and any route created for the
   session;
5. destroy the short-lived client private key when the campaign no longer needs
   it; and
6. retain or destroy the per-boot host-key record according to the evidence
   policy, never as authority for a later boot.

The public key remains authorized in every copy of that exact development
image. Losing control of the private key, discovering an unexpected copy, or
failing to prove teardown requires quarantine of the image and affected target,
not continued use with an informal key-rotation story.

## Explicit nonclaims

Development target access does not establish:

- a production administration plane or support account;
- least privilege, command confinement, or isolation from target hardware;
- persistent device identity or host-key continuity across boots;
- remote attestation, a fresh release decision, or anti-rollback;
- integrity of evidence generated after root-equivalent login;
- authorization to stage media, sign a release, run RPIBOOT, or mutate
  EEPROM/OTP; or
- `enrollment_ready` or production readiness.

A production image must leave this option disabled and omit the `codex` account,
USB SSH path, passwordless sudo, development client key, and RPIBOOT convenience
helper. Production access, if required, needs a separately threat-modeled,
revocable, audited, least-privilege design bound to the production identity and
freshness architecture.
