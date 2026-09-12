# Ubuntu 24.04 signing-gate deployment

This bundle installs the repository's immutable, approval-gated development
YubiKey signer on a dedicated Ubuntu 24.04 control host. Installation is inert:
it does not enable or start the gate, read a PIN, enumerate a smartcard, invoke
PKCS#11, or submit a signing request.

The service accepts only the fixed authority compiled into the selected
`mkDevelopmentYubiKeySigning` Nix output. The package fixes the token serial,
PIV slot, public key, signer/cohort IDs, provider modules, grant registry,
socket, state directory, and systemd credential destination. The installer
accepts only the package store path; none of those selectors can be overridden
at runtime.

`--staging-root` is exclusively a non-root test mode. It writes a self-contained
in-image comparison baseline so the fixture is relocatable, but that baseline
is mutable by the test owner and is not a deployment trust anchor. Never boot
or deploy a staging root. Pre-create it as a caller-owned, ACL-free directory
with mode `0700`; the installer rejects root callers and unsafe root metadata.
Live installation accepts only the verified Nix deployment output.

## Fixed host boundary

| Object | Path and access |
| --- | --- |
| Service identity | `kaiba-signing:kaiba-signing`; locked system user, no supplementary groups |
| Reviewed grants | `/etc/kaiba-provisioning/signing-grants.json`; `root:kaiba-signing`, mode `0440`; parent mode `0750` |
| PIN source | `/run/kaiba-provision-signing-credentials/yubikey-pin`; `root:root`, mode `0400`, on tmpfs |
| PIN credential | `/run/credentials/kaiba-provision-signing-gate.service/yubikey-pin`; systemd-created root ownership and one named-user read ACL |
| Durable state | `/var/lib/kaiba-provision-signing`; service-owned, mode `0700` |
| Receipt exports | `/var/lib/kaiba-provision-signing-exports`; service-owned, mode `0700`; outside durable gate state |
| Runtime/socket | `/run/kaiba-provision-signing` mode `0700`; `signing.sock` mode `0600`, both service-owned |
| PC/SC authorization | The two pcsc-lite actions are granted only to the `kaiba-signing` user by polkit |

The service sees the systemd credential copy, not the root-only source. Its
mount namespace makes the source directory inaccessible. `AF_UNIX` is the only
permitted address family, direct device access is closed, the capability sets
are empty, core dumps are disabled, and both reviewed Nix outputs are held by
direct GC roots. Static preflight compares every installed deployment asset
byte-for-byte with the pinned deployment output and rejects unit drop-ins.

## Host preparation

Install the host dependencies from Ubuntu 24.04. Do not add the service user to
`plugdev`, `scard`, or any operator group.

```console
sudo apt-get update
sudo apt-get install acl jq libccid pcscd polkitd
```

> [!IMPORTANT]
> A clean, revisioned Git checkout exports
> `kaiba-rpi5-stable-campaign-development-signing`, the configured runtime for
> the stable campaign's one-artifact ceremony. It is fixed to the reviewed
> sacrificial development YubiKey, exposes only the stable command, receipt
> tool, gate, and token backend, and is not production-approved. The
> historical five-artifact `development-signing` composition is still not
> exported; its separate integration gate remains documented in the
> [signed-boot workflow](../../docs/raspberry-pi-5-signed-boot-workflow.md#current-standalone-boundary)
> and [development ceremony](../../docs/ubuntu-rpi5-development-signing-ceremony.md#current-integration-gate).

Nix must already contain both the exact configured signing output and the
immutable deployment bundle. Build them with named result links so the reviewed
paths remain available until installation. For the stable campaign ceremony,
build both outputs from the same clean, revisioned repository checkout:

```console
nix build .#packages.x86_64-linux.kaiba-rpi5-stable-campaign-development-signing \
  --out-link result-development-signing
nix build .#packages.x86_64-linux.ubuntu-signing-gate-deployment \
  --out-link result-ubuntu-signing-gate-deployment
signing_path="$(readlink -e result-development-signing)"
deployment_path="$(readlink -e result-ubuntu-signing-gate-deployment)"
nix-store --query --hash "$signing_path"
nix-store --verify-path "$signing_path"
nix-store --query --hash "$deployment_path"
nix-store --verify-path "$deployment_path"
```

Before installing, review these public files in that exact output and compare
them with the release review:

```console
jq . "$signing_path/share/kaiba/signer-policy.json"
cat "$signing_path/share/kaiba/signer-policy-digest"
cat "$signing_path/share/kaiba/customer-key-hash"
```

Install the host boundary. The package path is public configuration, not a
secret. The installer creates a Nix GC root, but leaves both pcscd and the gate
untouched.

The live installer refuses a mutable source checkout. Run the copy in the
root-owned Nix deployment output:

```console
sudo "$deployment_path/share/kaiba/ubuntu-signing-gate/install.sh" \
  --package "$signing_path"
sudo /usr/local/sbin/kaiba-signing-gate-preflight --static
```

Installation is fail-closed but not transactional. A late error can leave the
locked identity, private directories, GC roots, or some static assets in place;
it never enables or starts the gate. Do not provision a PIN or start the unit
until the same reviewed installer completes and static preflight reports OK.
After a failure, inspect the reported object and either rerun the same verified
outputs after correcting the host condition or follow a separately reviewed
recovery procedure. Do not blindly remove or replace partial security objects.

Reinstalling with a different package or deployment fails while either direct
GC root names an old output. The roots are
`/nix/var/nix/gcroots/kaiba-provision-signing-gate` and
`/nix/var/nix/gcroots/kaiba-ubuntu-signing-gate-deployment`. Changing either
link is a separate reviewed authority change: stop the gate, review the new
outputs, remove only the corresponding old link explicitly, then rerun the
installer.

## Ceremony preparation

Install a separately reviewed v1alpha2 grant registry. The gate loads it once
at startup and independently validates its owner, parent, permissions, schema,
canonical ordering, request bindings, and expiry fields. Those checks do not
authenticate the reviewer's approval: the exact registry file SHA-256 received
through the independent review channel is the authority for this handoff.

Do not copy the registry directly from an operator-writable checkout into
`/etc`. First enter the independently communicated lowercase, 64-hex file
SHA-256, copy the input into a new root-owned staging directory under `/root`,
remove access and default ACLs, and verify the staged copy. The digest-derived
directory must not already exist; an existing path is an unresolved prior
handoff, not permission to reuse or delete it.

```console
(
  set -euo pipefail

  registry_source=./reviewed-signing-grants.json
  installed_registry=/etc/kaiba-provisioning/signing-grants.json

  read -r -p 'Independently approved registry file SHA-256: ' approved_registry_sha256
  case "$approved_registry_sha256" in
    ''|*[!0-9a-f]*)
      printf 'approved registry SHA-256 must be 64 lowercase hexadecimal characters\n' >&2
      exit 1
      ;;
  esac
  test "${#approved_registry_sha256}" -eq 64

  test -f "$registry_source"
  test ! -L "$registry_source"
  sudo test -d /root
  sudo test ! -L /root
  test "$(sudo stat --format='%U:%G:%a:%F' -- /root)" = 'root:root:700:directory'

  registry_stage_dir="/root/kaiba-signing-registry-stage-$approved_registry_sha256"
  if sudo test -e "$registry_stage_dir" || sudo test -L "$registry_stage_dir"; then
    printf 'registry staging path already exists; stop for review: %s\n' \
      "$registry_stage_dir" >&2
    exit 1
  fi

  sudo install -d -o root -g root -m 0700 -- "$registry_stage_dir"
  staged_registry="$registry_stage_dir/signing-grants.json"
  sudo install -T -o root -g root -m 0400 -- \
    "$registry_source" "$staged_registry"
  sudo setfacl --remove-all -- "$registry_stage_dir" "$staged_registry"
  sudo setfacl --remove-default -- "$registry_stage_dir"

  sudo test ! -L "$registry_stage_dir"
  sudo test ! -L "$staged_registry"
  test "$(sudo stat --format='%U:%G:%a:%F' -- "$registry_stage_dir")" = \
    'root:root:700:directory'
  test "$(sudo stat --format='%U:%G:%a:%F' -- "$staged_registry")" = \
    'root:root:400:regular file'
  test "$(sudo stat --format='%h' -- "$staged_registry")" = 1
  test -z "$(sudo getfacl --absolute-names --skip-base -- \
    "$registry_stage_dir" "$staged_registry")"

  staged_registry_sha256="$(sudo sha256sum -- "$staged_registry" | cut -d ' ' -f 1)"
  if test "$staged_registry_sha256" != "$approved_registry_sha256"; then
    printf 'staged registry SHA-256 does not match independent approval; stop\n' >&2
    exit 1
  fi

  if sudo systemctl is-active --quiet kaiba-provision-signing-gate.service; then
    printf 'signing gate must be inactive before registry installation\n' >&2
    exit 1
  fi
  sudo test -d /etc/kaiba-provisioning
  sudo test ! -L /etc/kaiba-provisioning
  sudo test ! -L "$installed_registry"
  sudo install -T -o root -g kaiba-signing -m 0440 -- \
    "$staged_registry" "$installed_registry"
  sudo setfacl --remove-all -- "$installed_registry"

  sudo test ! -L "$installed_registry"
  test "$(sudo stat --format='%U:%G:%a:%F' -- "$installed_registry")" = \
    'root:kaiba-signing:440:regular file'
  test "$(sudo stat --format='%h' -- "$installed_registry")" = 1
  test -z "$(sudo getfacl --absolute-names --skip-base -- "$installed_registry")"

  installed_registry_sha256="$(sudo sha256sum -- "$installed_registry" | cut -d ' ' -f 1)"
  if test "$installed_registry_sha256" != "$approved_registry_sha256"; then
    printf 'installed registry SHA-256 does not match independent approval; stop\n' >&2
    exit 1
  fi

  printf 'registry handoff verified: %s  %s\n' \
    "$installed_registry_sha256" "$installed_registry"
)
```

Record the approved and installed file SHA-256 in the ceremony evidence. If
any command above fails, preserve the source, staging directory, and installed
file for review. Do not provision the PIN or start the gate. Do not repair a
mismatch by editing, recopying, deleting, or reusing the staged path; obtain a
new authenticated handoff and follow the reviewed recovery procedure.

Enable the Ubuntu pcscd activation socket. Starting the socket does not call a
token utility; pcscd itself remains policy-controlled and can auto-exit.

```console
sudo systemctl enable --now pcscd.socket
```

Provision the PIN from a controlling terminal. The helper disables shell
tracing and core dumps, accepts no secret argument or environment override,
prompts twice without echo, and atomically creates only the fixed tmpfs file.
It refuses to proceed while the gate is active or any swap is enabled, because
a tmpfs page or shell memory could otherwise be written to persistent swap.

```console
sudo swapoff --all
swap_state="$(swapon --show --noheadings)" || exit 1
test -z "$swap_state"
sudo /usr/local/sbin/kaiba-signing-gate-provision-pin
```

Run the full preflight before starting the gate. It checks metadata and the
public registry envelope but never reads the PIN value, opens PC/SC, enumerates
a reader, or invokes a signer.

```console
sudo /usr/local/sbin/kaiba-signing-gate-preflight
sudo systemctl start kaiba-provision-signing-gate.service
sudo /usr/local/sbin/kaiba-signing-gate-preflight
```

Starting the gate validates the registry, state, and systemd credential but
does not ask the YubiKey to sign. Each authorized artifact completed on its
first attempt causes two ordered private-key operations and, under the reviewed
always-touch policy, two touches: the artifact signature followed by the
gate-derived canonical receipt-attestation signature. If either operation or
the durable completion fails, intent state remains and permanently blocks
further private-key use for that grant. Stop, preserve the evidence, and begin
only a new independently authorized ceremony attempt; there is no same-grant
retry command. A new approval creates new grant identities, so all five inputs
must be signed under that registry; never combine receipts across attempts. Two
is a successful first-attempt minimum, not permission to repeat a request.
Follow the reviewed
[development signing ceremony](../../docs/ubuntu-rpi5-development-signing-ceremony.md);
this deployment bundle does not automate that ceremony.

## Close the boundary

After the ceremony, stop the service before deleting the ephemeral source.
The credential mount and private runtime/socket directory disappear with the
unit; durable anti-replay state remains mode `0700`.

```console
sudo systemctl stop kaiba-provision-signing-gate.service
sudo rm -f -- /run/kaiba-provision-signing-credentials/yubikey-pin
pin_entries="$(sudo find /run/kaiba-provision-signing-credentials \
  -mindepth 1 -maxdepth 1 -printf '%P\n')" || exit 1
test -z "$pin_entries"
sudo /usr/local/sbin/kaiba-signing-gate-preflight --static
```

The PIN source also disappears on reboot. Never move it to `/etc`, the Nix
store, a shell variable exported to the environment, a command argument, or a
log. Do not use `Environment=`, `EnvironmentFile=`, or `SetCredential=` for the
PIN. Keep this dedicated signing host swap-free. Any future decision to restore
swap belongs to a separately reviewed host-maintenance procedure after the
ceremony boundary has been closed; it is not a ceremony step.
