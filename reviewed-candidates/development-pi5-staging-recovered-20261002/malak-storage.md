# Malak backing storage worksheet

The operator selected malak for the development Pi's staging runtime and
recovery evidence. The provisioner has a read-only Nix store, about 510 MB
free in `/tmp`, about 268 MB in `/var`, and no separate writable disk.
The selected NVMe cannot hold its own runtime or recovery backups.

## Current state: October 3

The complete SD and NVMe staging runtimes were assembled and independently
verified after the native ARM export from main revision
`733bc29ecbf0a003f03b7eebf1cf3e882ba0110d`. All seven copied NVMe runtime objects
matched their retained NAR hashes and sizes. The NFSv4 listener is active only
at `10.0.0.1:2049/tcp`, with three peer-restricted exports, four server threads
and active stable client tracking. The evidence resides on malak's ext4
`/dev/nvme0n1p5`, separate from the Pi's selected SD and NVMe.

The operator completed the narrow UFW repair after the first client mount timed
out. Its rule permits only incoming `usb0`, source `10.0.0.2`, destination
`10.0.0.1`, TCP port 2049. The completion check preserved all other firewall
rules and policies. Both Pi NFSv4.2 mounts are now qualified: runtime is
read-only; evidence is read/write with protected root-owned ancestors. Every
one of the 1,214 runtime files and 1,340 nodes matched the independently derived
inventory. A synchronized 1 MiB challenge matched independent server readback.

The native ARM staging command ran successfully through its exact fixed Nix
paths in a private, read-only mount namespace. All runtime files were rehashed
through that view, and the global Nix store was identical before and after.
Keep the original store first in the overlay's lower-layer order to preserve
its directory permissions. `findmnt` reports both the original ext4 mount and
the stacked overlay; the qualification checked both records. Each later
invocation must reconstruct and revalidate its own private view.

A separate synthetic qualification exercised protected traversal, exclusive
creation, sparse sizing, mode changes, file/directory synchronization and
stable reopen. It also rejected duplicate creates, symlinks, hardlinks and
unprotected ancestors. The complete 64 MiB snapshot matched a fresh client
mount with a separate NFS cache and independent malak readback:
`sha256:0060b9f84af430eb69fdb97afab03fad135209da6f37b9d88619bd60dc85b1d7`.
Malak independently reopened all ten qualification files and verified their
sizes, digests, ownership, modes and single-link identities.

The final readback and five historical public media receipts are retained in
`/home/codex-remote/kaiba-private/task1-physical-acceptance-20261002/storage-qualification-closeout-733bc29`.
The retention manifest digest is
`sha256:ed2cd5c58acf2ce800f09428f36ae70fb2aee298b1c209522118ed3d98c013b5`.
The [current status record](status-20261003.json) distinguishes these completed
storage checks from the remaining physical gates.

The subsequent public discovery and qualification exports also completed.
Their 40 copies, four offline-verified owned-recovery bundles, independent
receipt associations and historical hardware correlation are retained in a
separate protected closeout. The [task record](../../docs/task1-physical-acceptance.md)
and [status record](status-20261003.json) preserve their exact assurance limits.
These signing and pre-ownership records cannot close physical ownership,
recovery or current-lane qualification.

Preserve the original failed activation, listener and client/runtime attempts
alongside their separate reconciliation and completion journals. Do not rerun
their one-shot helpers. Network storage, the private Nix view and staging file
operations are qualified for the observed setup; revalidate attachment,
capacity, runtime and transport immediately before preparation. Actual recovery
range backups, inactive SD capture, original ownership, approved hardware and
witness bindings, authority/RTC/power qualification and physical execution
approval remain open. No target media was staged, and no campaign run or claim
has completed. The historical pre-activation observations below remain retained
with their original scope.

## Selected scope

| Item | Selected scope |
| --- | --- |
| Host storage | A new root-owned `/var/lib/kaiba-provisioning/task1-development-20261002` namespace |
| Transport | Isolated USB Ethernet: malak `usb0`, `10.0.0.1`; independently authenticated Pi `10.0.0.2` |
| Runtime | Read-only NFSv4 export containing only the verified complete NVMe runtime closure at its exact store basenames |
| Recovery evidence | Separate read/write NFSv4 export, root-owned mode 0700, with root-owned protected ancestors |
| Capacity | At least 24 GiB free before preparation; recompute exact recovery and snapshot sizes from the approved requirements |
| Existing retention | Keep the operator-owned public artifact archive separate from root-owned physical evidence |

Malak reported 140,907,233,280 available bytes on the backing filesystem during
preparation. This observation is not a reservation or a qualification result.
Before activation, the host had no NFS export or listener. Pinned native x86
NFS helpers were built at
`/nix/store/bkj4vw2fnz0idzj6vy32m37pcja2pxzh-nfs-utils-2.9.2`;
their help interfaces were checked before activation; the retained completion
records bind their subsequent server use.

## Setup and runtime constraints

The activated setup record binds the complete NVMe closure's path/NAR
inventory, selected campaign, plan digest, authenticated Pi boot and malak
filesystem. The final retained archive contains both complete staging runtimes.
Retain these bindings and revalidate them before each physical preparation.

Create a new root-owned namespace with protected ancestors. Copy only the
verified runtime closure into a frozen runtime tree, preserve exact filenames
and executable modes, and independently reopen and hash every copy against the
verified NAR/file inventory. Do not expose the host's entire `/nix/store`,
private signing material, home directory or existing evidence tree.

Configure NFSv4 over TCP with the listener bound to `10.0.0.1` and exports
restricted to the single USB peer `10.0.0.2`. Keep runtime read-only and evidence
read/write with synchronous server writes. Disable NFSv2/v3 and verify that no
auxiliary listener is exposed on other interfaces. The NFS daemon's `-H`
option binds its address; its manual warns that lockd may still listen on
all interfaces unless the older protocols are disabled.
[Source: rpc.nfsd](https://man7.org/linux/man-pages/man8/rpc.nfsd.8.html)

The staging tool runs as root and requires root-owned evidence directories and
files. The evidence export must preserve UID 0 rather than silently map writes
to an anonymous owner. Any root mapping exception must be restricted to this
isolated peer and new namespace. Verify actual ownership from both endpoints;
IP restrictions and `sec=sys` do not authenticate an independent reviewer.
Retain the reviewed export configuration, server identity, listeners, mount
options, capacity checks and operator setup record.

On the Pi, the NFS kernel module is present; `mount.nfs`, `nix` and `nix-store`
are absent. Verify the actual available mount interface and protocol support
before deployment. Provide the exact fixed paths without writing the SD root.
A proposed temporary read-only overlay uses the frozen NFS runtime tree and a
separate read-only bind of the existing store as its lower layers, with no
upper or work directory. Linux supports read-only overlays with multiple
lower layers; modifying those layers while mounted has undefined behavior.
[Source: OverlayFS](https://docs.kernel.org/filesystems/overlayfs.html)

Check overlapping store names byte-for-byte before constructing that view.
Pin all layer identities, freeze their contents, verify the overlay and
read-only mount flags, then rehash the executable, fixed configuration, plan
and payloads through their actual `/nix/store` paths on the Pi. The private
arrangement passed on-device qualification; reuse requires a new private
namespace and fresh checks. The signed provisioner and Nix trust
configuration were retained.

## Qualification before recovery capture

Use a separate qualification subdirectory, never a physical attempt directory.
Check at least 24 GiB free on both the server filesystem and the client view.
Confirm root UID, mode 0700, protected real ancestors, absence of symlinks,
single-link regular files, stable file/inode identities and that the backing
filesystem is independent of the selected SD and NVMe.

Through the client, create an exclusive qualification file, synchronize it and
its directory, reopen it and hash all bytes. Independently reopen and hash it
on malak, then recheck it through a fresh client view. Verify the exact file
operations used by the staging tool, including protected parent traversal,
exclusive creation, sparse snapshot sizing, mode changes and directory fsync.
Retain the size/digest and both observations. A successful small-file check
does not replace independent readback of every actual recovery range.

Revalidate the USB interface, authenticated Pi boot, server/export/mount
identity, free capacity and immutable runtime digests immediately before
preparation. Keep the transport available through preparation and staging.
A lost link, incomplete journal or uncertain attempt requires reconciliation;
do not automatically retry or overwrite its evidence.

Only after storage qualification, inactive SD capture, complete recovery
requirements, approved hardware/ownership bindings and the separate physical
execution approval can the staging ceremony proceed. Storage setup does not
close a campaign claim, establish safe-off or set `security_applied`.
