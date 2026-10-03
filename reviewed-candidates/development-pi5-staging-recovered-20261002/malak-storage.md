# Malak backing storage worksheet

The operator selected malak for the development Pi's staging runtime and
recovery evidence. The provisioner has a read-only Nix store, about 510 MB
free in `/tmp`, about 268 MB in `/var`, and no separate writable disk.
The selected NVMe cannot hold its own runtime or recovery backups.

This is a setup proposal. No export, service, Pi mount or physical attempt
has been activated or qualified. Administrator setup is required because
the malak account has no passwordless sudo.

## Proposed scope

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
The host currently has no NFS export or listener. Pinned native x86 NFS helpers
were built at
`/nix/store/bkj4vw2fnz0idzj6vy32m37pcja2pxzh-nfs-utils-2.9.2`;
only their help interface was used.

## Administrator setup packet

After the new ARM export and complete NVMe assembly have been independently
verified, bind the setup record to that closure's complete path/NAR inventory,
the selected campaign, plan digest, authenticated Pi boot and malak filesystem.
The currently retained archive has all recovered inputs and the complete SD
runtime, but it lacks the new ARM component and complete NVMe runtime. It is
not the final Pi runtime export.

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
and payloads through their actual `/nix/store` paths on the Pi. This temporary
mount arrangement needs on-device qualification; no signed provisioner rebuild
or change to Nix trust is implied.

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
