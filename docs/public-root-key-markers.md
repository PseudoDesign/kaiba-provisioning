# Public literals in root payloads

Some standard libraries and executables contain private-key PEM headers as
parser strings or published cryptographic self-test constants. A raw marker
search therefore rejects the reviewed development root image even when its
bytes match the signed release manifest.

The shared `internal/provisioning/pemmarkers` scanner rejects PEM/OpenSSH
private-key markers by default. Release packaging, campaign plan inspection,
and media preparation enable `reviewed-root-literals` only for their closed
release-root and media-root-data roles. Kernel, initramfs, device tree,
overlays, metadata, and verifier boot inputs retain strict scanning.

The compiled [catalog](../internal/provisioning/pemmarkers/reviewed_literals.json)
contains 21 exact fingerprints, public file provenance, and source references.
It contains no PEM bodies and accepts no caller-supplied exceptions. Each
accepted span begins at a recognized marker and ends at the first NUL byte,
inclusive. Its marker type, length, and SHA-256 must all match one catalog
entry. A candidate span is limited to 16 KiB. Unknown, changed, oversized, or
unterminated marker-bearing spans fail the scan. The scanner continues through
the rest of the file after each accepted span, so a later unknown marker still
fails.

The catalog accounts for all 42 occurrences in the development root payload
whose SHA-256 is
`68ebaaad2985e13b445b0d71bc7f3ef16fa064e870ee561f367282f3b4a80313`.
The occurrences include twelve complete GnuTLS self-test constants and thirty
parser or format-string literals in public libraries and OpenSSH binaries.
Every span was compared with its corresponding immutable public store file.
The GnuTLS constants were also compared with the named C constants in
`gnutls-3.8.13/lib/crypto-selftests-pk.c`, from the fixed-output GnuTLS source
archive. The catalog records both source hashes and constant names for
independent review. The image hash identifies that investigation; it does not
exempt an entire image from scanning.

This is a bounded marker check, not a proof that an opaque file contains no
private material. Known public literals are accepted wherever their exact
bytes occur within an eligible root role. Other private-key encodings remain
outside the marker check's scope. Input-role labels alone do not authenticate
provenance; signed manifest validation and source/build evidence remain
separate requirements.

Scanning does not alter the input or perform a private-key operation. Campaign
inspection still hashes every original byte and every requested mutation byte.
Changing the scanner leaves release component bytes, signatures, and
hardware qualification unchanged.
