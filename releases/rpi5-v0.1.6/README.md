# Raspberry Pi 5 v0.1.6 public signed inputs

This directory contains the already-signed, public inputs for the development
Raspberry Pi 5 v0.1.6 payload. It intentionally contains no private key,
signer, PIN, or signing provider.

The firmware's upstream copyright notices, license conditions and disclaimers
are in [notices/](notices/README.md), together with the file mapping and the
remaining permission question for configured and signed firmware. Keep that
directory with copies of these inputs.

The root flake's signed-release contracts pass these files through the v0.1.6
recovery verifier. That verifier binds the signatures, grants, receipts,
payload source revision, customer-key hash, EEPROM hash, boot image, and
RPIBOOT bundles. The standalone flake does not currently export the historical
development-station image composition.

`SHA256SUMS` covers every checked-in input file, the exact operational
payload manifest, and the firmware notice files. The verification checks
reconstruct the complete signed release and byte-compare its RPIBOOT bundles and signed-release manifest
binding. See the
[signed-boot workflow](../../docs/raspberry-pi-5-signed-boot-workflow.md) for
the public release boundary and its nonclaims.
