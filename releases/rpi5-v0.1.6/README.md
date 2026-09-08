# Raspberry Pi 5 v0.1.6 public signed inputs

This directory contains the already-signed, public inputs for the development
Raspberry Pi 5 v0.1.6 payload. It intentionally contains no private key,
signer, PIN, or signing provider.

The root flake's signed-release contracts pass these files through the v0.1.6
recovery verifier. That verifier binds the signatures, grants, receipts,
payload source revision, customer-key hash, EEPROM hash, boot image, and
RPIBOOT bundles. The standalone flake does not currently export the historical
development-station image composition.

`SHA256SUMS` covers every checked-in input file and the exact operational
payload manifest. The verification checks reconstruct the complete signed
release and byte-compare its RPIBOOT bundles and signed-release manifest
binding. See the
[signed-boot workflow](../../docs/raspberry-pi-5-signed-boot-workflow.md) for
the public release boundary and its nonclaims.
