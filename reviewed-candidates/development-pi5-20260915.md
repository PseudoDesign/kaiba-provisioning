# Development Pi 5 verifier public inputs, September 15, 2026

`development-pi5-20260915/` contains the four public inputs for the native
file/live-FDT verifier candidate. It selects cohort `development-pi5`, slot `a`,
verifier version 1, minimum security epoch 1, and authority
`https://192.168.8.249:8443`. The existing protocol authority key and logical
identity remain selected.

The root-signed policy has security epoch 2 and threshold 1. It retains active
primary `release-vm`, adds active replacement
`release-development-replacement-20260915`, and includes revoked negative-case
key `release-development-revoked-20260915`. Its canonical policy digest is
`sha256:8b3d95cc2065e80ee703aafb22321b8dd9014af28f4e4e27608426fd939719b9`.
The policy root remains `root-vm`, SPKI fingerprint
`sha256:7b47962aa6703403156ce19c111418d27edba56b43259d710e2ba05136f4877d`.

The public Ed25519 TLS CA expires October 16, 2026 at 04:07:11 UTC. The separately
retained server certificate covers only IP `192.168.8.249` and expires October
15 at 04:07:11 UTC. TLS keys are distinct from the policy's protocol-authority
key. Private keys and server credentials remain on the development station.

After this selection is reviewed into main and its CI passes, use the
[release-candidate workflow](../docs/release-candidate-artifacts.md) with the
exact main-history source commit, `profile=verifier`, and
`public_inputs=reviewed-candidates/development-pi5-20260915`. The source epoch
comes from that commit. The native ARM lane prepares the unsigned image and
signing plan; its successful output still requires the separate verifier-boot
signing review.

Public input selection and offline verification do not establish authority
availability, released-OS compatibility, recovery readiness, or physical
qualification. Continue with the [campaign preparation procedure](../docs/stable-campaign-preparation.md)
and its separately bound release manifests and hardware evidence.
