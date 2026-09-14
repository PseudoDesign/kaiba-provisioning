# Synthetic recovery-requirements fixtures

These canonical JSON fixtures are generated from
`mustTestRecoveryBackupRequirementsV1Alpha2` in
`recovery_requirements_v1alpha2_test.go`. The checked-in fixture test requires
an exact match to those deterministic helpers.

The SD fixture contains parser-produced selected and distinct physical-end
GPT lineage metadata. The NVMe fixture uses the reviewed v1alpha2 first-usable
LBA 2048 layout. Payload digests are synthetic; no hardware capture or private
campaign material was used. These files are contract inputs for tests, not
backups, media bytes, physical evidence, or authorization to stage a device.
