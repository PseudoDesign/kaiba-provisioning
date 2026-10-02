# Synthetic campaign fixture

`synthetic-plan.json` is the canonical public plan produced by the repository's
`kaiba-campaign-preparation-plan` Nix test fixture (campaign
`campaign-preparation-fixture`). It supplies the fixed 33-run, 37-claim matrix
to signature, rejection and admission tests without building fixture images
for each unit-test run.

The unit tests create temporary test-only Ed25519 keys and synthetic captures.
This plan and those captures provide no physical acceptance evidence. The
native `stable-campaign-packet-integration` check separately prepares an
expectation from the Nix fixture's actual materialized payload bytes and
independently compares their complete partition hashes.
