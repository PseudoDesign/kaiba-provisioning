# Hydra ARM64 jobset

`hydraJobs.aarch64-linux` exports the ten large checks inventoried by the pinned
`kaiba-infra` input. Each entry is the existing `checks.aarch64-linux` derivation;
there is no alternate test implementation or dependency override. Missing
inventory entries or incorrect derivation architectures fail evaluation.

Hydra on Ace polls this repository's `main` every five minutes once hardware
qualification and the infrastructure test gate have passed. GitHub Actions
remains the PR gate and runs the broader checks, package and export workflows.
The Hydra bundle does not replace that complete workflow.

## Main-push CI routing

The repository variable `HYDRA_MAIN_ENABLED` defaults to `false`. After native
qualification and live GitHub status delivery are verified, setting it to
`true` routes the ten heavy ARM64 checks on `main` pushes to Hydra. PRs and
manual runs retain the existing GitHub builders. The required `x86_64` aggregate
keeps its name and requires whichever backend the planner selected.

The Hydra waiter reads the newest status for each
`ci/hydra/kaiba-provisioning/aarch64-linux.<check>` context on the exact commit,
then verifies the linked build's repository, jobset, architecture, success and
derivation path against the planner. Missing, failed or mismatched jobs cannot
pass. The waiter needs only the workflow's read-only GitHub token; Ace holds the
separate status-write token. Public Hydra requests never carry GitHub tokens.

Hydra polls every five minutes and can skip intermediate main revisions. The
waiter fails if main has advanced before any statuses arrive; newer main runs
cancel older waiters. It never substitutes the latest evaluation's success for
the requested commit. Set `HYDRA_MAIN_ENABLED=false` to restore GitHub main
builds on subsequent workflow runs.

Ace asynchronously publishes successful checks' output and build dependency
closures to the existing `kaiba-provisioning` Cachix cache. Upload failures retry
independently of test results. See the infrastructure runbook for credentials,
service diagnostics and notification replay.

The input is `flake = false`, so it imports policy without adding another
nixpkgs dependency. When infrastructure policy changes, update this input's
lock deliberately and inspect the resulting job list:

```sh
nix flake update kaiba-infra
nix eval --json .#hydraJobs.aarch64-linux \
  --apply 'jobs: builtins.mapAttrs (_: drv: { inherit (drv) system drvPath; }) jobs'
```

Deployment and operation instructions live in `kaiba-infra/docs/hydra-on-ace.md`.
