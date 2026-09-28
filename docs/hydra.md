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
`true` routes the ten heavy ARM64 checks on `main` pushes to Hydra. The required `x86_64` aggregate
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

## PR and manual CI routing

After the `kaiba-hydra-ci-runs` service is deployed on Ace, set the repository
variable `HYDRA_CI_ENABLED=true`. It independently routes the same ten heavy
checks on `pull_request` and CI `workflow_dispatch` runs to Hydra. Setting it
back to `false` restores their GitHub ARM matrix on subsequent runs.

Ace polls the GitHub API every minute for running Hydra waiter jobs in this
repository's CI workflow. A queued or unapproved run cannot schedule work.
The waiter job name carries `github.sha`; keep that name's format unchanged.
For PRs, this is the synthetic merge commit, verified against the run's head
SHA. For manual runs, it must match the dispatched commit. Fork PRs require no
repository secret. Credentials for Hydra administration remain on Ace.

Each run attempt gets an immutable jobset named
`kaiba-provisioning/ci-<run-id>-<attempt>`, triggered once with automatic polling
disabled. Rerunning the Hydra waiter creates a new
attempt jobset; another PR or manual run cannot cancel its waiter through a
shared main-only concurrency group. All ten jobs are checked, with Hydra reusing
unchanged successful derivations. Other selective image checks retain their
input comparison and GitHub builders.

The waiter checks the jobset's pinned commit, the evaluation's immutable flake
reference, exactly ten distinct jobs, their ARM64 architecture, and the exact
planned derivation paths. It accepts a reused build only through membership in
that evaluation. Missing results, mismatched identities, evaluation failures,
cancelled builds and nonzero build statuses cannot pass the required aggregate.
Its GitHub summary links to all ten Hydra builds.

The waiter allows nearly six hours for queued work and uncached builds on Ace,
within GitHub's [hosted job limit](https://docs.github.com/en/actions/reference/limits).
A timeout fails the required gate while Hydra may continue building. Rerun the
workflow after those builds finish to verify and reuse their results.

Historical run results remain visible. Run jobsets do not poll automatically,
and their outputs are disposable under normal retention. A build
already scheduled when its GitHub workflow is cancelled may finish. PR/manual
jobsets do not publish to Cachix or use main's commit-status contexts. Other
manually dispatched release and component workflows keep their existing
artifact/publication contracts.

Ace asynchronously publishes successful main checks' output and build dependency
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
