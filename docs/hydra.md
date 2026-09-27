# Hydra ARM64 jobset

`hydraJobs.aarch64-linux` exports the ten large checks inventoried by the pinned
`kaiba-infra` input. Each entry is the existing `checks.aarch64-linux` derivation;
there is no alternate test implementation or dependency override. Missing
inventory entries or incorrect derivation architectures fail evaluation.

Hydra on Ace polls this repository's `main` every five minutes once hardware
qualification and the infrastructure test gate have passed. GitHub Actions
remains the PR gate and runs the broader checks, package and export workflows.
The Hydra bundle does not replace that complete workflow.

The input is `flake = false`, so it imports policy without adding another
nixpkgs dependency. When infrastructure policy changes, update this input's
lock deliberately and inspect the resulting job list:

```sh
nix flake update kaiba-infra
nix eval --json .#hydraJobs.aarch64-linux \
  --apply 'jobs: builtins.mapAttrs (_: drv: { inherit (drv) system drvPath; }) jobs'
```

Deployment and operation instructions live in `kaiba-infra/docs/hydra-on-ace.md`.
