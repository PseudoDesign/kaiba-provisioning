# Development and validation workflow

Use `nix develop` once per shell, then use `scripts/check.sh` to select the
smallest check that answers the current question. The commands use the pinned
tools and retain Go's normal local build and test cache.

| Stage | Command | Purpose |
| --- | --- | --- |
| Edit a Go component | `scripts/check.sh go ./internal/provisioning/campaignmedia ./cmd/kaiba-rpi5-stable-campaign-gpt-inspect` | Exercise the affected packages without images or signing plans |
| Edit station assets | `scripts/check.sh ui` | Python asset contracts and JavaScript behavior |
| Prepare a candidate | `scripts/check.sh fast` | Formatting, complete Go suite, UI checks, and inert deployment smoke test |
| Change a Nix contract | `scripts/check.sh contracts CHECK...` | Realize named checks on the current native architecture |
| Finish a PR | `scripts/check.sh full` | Complete native Nix checks; CI covers both supported architectures |

Go test flags can follow package names, for example `-run TestInitialGPT`.
Use `-count=1` when fresh execution matters; routine editing should benefit from
Go's test cache. A focused pass does not replace the finished candidate's full
CI result. Run the native ARM checks in CI or on an approved native ARM builder.

## Test ownership

`checks.<system>.unit` owns the complete Go suite. It is independent of the probe
binary, firmware and other package builds, so CI runs it before the broader x86
check graph. The later `flake check` reuses the same result in the same Nix store.

`checks.<system>.unit-static` owns the existing static-mode contract package
coverage with `CGO_ENABLED=0`. It preserves the different build mode while
sharing one compiler cache across the packages. EEPROM, media and release
contracts depend on that result instead of running those unit tests again. The
static suite also emits the synthetic publication fixture used by the release
schema check. Packaging, schema validation, dependency restrictions, and native
ARM execution remain separate checks.

Avoid adding a Go rerun to a Nix contract unless it exercises a distinct build
mode or supplies an integration artifact that cannot be obtained from the
existing test outputs. Avoid rerunning a full suite after a comment-only edit
when its inputs and the tested source revision have not changed. Changes to
actual code, dependencies, or integration invalidate the relevant evidence.

## Candidate and physical boundaries

Finish implementation and review before choosing the immutable release commit.
Record the commit used to build final artifacts alongside their digests. PR CI
tests GitHub's merge result, which can have a different revision from the branch
head; the source revision embedded in an image makes those artifact identities
different even if their application code is identical.

Keep complete signing approval, device selection, recovery and independent
readback at their existing execution boundaries. For hardware iteration,
prioritize an observable positive baseline, then one negative case, before the
full qualification matrix. Generic QEMU regressions establish their documented
software behavior; physical Pi results establish the hardware behavior.
