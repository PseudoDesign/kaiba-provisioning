# Preparing exact release candidate artifacts

Use **Actions → Release candidate artifacts → Run workflow** to prepare a
stable-campaign development provisioner for review. Select the `main` workflow
branch and supply the complete lowercase 40-character commit SHA to build.
The commit must already belong to the history of `main` at dispatch time.
An unmerged branch, abbreviated SHA, tag, or dirty working tree is not a
candidate input. A historical main commit is allowed, so preparing a retained
candidate does not silently advance its source when main changes.

The equivalent GitHub CLI command is:

```console
gh workflow run release-candidate.yml --ref main \
  -f source_sha=<full-reviewed-main-commit-sha>
```

Ordinary PR CI continues to check GitHub's prospective merge result, including
realization of both configured signing runtimes and the native public signing
plan. Its required check names and x86/ARM success gate remain intact. Those
checks test integration; the synthetic merge SHA is not the source to use for signing.
After merge, choose the actual main commit and its passing CI run. Main CI
also builds the operator outputs to populate the trusted cache. Candidate
preparation reuses those caches without cache-write credentials.

The candidate workflow builds two native lanes:

| Builder | Selected outputs |
| --- | --- |
| Native ARM64 | Unsigned provisioner boot/root artifacts and their signing plan |
| x86_64 | Configured development signing runtime, built without invoking it |

Both checkouts use the same selected source SHA. Reporting tools stay pinned to
the workflow's own SHA, which is recorded separately. The ARM export checks
that the unsigned manifest and signing intent name the selected source and
that the intent binds that exact unsigned manifest and artifact set.

## Retain and reuse the outputs

Wait for **Release candidate artifacts complete** and the whole workflow to
succeed. Download both `candidate-<sha>-<system>` artifacts from that run;
their default retention is 30 days. Retain them with the candidate's review
records before expiration. An artifact from one successful lane of an otherwise
failed run is incomplete preparation.

Each download includes:

- `nix-store-export.gz`: the selected outputs and their complete runtime
  closures, including the unsigned image bytes on ARM. This preserves exact
  store paths and references when the hosted runner disappears.
- `provenance.json`: selected source, main and workflow revisions, workflow run
  identity, Nix version, package attributes, output paths and NAR hashes,
  exported paths, and the compressed archive size and SHA-256.
- `SHA256SUMS` and `SUMMARY.md`: file checksums and a readable inventory.
- The ARM download also includes the public unsigned manifest, signing plan,
  release intent, and public key for review without importing the large archive.

On the Nix-equipped review/signing workstation, unpack each download into a
separate directory and compare its source SHA, workflow run, and archive digest
with the successful workflow's job summary. Then verify and import it:

```console
sha256sum --check SHA256SUMS
gzip --decompress --stdout nix-store-export.gz | nix-store --import
```

The import may require the workstation's normal Nix administrator privileges.
This is a [Nix store export](https://nix.dev/manual/nix/latest/command-ref/nix-store/export),
so references and executable permissions survive the transfer. It includes
runtime closures, not every build-time dependency. Read the exact top-level
paths from `provenance.json`; compare `nix path-info --json <output-path>` with
the recorded NAR hashes. ARM artifacts can be imported and inspected on x86;
ARM executables still require an ARM execution environment. Use the separately
exported x86 runtime on the signing workstation.

These outputs are public build inputs. The workflow has no signing credentials,
does not contact a token, does not sign, and does not stage or boot hardware.
A successful build is not a signing approval, a replacement for the selected
commit's CI and independent review, or hardware qualification. Continue the
reviewed [development provisioner signing and staging boundary](raspberry-pi-5-development-target-access.md)
with this exact source and these exact bytes. The unsigned inner `boot.img`
still requires its signature and outer boot filesystem before media staging.
