# Preparing exact release candidate artifacts

Use **Actions → Release candidate artifacts → Run workflow** to prepare a
stable-campaign development provisioner or a file/live-FDT verifier for review.
The default `provisioner` profile preserves the existing provisioner export.
Select the `main` workflow
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

For the `verifier` profile, ARM64 instead builds the exact unsigned verifier
boot image and its verifier-only signing plan. The x86 lane exports the
configured verifier signing runtime. Each build lane checks both the running
Linux CPU architecture and Nix's native system before building; ARM outputs
are not assembled by cross-compilation or a local x86 fallback.

Both checkouts use the same selected source SHA. Reporting tools stay pinned to
the workflow's own SHA, which is recorded separately. The ARM export checks
that the unsigned manifest and signing intent name the selected source and
that the intent binds that exact unsigned manifest and artifact set.
Builds reject any required lock-file update, including an update only in memory,
so the selected commit's dependency pins remain part of the candidate identity.

## Reviewed verifier public inputs

The verifier profile requires a relative `public_inputs` directory already
committed in the selected source revision. Its complete file set is:

| File | Meaning | Maximum size |
| --- | --- | --- |
| `candidate.json` | Closed verifier configuration below | 16 KiB |
| `policy.json` | Reviewed root-signed verifier policy | 1 MiB |
| `root-public.pem` | Public policy-root key | 16 KiB |
| `authority-ca.pem` | Public TLS authority certificate | 64 KiB |

Only ordinary Git `100644` files are accepted. Directory traversal, symlink
components, hardlinks, special files, missing/extra files, oversized content
and recognizable private-key PEM material are rejected. The exporter compares
each file's bytes with its blob in the selected commit before and after the
build, including when Git's working-tree status has been told to ignore a file.
An external workstation directory or `/tmp` input is not accepted.

`candidate.json` has exactly these nine keys. This example describes fields;
it is not a selected candidate or a working authority configuration:

```json
{
  "schema_version": "kaiba.provisioning.rpi5-stable-verifier-candidate/v1alpha1",
  "verifier_version": 1,
  "cohort_id": "development-pi5",
  "slot_id": "a",
  "minimum_security_epoch": 1,
  "authority_url": "https://authority.example.invalid:8443",
  "authority_key_id": "authority:reviewed",
  "audience": "stable-verifier-hardware-spike",
  "logical_identity": "development-pi5"
}
```

Duplicate or unknown JSON fields are rejected. Versions and epochs are integers
from 1 through 2,147,483,647. IDs use lowercase letters, digits and `._:-`, start
with a lowercase letter or digit, and have at most 128 characters. The HTTPS
URL is at most 2,048 ASCII characters, with a hostname and no credentials,
whitespace, control characters or fragment. Firmware selection, kexec mode,
extra NixOS modules, input filenames and the 96 MiB image size are fixed by
`mkRpi5StableVerifierCandidate`; configuration cannot override them.

After reviewing and committing the four public files with the supported
constructor, select that exact main-history commit:

```console
gh workflow run release-candidate.yml --ref main \
  -f source_sha=<full-reviewed-main-commit-sha> \
  -f profile=verifier \
  -f public_inputs=reviewed-candidates/example-verifier
```

The workflow calls `flake.lib.mkRpi5StableVerifierCandidate` with that source
revision, the committed public directory, and the commit's committer timestamp
as `sourceDateEpoch`. The timestamp is not a dispatch-time selector. It checks
the actual unsigned manifest, both copies of `boot.img`, the signing intent and
plan against those exact bytes, source and epoch. The public verifier command
also runs `validate-plan` and `validate-unsigned`; neither operation signs.
The four reviewed input files and their SHA-256, size and Git blob identities
are retained in both architecture exports. A passing export records build
provenance, not policy approval, authority availability or hardware readiness.

## Retain and reuse the outputs

Wait for **Release candidate artifacts complete** and the whole workflow to
succeed. Download both `candidate-<sha>-<system>` artifacts from that run;
for the verifier profile their names are
`candidate-verifier-<sha>-<system>`.
Their default retention is 30 days. Retain them with the candidate's review
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
- Verifier downloads include `public-inputs/` with the exact four reviewed
  files. Their hashes and the source commit timestamp are also recorded in
  `provenance.json`; `SHA256SUMS` covers those copied files.

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
with this exact source and these exact bytes. For the verifier profile, use the
separate verifier-only signing plan and authenticated campaign evidence path;
the provisioner intent cannot authorize a verifier. The unsigned inner
`boot.img` still requires its signature and outer boot filesystem before media
staging. This workflow does not supply delegated-release manifests, campaign
mutation inputs, recovery backups or physical campaign observations.
