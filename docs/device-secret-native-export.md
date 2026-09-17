# Native device-secret candidate export

The `Device-secret candidate` workflow builds the exact unsigned experiment on
GitHub's native ARM runner when the workstation has no native ARM builder. It
uses the existing experiment and signing-plan constructors; it does not select
a physical device or authorize an operation. This is a preparation route for the
[execution packet](device-secret-execution-packet.md).

## Inputs and visibility

Dispatch from `main` with a complete lowercase source commit already in its
history, the closed twelve-field public experiment JSON, and SHA-256 of the exact
JSON bytes. The configuration's `source_revision` must equal the selected commit.
The workflow uses the development signer public key/review pinned in that source.
There is no arbitrary expression, package, source URL or signer selector.

**The submitted bindings are visible in Actions and exported artifacts.** Use
only reviewed public experiment identifiers, hashed board/disk identifiers,
public UUIDs/nonce, source revision, slot and expected usage. Keep raw serials,
host selectors, SSH details, review notes, credentials, secrets, backups, captures
and execution grants on the private workstation. A digest is a binding, not a
publication approval. Obtain any required review of selected inputs before
sending them to the public workflow. Never use a secret as the public nonce.

After that review, prepare a dispatch body without shell interpolation:

```console
python3 - /absolute/reviewed-experiment.json > /absolute/dispatch.json <<'PY'
import hashlib, json, pathlib, sys
raw = pathlib.Path(sys.argv[1]).read_bytes()
config = json.loads(raw)
json.dump({"ref": "main", "inputs": {
    "source_sha": config["source_revision"],
    "experiment_json": raw.decode("utf-8"),
    "experiment_sha256": hashlib.sha256(raw).hexdigest(),
}}, sys.stdout)
PY
gh api --method POST \
  repos/PseudoDesign/kaiba-provisioning/actions/workflows/device-secret-candidate.yml/dispatches \
  --input /absolute/dispatch.json
```

The exact bytes, including a final newline, are hashed and retained. The Nix
constructor independently validates its checked representation using the target
helper's `--check-config` mode. Neither validation opens firmware or media.

## Outputs and workstation handoff

The artifact name binds the source revision and submitted configuration digest.
Its provenance records workflow/source revisions, Actions run/attempt, native
runner verification, both submitted/checked configuration digests, selected Nix
paths/NAR hashes and the complete exported closure's hashes, sizes and references.
The closure is bounded to 8 GiB before export.

The archive contains all five output roles: unsigned boot/root/tree artifacts,
checked experiment configuration, experiment review, single-image signing plan,
and its separate signing-input manifest. It also includes readable copies of
the manifests/review/public key and a checksum list. Both source and output
bindings are checked before export. The signing-plan constructor verifies the
verity tree, signed-root arguments and single-image signing contract during its
file-only build. No signer or target execution command runs.

Download the exact run's artifact to a new private directory on malak. Verify
its source/configuration against the local reviewed proposal and the archive
checksum before importing the Nix closure. Verify every retained NAR hash and
create durable GC roots for the selected outputs. Re-evaluate the same pinned
constructor locally: its output paths must agree with the imported paths.
Do not enable emulated rebuilding as a fallback for a missing imported output;
a different path or missing output needs investigation.

Then prepare the existing [native signing ceremony](native-offline-handoff.md)
for these exact bytes. Signing approval, authenticated receipt finalization,
slot/image review, packet construction, media backup/staging and the two physical
boots remain separate. An unsigned export cannot qualify HMAC or copied-media
protection, and cannot be used as a media-execution packet.

## Verification

The regular-file tests reject mismatched/duplicate/extra inputs, unsupported
slot usage, raw identifiers, injected expressions, non-native hosts, altered
experiment bindings, altered payloads and authorization claims. The existing
source-selection tests cover full-SHA main ancestry and clean checkouts.

```console
python3 -B -m unittest discover -s tests/release-candidate -p 'test_*.py' -v
```

Native CI also runs the complete build/export path using synthetic bindings and
labels the output `ci-rehearsal`. It does not upload that rehearsal as a selected
physical candidate. This tests the workflow's artifact handoff in addition to
the existing target, LUKS and media-executor checks.
