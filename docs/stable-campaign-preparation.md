# Preparing a complete public campaign

**Scope:** reference for the existing online stable-verifier campaign. Its artifacts and safety boundaries remain valid within their recorded scope; its server-required boot and offline-refusal behavior do not define the selected [offline fleet policy](fleet-admission-policy.md).

`mkRpi5StableVerifierCandidate` builds the native ARM verifier and its public
signing plan from a closed public configuration. After the reviewed signatures
exist, `mkRpi5StableVerifierCampaignPreparation` connects the release, twenty
manifest mutations, complete campaign plan, four payloads, first two run
materializations, staging plan, recovery requirements and packet check.

These constructors operate on files in the Nix store. Their results do not
capture recovery backups, approve signing or media writes, start an authority,
change Pi power, or establish hardware qualification.

## Native unsigned verifier

Prepare a directory containing exactly four public regular files:

- `candidate.json`, using the [candidate schema](../schemas/rpi5-stable-verifier-candidate-v1alpha1.schema.json).
- `policy.json`, the canonical signed policy, with the reviewed delegated keys.
- `root-public.pem`, the independent RSA public key for that policy.
- `authority-ca.pem`, the public TLS CA certificate selected for the actual test window.

The candidate configuration selects the verifier version, cohort, slot, minimum
security epoch, HTTPS authority origin, authority key ID, audience and logical
identity. The constructor fixes the native ARM platform, file/live-FDT handoff,
firmware inventory and 96 MiB boot image; it has no extra-module or signing
selector. The authority URL permits an empty path or `/` and no query, matching
the verifier's authority client. Source revision and epoch are explicit independent arguments.

```nix
candidate = kaiba.lib.mkRpi5StableVerifierCandidate {
  publicInputs = ./reviewed-verifier-public-inputs;
  sourceRevision = reviewedCommit;
  sourceDateEpoch = reviewedCommitTimestamp;
};
# candidate.unsignedBoot and candidate.signingPlan are aarch64-linux outputs.
```

For public inputs reviewed into a main-history commit, the
[candidate export workflow](release-candidate-artifacts.md) supports the
`verifier` profile. It builds on the native ARM runner and exports the exact
public inputs, image, signing plan and closure with source/NAR/file records.
The x86 lane exports the configured verifier signing runtime. A local private
consumer may use the same constructor without publishing its public input
selection; it still needs a native ARM builder for uncached outputs.

Evaluation and image construction do not verify policy signatures or establish that a TLS
certificate will be valid during a future attempt. Final review must cover
those trust choices and the exact configuration before
[verifier signing](stable-verifier-signing.md).

## Manifest mutation preparation

The `kaiba-rpi5-stable-campaign-mutations` CLI consumes the signed policy,
independent root public key, and positive, replacement and revoked manifests.
Each manifest must contain one real signature over the same release preimage.
The primary and replacement keys must be different active keys; the third key
must be distinct and revoked. Threshold one is required for this campaign.

```console
kaiba-rpi5-stable-campaign-mutations \
  --policy /absolute/public/policy.json \
  --root-public-key /absolute/public/root-public.pem \
  --positive-manifest /absolute/public/positive-manifest.json \
  --replacement-manifest /absolute/public/replacement-manifest.json \
  --revoked-manifest /absolute/public/revoked-manifest.json \
  --output /absolute/new-mutation-directory
```

The tool authenticates those signatures, preserves the replacement/revoked
manifest semantics, derives the unsigned and wrong-key cases, and creates the
sixteen single-field cases. It checks each exact change through the campaign
resolver. It publishes exactly twenty files in a new directory. It never signs
or generates keys. Metadata signature verification does not authenticate the
release component bytes or their build provenance.

## Complete assembly after signing

Supply the authenticated signed verifier from
`mkRpi5VerifiedStableVerifierSigning`, the independently built delegated release
from `mkRpi5DelegatedReleaseSpike`, the two separately signed manifests, six
reviewed disk/partition GUIDs and the two retained v1alpha2 GPT envelopes:

```nix
preparation = kaiba.lib.mkRpi5StableVerifierCampaignPreparation {
  system = "x86_64-linux";
  inherit campaignID sourceRevision verifiedSignedBoot delegatedRelease;
  inherit replacementManifest revokedManifest;
  inherit sdDiskGUID nvmeDiskGUID bootPartitionGUID;
  inherit rootDataPartitionGUID rootHashPartitionGUID releasePartitionGUID;
  inherit sdEnvelope nvmeEnvelope;
};
```

Every artifact argument must be a fixed store path. Import only each specific
public file, not a credential or evidence directory. The caller must provide
truthful source/build provenance for the released OS; selecting a tooling
revision does not relabel older OS components.

Release packaging, plan input inspection, and media construction share the
[public root literal scan](public-root-key-markers.md). Its fixed exceptions
apply only to the release root and media root-data roles. They account for
exact public library constants without changing the root bytes or their signed
manifest digests; all other roles retain strict PEM marker rejection.

The consumer extracts the public trust files from the signed verifier and
derives the exact 27 public inputs and 10 mutation targets from the release and
real first overlay. Each role gets a separate regular file. It computes the
deterministic root hash tree before plan creation, then the media constructor
independently regenerates and validates it. This removes the dependency cycle
between the plan and media. The complete fixed campaign remains 33 runs and
37 planned claims.

Useful returned outputs are `campaignMutationInputs`, `planInputs`,
`campaignPlan`, `baselineMedia`, `run1`, `run2`, `stagingPlan`,
`recoveryRequirements`, and `packet`. Build `packet` to require the entire
chain and prove that the independently selected first two runs use identical
baseline payloads. `payloads` names the four immutable payload files for the
separate [per-leg staging constructors](stable-campaign-staging.md).

`kaiba-rpi5-stable-campaign-staging-plan` also exposes the staging-plan step
directly. Its twelve required flags select the campaign plan, artifact set,
six GUIDs and four public payload files. It hashes the actual payloads and
their complete zero tails, renders the final GPT bytes using the shared
renderer, checks all bindings, and writes canonical JSON to stdout. It opens
only regular files and has no block-device or write interface.

The recovery envelopes are descriptions of previous reads. The packet cannot
refresh them or turn their digests into backup bytes. The archived
[first physical baseline procedure](archive/first-physical-baseline.md) records this candidate's requirements for
backup capture/readback, attachment checks, staging approval, media writes and
bounded run observations. It is not a direction to resume that campaign as
the next fleet milestone.

## Software verification

The Go tests cover cryptographic substitutions, exact mutation selectors,
payload/tail hashes, GPT generation, malformed inputs and file boundaries.
`checks.<system>.stable-campaign-preparation` uses explicitly synthetic keys,
release components and initial GPT declarations to exercise the complete Nix
assembly, including both run materializations and the packet checker. It does
not simulate or attest a physical boot.
