# First-baseline preparation packet

`kaiba-rpi5-stable-campaign-packet` checks the public inputs needed for run 1,
`positive-baseline`, and run 2, `authorization-offline-rejected:authority-offline`.
It emits one digest-bound preparation report. The tool requires both independent
run materializations and proves that they use the same four baseline payloads.
It does not create physical evidence or authorize an attempt.

## What is checked

Supply the canonical campaign plan, baseline `artifact-set.json`, both run
`materialization.json` records, staging plan, v1alpha2 recovery requirements,
and the independently retained SD and NVMe envelopes. The tool:

- Rehashes all 27 public inputs and all 10 positive byte-mutation targets,
  checks the planned mutation digests, and resolves their public semantics.
- Cross-binds those bytes to the artifact set and both code-selected runs.
  Replacing run 2 with another baseline record or substituting a mutated run
  is rejected.
- Cross-binds the staging layout and recovery requirements to the independent
  inputs. It independently renders final GPT bytes and checks their planned
  digests, including the full-device backup placement.
- Hashes each actual payload and its complete planned zero tail. The four
  source bindings and whole-partition expectations must match the staging plan.
- Derives each run's required verifier trace, terminal boundary, raw evidence
  roles, and outstanding claim-specific witnesses from the fixed campaign.

The report's assurance is `public-byte-and-contract-consistency-only`. Its
source revision is an explicit caller assertion: neither Git history nor CI
provenance is authenticated here. Public signatures are not cryptographically
verified by this tool; retain the reviewed signing and artifact-build records.
The public-input names describe the caller's selections, not proof that the
files originated in the intended release tree or build.

## Prepare the report

Retain the inputs in the operator's protected evidence directory outside Git.
Use the exact 27 named files and 10 mutation-target files selected for the
campaign plan. The `positive-release-tree` input is the plan's domain-prefixed
serialized file inventory, not an arbitrary archive of that directory. Reuse
the exact resolver bytes rather than constructing an approximate replacement.
Keep regular copies with no symlinks or hard links; separate public input and
mutation-target roles must have distinct opened file identities. A payload may
reuse its corresponding mutation-target file, but different payload roles may
not reuse one inode.

All paths must be canonical absolute Linux paths. Contract JSON files are
limited to 1 MiB, each public source to 16 GiB. The reader walks parent
directories without following symlinks and rejects special files with `O_PATH`
before acquiring a readable descriptor. It retains opened file identities and
checks metadata again before emitting the report. These checks do not establish
an atomic snapshot against a malicious local operator.

For a prepared input directory, this Bash example derives the repeated names
from the retained campaign plan and passes them without shell evaluation:

```bash
packet_dir=/absolute/protected/first-baseline
public_dir=/absolute/protected/campaign-public-inputs
target_dir=/absolute/protected/campaign-positive-targets
source_revision=FULL_REVIEWED_COMMIT_SHA

args=()
while IFS= read -r name; do
  args+=(--public-input "$name=$public_dir/$name")
done < <(jq -r '.public_inputs[].name' "$packet_dir/campaign-plan.json")
while IFS= read -r target; do
  args+=(--byte-mutation-target "$target=$target_dir/$target")
done < <(jq -r '.byte_xor_mutations[].target' "$packet_dir/campaign-plan.json")

nix run .#kaiba-rpi5-stable-campaign-packet -- \
  --source-revision "$source_revision" \
  --campaign-plan "$packet_dir/campaign-plan.json" \
  --artifact-set "$packet_dir/artifact-set.json" \
  --run-1-materialization "$packet_dir/run-1/materialization.json" \
  --run-2-materialization "$packet_dir/run-2/materialization.json" \
  --staging-plan "$packet_dir/staging-plan.json" \
  --requirements "$packet_dir/requirements.json" \
  --sd-envelope "$packet_dir/sd-envelope.json" \
  --nvme-envelope "$packet_dir/nvme-envelope.json" \
  --boot-filesystem "$packet_dir/sd/boot-filesystem.img" \
  --root-data "$packet_dir/sd/root-data.img" \
  --root-hash "$packet_dir/sd/root-hash.img" \
  --release-filesystem "$packet_dir/nvme/release-filesystem.img" \
  "${args[@]}" > "$packet_dir/preparation.json"
```

Require successful exit before retaining the output as a complete report. The
tool writes only stdout and diagnostics; shell redirection creates the named
report. The packet digest uses SHA-256 over the domain
`kaiba.provisioning.rpi5-stable-verifier-preparation-packet.v1alpha1`, one NUL,
and the canonical report with `packet_digest` omitted, excluding the transport
newline. This is a content binding, not a signature or approval.

## Remaining operator and physical records

The report lists outstanding source/CI provenance, board and attachment review,
signing/trust/platform review, authority configuration and public certificate
validity, Pi RTC prerequisite, capture operator and UART/power topology, capture
duration limit, explicit execution approval, and stop/recovery procedure. It
records the existing UART and auxiliary byte limits, but does not choose the
operator's capture duration or claim that any capture is complete.

Backup capture, backup readback, live attachment verification, approval,
destructive staging readiness, hardware observation, and claim closure remain
false. The retained GPT envelopes describe previously declared ranges; this
tool neither captures their recovery bytes nor authenticates their physical
provenance or freshness. All run witnesses remain outstanding.

Continue with the [first physical baseline runbook](first-physical-baseline.md)
only when its staging and execution prerequisites are independently met.
Run 2 reuses the verified baseline media, with a separate authority-unavailability
condition and capture. The first observations do not close the full 33-run,
37-claim qualification.

## Software validation

The normal Go tests exercise payload hashing, zero tails, failed reads, changed
files, special files, symlinks, hard links, and argument rejection. The separate
native Nix integration check constructs the real test campaign artifact set,
run materializations, public resolver inputs, four payloads, and canonical GPT
expectations, then invokes the CLI. It hashes complete planned partition ranges
and rejects run, payload, public-input, GPT, and recovery-record substitution:

```console
scripts/check.sh go ./internal/provisioning/campaignpacket ./cmd/kaiba-rpi5-stable-campaign-packet
scripts/check.sh contracts stable-campaign-packet stable-campaign-packet-integration
```

The integration test's initial GPT envelopes are explicitly synthetic fixture
declarations. Its success proves the packet's public input checks, not a physical
capture, staging operation, released-OS boot, or authenticated witness.
