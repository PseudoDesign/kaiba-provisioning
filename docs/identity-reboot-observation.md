# Read-only identity observations around a warm reboot

The [reboot observer](../scripts/offline-qualification/observe_reboot.py)
collects bounded metadata from Ace and compares two retained observations.
It performs no reboot, service activation, initialization, or remote file write.
The operator controls any reboot separately through the reviewed host procedure.
The tool supplies software acceptance evidence, not physical boot attestation
or offline qualification.

This observer targets the installed persistent identity pilot described in
the [host rollout](https://github.com/PseudoDesign/nix-pseudo-design/blob/codex/spiffe-persistent-pilot/docs/ace-identity-pilot.md).
That pilot uses `pilot.kaiba.pseudo.design`, an exact-unit identity probe,
and a local SPIRE authority. Its initial
[acceptance receipt](https://github.com/PseudoDesign/nix-pseudo-design/blob/codex/spiffe-persistent-pilot/docs/observations/2026-09-29-ace-identity-pilot.json)
records persistent generation 10 and does not claim a physical reboot.
The reboot observer is implemented with synthetic tests; no native reboot
result is established merely by adding this tool.

## Collection boundary

Collection uses the [inventory tool's strict SSH transport](offline-qualification-inventory.md)
to the already configured Ace destination. It never accepts an unknown key,
updates known-hosts files, forwards credentials, or reuses an SSH multiplexed
connection. An optional `--known-hosts` names an existing private trust file.
Only the fixed read-only script is sent to `sudo -n sh -s`; caller-supplied
paths and comparison expectations never enter the remote shell.

The fixed observations are:

- Current, persistent and booted NixOS closures; persistent generation; boot ID,
  uptime, UTC and reported NTP synchronization.
- SHA-256 of the public persisted trust bundle. No authority/agent key,
  database, bootstrap manifest, or SPIRE admin-node record is read.
- The public probe output, completed systemd invocation and monotonic start/end
  timestamps, with its output-file metadata. Unit and file metadata are read
  before and after the output to reject a racing timer update.
- The existing pilot client's public `status` response. Its full canonical JSON
  digest is compared; public-key bodies, enrollment IDs and nested status fields
  are omitted from the projection. The collector does not read `state.json`;
  it checks only its ownership, permissions and link count.
- Existing pilot directory and protected mount metadata, absence of the
  consumed runtime grant, failed-unit presence, and activity of Hydra server,
  evaluator, queue runner, PostgreSQL, SSH, SPIRE server/agent and the probe timer.

The installed public-status client necessarily accesses its own credential
state as its existing service user to construct public status. It exports no
private key or certificate body. The observer never calls proof, enrollment,
renewal, mutation, or SPIRE admin APIs.

Each field is limited to 16 KiB, the transcript to 256 KiB and the SSH session
to 45 seconds. A complete capture is retained in a new local mode-0700
directory: `raw.txt`, `observation.json`, and the exact observer and transport
helper sources, each mode 0600. Choose a directory outside the checkout and
Nix store. Keep these private; publish only a reviewed sanitized receipt.

## Before and after collection

Review the currently deployed closure, generation, service load and recovery
access first. Preserve the existing boot/unlock/storage profile and enrolled
pilot. A clean service observation does not prove that no work is in flight,
so it is not permission to interrupt Hydra or reboot the host.

From the provisioning checkout, collect the baseline without changing Ace:

```sh
python3 -B scripts/offline-qualification/observe_reboot.py collect \
  --known-hosts /absolute/private/known_hosts \
  --output-dir /tmp/kaiba-ace-reboot-before-session
```

After a separately authorized, supervised reboot and successful SSH return,
use the identical observer source and trust anchor:

```sh
python3 -B scripts/offline-qualification/observe_reboot.py collect \
  --known-hosts /absolute/private/known_hosts \
  --output-dir /tmp/kaiba-ace-reboot-after-session
```

Exit 0 means the capture is complete and ready for comparison; exit 2 retains
complete evidence with readiness failures; exit 1 means required evidence was
missing, malformed or inconsistent. Output does not print host status fields.
For exit 2, inspect only `readiness_issues` in the private projection first.
Missing commands or failed protected reads cannot become successful checks.

The existing probe timer may take up to five minutes after startup. The
operator can wait for it or explicitly start the installed probe through the
host's normal administration path; the collector itself never starts it.
A persisted pre-reboot output file is insufficient: the observer requires a
successful completed invocation in the current boot, a matching recent output
mtime, and an SVID with more than 30 seconds remaining. The last completed
invocation must be at most seven minutes old. Systemd monotonic timestamps and
`/proc/uptime` are used for ordinary boot observation, not suspend/resume
qualification. A concurrent probe update is rejected; collect again into a
new directory if that happens.

## Compare against the intended profile

The initial pilot uses these explicit expectations. Review and update them
for a deliberate future deployment; never derive the expected profile from
the post-reboot observation merely to make it pass.

```sh
python3 -B scripts/offline-qualification/observe_reboot.py compare \
  --before /tmp/kaiba-ace-reboot-before-session \
  --after /tmp/kaiba-ace-reboot-after-session \
  --expected-system /nix/store/ylpbjk8jzr195l7yn7f713sgjfimicbs-nixos-system-ace-26.05.20260807.ee48b14 \
  --expected-generation 10 \
  --expected-spiffe-id spiffe://pilot.kaiba.pseudo.design/device/ace/instance/ace-pilot-20260929/workload/identity-probe \
  --output-dir /tmp/kaiba-ace-reboot-comparison-session
```

Comparison regenerates both projections from retained transcripts and requires
the same collector/helper version. It rejects altered reports or mismatched
source bytes. A pass requires a changed boot ID and probe invocation, the
expected current/persistent system and generation on both sides, the expected
booted system afterward, identical expected SPIFFE URI, trust-bundle digest
and complete public enrollment-status digest, plus both readiness checks.
The before snapshot may legitimately have an older booted-system link after
a prior persistent switch; it is the after snapshot that must boot the intended
profile. Certificate serial and process ID need not remain unchanged.

The default station observation interval is at most 900 seconds, configurable
with `--max-interval-seconds` up to 1800. The post-reboot uptime must place the
new boot within that interval, with a 30-second capture margin. Each target UTC
must be within 30 seconds of its station capture. These bounds support a short
supervised online reboot; they do not qualify an untrusted clock. Legitimate
bundle rotation or a public enrollment-status change makes this exact
comparison fail and needs explicit review, not a silent exception.

The comparison writes a new private `comparison.json`. Exit 0 means all checks
passed; exit 2 retains a failed comparison; exit 1 means evidence could not be
validated. Digests identify retained bytes, not a compromised target's truth.
`warm_reboot_observation_passed` is a consistency result around the operator's
reported reboot, not independent proof of the reboot action or physical power
state. An independent operator record must describe the action and outcome.

## Gates that stay open

Every report keeps physical cold boot, authenticated boot-chain, hardware,
offline rollback and clock-continuity qualification unproven. Fleet admission
remains unevaluated and DNS publication is not tested. A changed boot ID and
healthy services do not prove power-loss behavior, offline startup, TPM/native
monotonic state, old-image rejection, recovery safety, or non-exportable keys.
The pilot's one-hour agent identity and requirement for synchronized time still
bound downtime. No grant is recreated to rescue an expired agent.

Run the software checks with:

```sh
python3 -B -m unittest discover -s tests/offline-qualification -p 'test_*.py' -v
scripts/check.sh contracts offline-qualification-inventory
```

The tests cover stale preboot output, current-boot timestamps, wrong generation
or booted closure, unchanged boot ID, expiry and clock skew, service failures,
bundle/enrollment changes, transcript races, source/projection tampering, and
private evidence retention. They do not reboot a host.
