# Guided station campaigns

The existing live station has a separate **development campaign** mode for a
touchscreen browser. It shows the configured device, current step, last recorded
result, any required input and the permitted next action. Diagnostic identifiers
and attempt history are available through **Export report**. The browser does
not own progress or choose executable paths.

The controller, authenticated station relay, durable journal and touchscreen
view are implemented. The native software check uses the packaged enrollment
client with disposable process-mode state. A reviewed Pi execution packet,
target-specific wrappers and isolated development fleet eligibility remain to
be integrated before this view can conduct the real-device enrollment campaign.
No physical result or fleet admission follows from the software check.

## Execution and authority

`kaiba-provision-campaign` owns one campaign journal and one immutable plan. The
plan binds a campaign, station/lane, target reference, profile label, expiry and
execution-packet digest. Every step pins the Nix-store path and SHA-256 of one
wrapper, a timeout, reviewed result messages, and optional fixed input choices.
There is no browser API for commands, arguments, environment variables, device
paths, credentials, profiles or arbitrary text.

The plan is an orchestration description, **not execution authorization**. Each
wrapper must retain the packet's target/identity checks, approvals, freshness,
claims/fencing where applicable, durable one-use intent, postcondition checks
and evidence handling. It must reject a request outside its reviewed scope. The
controller runs wrappers as its service account without adding privileges;
the browser-facing station needs only its mTLS credentials. A physical-action
acknowledgment is operator input, not verified physical evidence or independent
approval. PINs and secrets never belong in a campaign plan or browser form.

The controller verifies the pinned program's bytes and executes its open file
descriptor. Programs receive only a closed JSON request on stdin and an empty
command-search path. Wrappers must use fixed dependency paths. Normal completion
requires one bounded JSON result on stdout and empty stderr. Raw process output
is discarded; wrappers are responsible for retaining any permitted private
diagnostics in their own evidence store. The exported references are hashes.

This assumes a trusted controller host and immutable Nix store. The journal
protects restart continuity, not against an administrator replacing the host's
state or binaries. Protect its persistent parent directory and backups under
the station-host policy. Do not copy a live campaign journal to create another
execution authority.

## Start the controller and station

Build the two native packages:

```console
nix build .#kaiba-provision-campaign .#kaiba-provision-station --no-link
```

Prepare the public reviewed plan as a Nix-store file. Keep credentials outside
Git and the Nix store. Give the controller an existing persistent directory,
owned by its service account with mode `0700`. Journal files use mode `0600`.
The directory must initially be empty; one controller holds its lifetime lock.

These examples contain placeholder paths and identities, not an executable
hardware packet. Obtain the exact plan binding with the read-only command:

```console
kaiba-provision-campaign \
  --plan /nix/store/REVIEWED-campaign-plan.json --describe-plan
```

Use its `plan_digest` in the station configuration. It hashes the decoded,
validated plan's JSON representation, not the original file's whitespace.

```console
kaiba-provision-campaign \
  --plan /nix/store/REVIEWED-campaign-plan.json \
  --state /var/lib/kaiba-campaign/selected-device \
  --listen 127.0.0.1:8446 \
  --tls-cert /run/credentials/campaign/server.crt \
  --tls-key /run/credentials/campaign/server.key \
  --client-ca /run/credentials/campaign/station-ca.crt

kaiba-provision-station \
  --listen 127.0.0.1:8081 --station-id station-1 --lane-id lane-1 \
  --campaign-url https://127.0.0.1:8446 \
  --campaign-id reviewed-campaign-id \
  --campaign-plan-digest sha256:REPLACE_WITH_DESCRIBED_PLAN_DIGEST \
  --campaign-server-ca /run/credentials/station/campaign-ca.crt \
  --tls-cert /run/credentials/station/station.crt \
  --tls-key /run/credentials/station/station.key
```

Run these as separate supervised services. Preserve their configuration and the
controller's journal across restarts. The server certificate must authenticate
the configured origin. Both services validate the canonical client URI
`spiffe://kaiba.network/station/station-1/lane/lane-1`; the controller independently
requires the plan's station/lane on every request. It does not accept a browser
certificate or a claimed identity in JSON. Trust roots are explicit, redirects
are rejected, and reads and requests are bounded.

Campaign inputs are all-or-none and cannot be mixed with observer/control
configuration. The existing observer remains read-only; `--enable-mutations`
remains rejected. The foundation and public simulation retain their contracts.
Open `http://127.0.0.1:8081/` in the local browser. The
[display-session policy](provisioning-station-kiosk.md#local-display-session)
still applies; a kiosk switch alone does not restrict the operator account.
This change does not install a desktop or add a deployment platform.

## Progress and recovery

**Begin campaign** records intent before launching the first wrapper. Successful
steps advance automatically until input is needed. **Pause after this step**
allows the active operation to finish, then pauses before the next. It is not
an emergency stop. Input choices and action labels come from the reviewed plan.

The browser polls two seconds after each completed request, disables actions
while a request is pending or state is stale, and never retries an action
automatically. Request IDs and expected revisions prevent duplicate execution.
Losing a reply triggers a status read. A browser reload restores progress from
the controller. A station restart replaces its session capability; the browser
reacquires it after rejection and reads progress before another operator action.

The controller records each intent and result with atomic replacement and
filesystem sync. An interrupted in-flight operation becomes
`reconciliation_required` after restart. **Check existing result** is offered
only when the packet supplies a separately pinned, read-only reconciler. That
wrapper receives the original execution request ID and input with
`reconcile: true`; it must inspect the existing operation and never retry its
mutation. A confirmed success advances normally. An uncertain, blocked or
quarantined result cannot be bypassed from the screen.

If the packet expires, further execution is disabled. If the journal cannot be
verified or written, execution stops. Preserve a missing/corrupt journal,
unfinished temporary or uncertain executor result for review. Do not delete,
edit, reset or recreate the journal to resume an operation. There is no reset,
force-complete or generic retry action.

## Contracts and export

The controller's mTLS routes are `GET /api/v1/campaign/state`,
`POST /api/v1/campaign/actions`, and `GET /api/v1/campaign/report`. The loopback
station relays them through `/api/v1/state`, `/api/v1/actions` and
`/api/v1/report`. Actions require the current session token and exact same
origin; exports also require the token. This capability limits browser requests
to the local station session; it is not an operator identity or packet approval.

The closed Go types in
[`guidedcampaign/types.go`](../internal/provisioning/guidedcampaign/types.go)
define the versioned plan, execution, state and report contracts. Unknown JSON
fields and duplicate members are rejected. Result codes select reviewed text;
they cannot inject logs into the screen. The report contains plan/packet
bindings, timestamps, bounded inputs, attempt outcomes, diagnostic references
and FA-01–FA-08 as `not_evaluated`. It is a local orchestration record, not the
provisioning evidence contract accepted by the fleet service or an independent
audit. Review any real-device report before publishing it.

`campaign_complete` means the configured development steps finished. Both
`production_enrollment` and `hardware_qualified` remain false. Provisioning
evidence and fleet membership continue to follow the
[enrollment handoff](enrollment-handoff.md) and
[admission policy](fleet-admission-policy.md).

## Repeatable software demonstration

```console
nix develop --command scripts/check.sh contracts guided-station-campaign
nix develop --command scripts/check.sh ui
```

The native check runs the packaged controller and station with disposable mTLS
credentials, plus the real packaged device client in process mode. It checks
automatic progression, duplicate input, required input, browser-session renewal,
station/controller restart, authority outage, wrong-station denial and report
export. Fixed synthetic wrappers exercise digest mismatch, stderr, overflow,
invalid results, timeout and process failure. No fixture accesses a Pi, firmware
mailbox, signer, deployed fleet service or physical storage.

The output's `report.json` records these software scenarios. The client
initializes a disposable identity and reopens it in fresh processes; this does
not test encrypted cold reopen, enrollment issuance, activation or hardware
admission. Go tests separately cover reconciliation, quarantine, journal failure
and concurrent actions; JavaScript tests cover rendering and browser recovery.
