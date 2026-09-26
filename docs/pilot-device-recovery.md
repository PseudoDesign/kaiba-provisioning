# Protected pilot recovery and installation

The expired-access recovery path supports a management-relayed key proof,
protected successor installation and installed-key proof after a client-process
restart. Fleet activation is a separate operator action. These software paths do
not establish production qualification or change Ace until a reviewed live
recovery completes.

The management operator uses current management credentials to request the
fleet recovery approval. Device authentication with an expired certificate is
never used. The operator constructs this public packet from the authenticated
current predecessor and approval responses:

```json
{
  "schema_version": "kaiba.pilot-recovery-packet/v1alpha1",
  "predecessor": "<complete current PilotDeviceBinding object>",
  "approval": "<complete awaiting_proof recovery response object>"
}
```

The placeholders above stand for JSON objects. Compute the SHA-256 of the
RFC 8785 canonical packet and independently bind it into the reviewed execution
packet. Transfer the public JSON and run the following through authenticated
management access to the device, as its existing protected-client account:

```sh
kaiba-pilot-device --state /existing/protected/state \
  --input /reviewed/recovery-packet.json \
  --recovery-digest sha256:<reviewed-canonical-packet-digest> prepare-recovery
```

The digest is a trusted operator input, **not an authority signature**. Do not
calculate it from an untrusted packet and treat the result as authorization.
Review must bind the authority/tenant/domain, approver, review reference, exact
predecessor, fresh record selections, operation and validity window. The device
cannot independently discover revocation or verify the current selection while
offline; the management-authenticated server rechecks eligibility on proof
submission. The local client additionally checks the retained key, certificate,
identity, storage generation, scope, revisions, references and challenge window.
It checks the old certificate at issuance solely to compare historical identity,
never to authorize a network connection.

The client stores the full packet, digest and one signature in its existing
private atomic state before returning `{"signature":"..."}`. It makes no
network calls. Relay that response using current management credentials to
`POST /api/v1/pilot/enrollments/{id}/recoveries/{operation}/proof`.
An exact command repeat, including after restart or expiry, returns the saved
signature without signing again. A different packet or pending normal renewal
requires reconciliation. An unfinished recovery blocks a new normal-renewal operation;
there is no reset or replacement-operation escape hatch. Status reports
`recovery.phase=proof_prepared`, which does not imply server acceptance.

The original key, certificate, membership and renewal history remain intact.
Current software supports initial 0.2 and normally renewed 0.3 predecessors.
After recovery is active and freshly confirmed, normal renewal may use the
recovered 0.4 binding. The saved recovery and any earlier renewals remain intact.
A second expired-access recovery on this client remains unsupported and requires
review; it cannot overwrite the retained recovery packet. The deployable
binary still requires protected storage. Software fixtures replace only storage
observation and make no hardware qualification claim.


## Install, restart, prove and reconcile

After fleet verifies the relayed proof, the management operator calls the exact
recovery operation's `issue` route and transfers its complete public installation
response. Run as the existing protected-client account:

```sh
kaiba-pilot-device --state /existing/protected/state \
  --input /reviewed/recovery-installation.json install-recovery
# A separate invocation establishes the required new client process.
kaiba-pilot-device --state /existing/protected/state prove-recovery-installed
```

Installation compares the full saved authorization, predecessor and key proof,
then validates the successor certificate, same key/identity, fresh record
references and bounded validity window. The original credential remains intact;
the successor is saved separately. Installing twice cannot replace the tuple.
The installed-key challenge uses the successor certificate for mTLS and a
recovery-specific proof purpose. The client persists one signature before sending
it. A failed or lost response leaves `proof_submitted`; another ordinary proof
command refuses to sign or submit again.

After reviewing an interrupted attempt, `retry-recovery-installed` first reads
the authenticated retained installation. It retrieves an already verified receipt
or explicitly resubmits the same saved proof. `reconcile-recovery` only reads the
installation and, after operator activation, the current authenticated self view.
A historical activation response alone never switches ordinary access: the fresh
self view must authorize the exact recovered binding. Once confirmed, ordinary
requests use the successor; old credentials and history remain available for
reconciliation. Revocation or dependency denial leaves access denied.

Disposable tests cover protected-state failure, process restart, lost replies,
explicit same-proof reconciliation, tampered receipts, denied current access and
unchanged original key/certificate. Fleet integration adds persistence-fault
rollback and shared-contract checks. No test result is a live recovery receipt.


## Normal renewal after recovery

Use the existing `prepare-renewal`, installation, fresh-process proof and
reconciliation commands with a fresh operator-approved normal renewal. The
predecessor must still be current and unexpired. Recovery grants never authorize
normal renewal, and normal renewal cannot bypass an unfinished recovery.

When starting the first subsequent renewal, protected state records the boundary
between renewals completed before and after recovery. State loading validates
the entire ordered chain, including the original recovery packet, installation
receipt and active binding. Missing history or a changed boundary fails closed.
Pending renewal continues to use the recovered credential; only confirmed
activation selects its successor. Later normal renewals preserve that same
history. `reconcile-recovery` refuses to alter a state that has entered this later
renewal chain; use `reconcile-renewal` for the current operation.
