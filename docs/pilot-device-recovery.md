# Protected pilot recovery proof

The planned expired-access recovery path now has a device-side proof relay.
It does **not** issue or install a successor certificate, activate a binding,
renew access, or establish production qualification. Ace's expired access is
unchanged until a separately reviewed live recovery completes.

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
requires reconciliation. A saved recovery blocks a new normal-renewal operation;
there is no reset or replacement-operation escape hatch. Status reports
`recovery.phase=proof_prepared`, which does not imply server acceptance.

The original key, certificate, membership and renewal history remain intact.
Current software supports initial 0.2 and renewed 0.3 predecessors; recovery
cutover and subsequent recovery-history support remain planned. The deployable
binary still requires protected storage. Software fixtures replace only storage
observation and make no hardware qualification claim.
