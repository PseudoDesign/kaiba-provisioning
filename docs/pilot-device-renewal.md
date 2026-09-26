# Protected renewal client

These commands implement initial 0.2-to-0.3 and successive 0.3 pilot renewals.
They use the existing operational key and protected state directory. They do not
approve admission, configure issuer grants, activate fleet membership, renew an
expired predecessor or change hardware. Use them only with the matching fleet
renewal implementation and reviewed current records.

The source contract is the proposed 0.3 protocol at kaiba-contracts commit
`6b42c0f1a1b55570aeb1e1f03662f5ef3e0242a4`. Integration with fleet commit
`b5cf406ab79168f0b8ca586fc46380e1bbadae41` tests the first and successive renewals.
Expired-access recovery uses the separate [recovery workflow](pilot-device-recovery.md).

## Protected state and current credential

The existing 0700 directory, 0600 single-link state, nonblocking exclusive lock,
protected-volume guard and atomic write/fsync/rename/fsync rules remain in use.
Every renewal save also rechecks the storage guard. No renewal operation generates
or exports a private key. Failed writes preserve temporary files for review;
there is no automatic cleanup or state reset.

A new optional `renewal` section records the exact reviewed approval, authenticated
predecessor binding, key-possession signature, successor certificate, staged
binding, installation challenge/signature, receipt and active binding. The original
credential/configuration and enrollment proof stay intact in the same protected
record. No local workflow database or additional unencrypted credential file is
introduced. Older binaries reject this new state field; do not downgrade them
or delete the field to bypass reconciliation.

Normal `self` and `submit-diagnostic` requests use the predecessor until the local
renewal phase becomes `active`, then use the saved successor with the same private
key. Installation requests use the successor explicitly. Local activation requires
both the exact linked fleet cutover record and a successful authenticated current
`self` response using that successor. A historical active record or a CA-valid
certificate alone is insufficient.

`status` adds a public renewal summary: operation, local phase, intended credential
revision and successor digest when available. Local `active` is retained history,
not an assertion of current authorization; `self` remains the live check.

## Operator/device sequence

Every command opens the existing protected directory. An example prefix is:

```sh
kaiba-pilot-device --state /var/lib/kaiba-pilot-device
```

The exact directory and execution account remain deployment choices. Do not use
an ordinary filesystem to bypass the protected-storage requirement.

1. The operator obtains a current fleet approval for the exact successor window
   and supplies its public JSON as `approval.json`.
2. Run `--input approval.json prepare-renewal`. The client reads current fleet
   membership using its predecessor certificate, validates the approval against
   that binding and its local key/configuration, saves one key-possession signature,
   then submits it. It does not send an operator approval request.
3. The operator installs the exact reviewed issuer grant and requests issuance
   through fleet. This must fit the short key-proof window; this client does not
   extend that window or replace an abandoned operation.
4. Run `install-renewal`. It fetches the authenticated staged result, checks the
   successor key, issuer, identity, exact approved validity, serial/digest and
   linked binding, then saves the pending certificate without replacing the current
   credential.
5. In a **new client process**, run `prove-renewal-installed`. It authenticates
   using the successor, validates every installation challenge binding, saves one
   signature before sending it and verifies the returned installation receipt.
6. The operator explicitly activates fleet cutover after its current checks.
7. Run `reconcile-renewal`. It reads the saved operation using the successor and
   checks current successor access before atomically selecting it locally.
8. Run `self` and retain the existing reviewed evidence/backup process. Software
   command success alone does not complete a live pilot report.

The key-possession and installed-key challenges have different purposes. Their
signatures cover canonical JSON, using the existing P-256 key. The client checks
identity, target, storage/key generations, predecessor, approval, staged binding,
certificate digest, tenant/domain, permissions and bounded times. It never uses
caller-supplied private key material or a replacement fleet origin.

## Interruption and explicit recovery

| Local phase / interruption | Next step |
| --- | --- |
| Before a key proof is saved | Correct the read/configuration problem; no new key exists |
| `prepared`, key-proof reply missing | `retry-renewal-proof` explicitly resends only the saved signature for the same operation |
| `approved`, issuance/staging incomplete | Operator reconciles the fleet/issuer operation; this client cannot cause reissuance |
| `installed`, challenge read failed | A later `prove-renewal-installed` obtains the same durable challenge; no signature had been sent |
| `proof_submitted`, installed-proof result missing | `retry-renewal-installed` first reads fleet state, then either accepts the retained receipt or explicitly resends the exact saved signature against the same still-valid challenge |
| `verified`, fleet activation pending | Operator completes or reconciles activation, then run `reconcile-renewal` |
| Fleet cut over but local save/result was lost | `reconcile-renewal` uses the pending successor; it does not require the now-superseded predecessor for this read |
| Storage guard fails, temporary file remains, or record differs | Preserve state for review; do not delete history or create a new operation |

Ordinary proof commands do not silently repeat an ambiguous submission.
Reconciliation never creates a new signature. Changed approvals/challenges,
expired challenges, denied access and conflicting results fail closed. No expired
TLS bypass or automatic re-enrollment is provided. A fleet outage after server
cutover can temporarily leave ordinary requests using the denied predecessor;
the pending successor and its history remain available for later reconciliation.

## Verification

Go mTLS tests exercise missing replies, exact-signature reuse, storage loss,
process restart, unchanged key/predecessor bytes and refusal to select a successor
from historical records without current access. Native cross-repository tests use
these commands in fresh processes with real fleet/issuer services, durable
PostgreSQL and generated synthetic credentials. The fixture substitutes only the
protected-filesystem observation; the packaged production client still rejects
ordinary test storage. Tests do not claim real LUKS, firmware or live renewal
qualification. No device deployment or deadline change is included in this change.


## Subsequent operations and retained history

After the current renewal is locally `active`, `prepare-renewal` can accept a new
operation bound to that exact active binding and certificate. It performs a fresh
current self read, validates the new approval and saves the completed operation
in `renewal_history` together with the new prepared proof in one atomic write.
A failed read or storage guard leaves the previous state unchanged. A lost proof
reply leaves both the completed history and new proof available after restart.

While the new operation is pending, ordinary requests use the last archived
active certificate. Only authenticated cutover plus current successor access
selects the new certificate. Neither preparation nor installation replaces the
original enrollment fields. Approval references follow the current predecessor;
key and storage generations remain unchanged as credential revision advances.

Every load validates the complete ordered chain from the original enrollment,
including signatures, certificates, staged bindings, receipts and active records.
Missing, reordered, duplicated or incomplete entries fail closed. Archived
operation IDs cannot be reused; commands address only the current operation.
Original single-renewal state loads without migration; older binaries reject
state containing `renewal_history`, so do not downgrade or remove fields.

At most 127 completed operations can precede the current operation. The existing
1 MiB state-file limit also applies and can be reached earlier. No automatic
trimming, compaction or history deletion is provided; a capacity failure preserves
state for review. Expired historical records remain loadable, but network use
continues to enforce the selected credential's current validity. Loading history
is not expired-key recovery or permission to renew a revoked identity.

Expired access uses the separate [protected recovery proof relay](pilot-device-recovery.md).
Normal renewal never accepts an expired credential or bypasses a pending recovery.
