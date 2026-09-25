# Pilot device credential client

`kaiba-pilot-device` implements the existing-device pilot proof profile
`kaiba.pilot-key-proof/v1alpha1`. It is separate from the development enrollment
client: no fabricated provisioning transaction, rehearsal audience or qualified
fleet credential is accepted. The matching lifecycle service is in
[kaiba-fleet](https://github.com/PseudoDesign/kaiba-fleet). Real deployment and
Ace/Mako enrollment still require reviewed per-device records, storage and issuer
configuration; merging software creates no operational key on either device.

## Storage and configuration

The caller creates a private 0700 directory owned by the client account. The
client pins that directory inode, refuses symlinks and unexpected files, requires
0600 single-link state files, and uses a process lock and fsync/atomic rename.
An interrupted temporary save requires reconciliation instead of silently
creating another key. Each successful initialization retains one P-256 key;
unchanged configuration reopens it and changed configuration is rejected.

The deployable executable has no storage bypass. Before creating a key or using a stored
key it requires writable ext4 mounted `nosuid,nodev,noexec`, no active swap, and
the configured LUKS2 UUID. It supports a direct mapping or a bounded,
single-parent LVM chain above that mapping. Mixed backing devices, cycles,
unknown mapper types, missing metadata and chains beyond eight mappings fail.
All observations are read-only kernel metadata; the client opens no raw device.
A separately reviewed bind mount can supply the credential directory's mount
flags while preserving applications and existing filesystems. This code does
not create that mount, modify LUKS, or establish hardware key custody.

The private JSON configuration contains:

| Field | Meaning |
| --- | --- |
| `schema_version` | `kaiba.pilot-device-client/v1alpha1` |
| `fleet_url` | Exact HTTPS origin; redirects and ambient trust are disabled |
| `server_ca_pem`, `issuer_ca_pem` | Explicit fleet transport and operational certificate trust |
| `protected_volume_uuid` | Required observed LUKS2 volume UUID |
| `binding` | Exact `target`, `adoption_ref`, `policy_ref`, `admission_ref`, `audience`, `certificate_profile`, `issuer_id` |

`certificate_profile` must be `rpi5-existing-luks-pilot-v1`. The target includes
asset label and identity/storage EvidenceRefs; each record reference includes
ID, revision and digest. Configuration comes from the reviewed station/authority
handoff, not a browser-selected hostname or device-provided authority.

## CLI and proof sequence

Flags precede the command. These paths illustrate the interface; they are not an
authorization to initialize a real device:

```sh
kaiba-pilot-device --state /private/credentials --config /private/pilot.json init
kaiba-pilot-device --state /private/credentials status
kaiba-pilot-device --state /private/credentials --input /private/challenge.json bootstrap
kaiba-pilot-device --state /private/credentials --input /private/issued.crt install
kaiba-pilot-device --state /private/credentials prove-installed
kaiba-pilot-device --state /private/credentials self
```

The station submits the public SPKI with the exact handoff references to fleet,
relays its bootstrap challenge over the authenticated target connection, submits
the resulting proof and installs the returned certificate. Bootstrap signing is
restricted to the configured context, a fresh challenge and the local key. A
repeated identical challenge returns the saved signature; a substituted challenge
is rejected. No command exposes a private key or provides generic signing.

Certificates must bind that key, the pinned issuer and fleet-assigned pilot URI,
with only client-auth/digital-signature use. The client records its process
identity at installation. Installed-key proof requires a different process and
binds the exact certificate DER digest as well as the complete bootstrap tuple.
This establishes client-process restart, not cold boot or hardware attestation.

The pending proof is saved before transmission. An ambiguous result stops in
`proof_submitted`; another `prove-installed` cannot automatically sign or retry.
The station obtains the authoritative enrollment snapshot using its authorized
operator read. Use `--input snapshot.json reconcile` for committed verification,
or `--input snapshot.json retry-installed` to send only the existing signature
for that same still-pending, unexpired challenge. Neither generates another key
or challenge. A lost challenge response can be recovered by repeating
`prove-installed`: the server returns the identical unexpired pending challenge.
Expired challenges stop for review; this first pilot implementation has no
challenge reset, rekey or quarantine-recovery shortcut.

`self` always queries current fleet authority. Local `verified` means the key
proof was recorded; it is not cached membership or authorization. Fleet performs
activation separately after checking the current sources and verifier receipt.

## Tests and limits

Focused tests cover storage refusal before key creation, LVM backing validation,
private-file permissions, persistent keys, same-process rejection, substituted
and rehearsal challenges, and lost-proof reconciliation without another network
request or signature. The fleet native `pilot-lifecycle` check runs two client
process sequences, the actual authority/services and a durable test issuer with
disposable PKI. It separately verifies that the deployable client refuses normal
temporary storage. A test-only executable substitutes the storage observation
for the software flow; it is not exported as a deployment package. Its result
cannot qualify encrypted storage, process isolation or hardware protection.

All software results remain synthetic. Real issuer key custody, per-device
custody/workload reviews, protected-directory deployment, actual process-restart
proofs and retained real membership reports remain required before pilot use.
Accepted FA gaps remain gaps; `full_qualification` stays false.

## Request diagnostics

Authority request failures now preserve a bounded classification. The CLI exits
nonzero, leaves stdout empty, and writes one JSON object to stderr:

```json
{"schema_version":"kaiba.pilot-device-error/v1alpha1","error":"http_status","http_status":403,"reconciliation_required":true}
```

Kinds are `http_status`, `transport`, `timeout`, `canceled`, `tls_verification`,
`redirect`, and `invalid_response`. HTTP status is included when available.
Response bodies, URLs, certificates and underlying transport error strings are
excluded. A 403 establishes rejection of that request, not whether its cause was
membership, policy, or a dependency which the service maps to denial. Local
input/storage/binding failures retain their existing error behavior.

The Go error still matches `ErrReconcile` through `errors.Is`. Request failure
does not prove that a write was uncommitted. Installed-proof failures still
retain the saved proof and require authoritative reconciliation; diagnostics do
not authorize automatic retries or a new proof.

## Submit a diagnostic reference

The `submit-diagnostic` command sends a reference with the existing verified
pilot credential. It neither uploads diagnostic contents nor fetches the URI.
The fleet independently checks current membership and policy.

```json
{"reference":{"uri":"urn:example:diagnostic:001","digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111"}}
```

```sh
kaiba-pilot-device --state /var/lib/kaiba-pilot-device \
  --input reference.json --idempotency-key diagnostic-001 submit-diagnostic
```

Input is limited to 4096 bytes, URI to 2048 bytes, and the digest must be a
lowercase SHA-256 reference. The explicit idempotency key is 1–128 ASCII letters,
numbers, dots, underscores, colons or hyphens, starting with a letter or number.
The URI must be absolute. Treat reference metadata as disclosed to the fleet;
do not put credentials or secrets in it.

Retain the exact input file and key outside the credential state. Following an
ambiguous result, an operator can explicitly resend the same reference and key;
the server's existing idempotency rule prevents another logical submission.
Changed content under that key is rejected. There is no automatic resend,
new key, local credential-state mutation, or caller-selected device identity.
A successful receipt must name this enrollment and match the digest of the
canonical request. Receipt validation failure remains ambiguous and must not
be worked around by choosing a fresh idempotency key.

Synthetic mTLS tests cover status classifications, lost replies, input bounds,
receipt substitution and unchanged credential state. Live diagnostic submission
and deployment of this client remain separate execution steps; these software
tests do not close those real-device evidence conditions.
