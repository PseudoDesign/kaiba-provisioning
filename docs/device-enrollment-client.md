# Development device enrollment client

`kaiba-device-enrollment` generates and retains a device's P-256 management key,
answers bound enrollment challenges, installs the issued certificate, and
proves the installed key after restart. It targets the isolated
[fleet rehearsal](https://github.com/PseudoDesign/kaiba-fleet/pull/1). It does not
change fleet eligibility, activate a credential, or implement the production
CA, replacement, renewal or retirement workflows.

This is software preparation for a single-device readiness campaign. No Pi
execution or protected-storage qualification is claimed by the client tests.
The [admission policy](fleet-admission-policy.md) and
[enrollment handoff](enrollment-handoff.md) continue to govern enrollment.

## Ownership and trust

This repository owns the device executable; `kaiba-fleet` owns the enrollment
service, inventory and authorization decision. `kaiba-contracts` owns the shared
record definitions. The client's configuration and private state format are
local implementation details, not additions to those shared contracts.

The station obtains an enrollment challenge using its authenticated fleet
connection and relays it over its authenticated connection to the target. The
station also supplies the pinned public configuration, issued certificate and,
when necessary, an authenticated enrollment status read. The existing station
UI remains read-only; automatic orchestration of this relay is future work.

The client binds proofs to the provisioning record, assigned device/instance,
storage generation, management slot, key generation, SPKI, certificate profile,
purpose, audience and nonce. It accepts only the rehearsal audience and
certificate profile, with `mode: development`. Certificate installation checks
the key, issuer, device URI, client-auth usage and validity. Installed-key proof
uses HTTPS with explicit trust roots, mTLS, bounded responses and timeouts, and
no redirects or proxy discovery. The returned verifier receipt must match the
challenge and installed credential tuple.

Fleet inventory remains authoritative. A local `verified` result records key
proof, not active membership. `check-access` makes a new request every time;
it does not cache a successful authorization. The client neither independently
audits a `DeviceBinding` nor authorizes from its contents.

## Configuration and commands

Build natively with `nix build .#kaiba-device-enrollment`. The executable is
standalone Go software; changing it does not require signing a boot image. The
native ARM CI lane exports the executable and a source/build/digest manifest.
That export is software provenance, not permission to execute it on a device.

Create an empty, owner-only (`0700`) state directory on the chosen protected
filesystem. The client does not create or format that filesystem. Its public
configuration JSON has these required fields:

| Field | Value |
| --- | --- |
| `schema_version` | `kaiba.device-enrollment-client/v1alpha1` |
| `mode` | `development` |
| `fleet_url` | HTTPS origin of the rehearsal service; no credentials, path, query or fragment |
| `server_ca_pem` | Exactly one explicit server trust-root certificate |
| `issuer_ca_pem`, `issuer_id` | Exactly one credential issuer certificate and its configured identifier |
| `authority_id`, `transaction_id`, `target` | Exact station-selected rehearsal source and target |
| `provisioning_ref` | Exact `record_id`, integer `revision` and `sha256:` digest |
| `restart_requirement` | `boot` for the device campaign; `process` only for software rehearsal |
| `protected_volume_uuid` | Required for `boot`; exact expected LUKS2 volume UUID. A process-only rehearsal may omit it. |

Each command emits public JSON on success and a bounded category on failure:

```sh
kaiba-device-enrollment initialize --state "$credential_directory" --input config.json
kaiba-device-enrollment bootstrap --state "$credential_directory" --input challenge.json
kaiba-device-enrollment install --state "$credential_directory" --input certificate.pem
kaiba-device-enrollment status --state "$credential_directory"
# After the separately arranged restart:
kaiba-device-enrollment prove-installed --state "$credential_directory"
kaiba-device-enrollment check-access --state "$credential_directory"
```

The station sends the bootstrap signature to the fleet service and relays its
certificate back before `install`. There is no generic signing, key import or
key export command. `initialize` with identical configuration returns the same
public key; it does not rotate an existing key.

The boot requirement compares the kernel boot ID at installation with the one
at proof. A changed boot ID is evidence of a new kernel session, not a cold
power cycle. Process-only testing reports no boot change. The client always
reports `production_enrollment: false` and `hardware_qualified: false`.

The [protected-storage helper](enrollment-storage-development.md) provides a
bounded development filesystem. When `protected_volume_uuid` is configured,
initialization and every state open verify the pinned directory's actual Linux
mount: writable ext4 with `nosuid,nodev,noexec`, a matching LUKS2 device-mapper
UUID, and no swap. Missing or substituted storage is rejected before key
generation or protocol activity. This check does not qualify hardware custody,
recovery images or privileged software access to the key.

## Interrupted operations

The key and progress share an atomically replaced, fsynced private state file.
A directory lock excludes concurrent clients. Symlinks, hard-linked files,
unsafe ownership/permissions and incomplete writes stop execution without
generating a replacement key. Preserve a failed state directory for review.

The client persists the installed-key challenge and signature before submitting
it. If the reply is lost or invalid, the next `prove-installed` stops without
sending another request. The station retrieves the current enrollment status:

- If the same tuple is already verified/active, relay that response to
  `reconcile --state ... --input enrollment.json`. No request or new signature
  is made.
- If the exact same unexpired challenge is still staged, explicitly invoke
  `retry-installed --state ... --input enrollment.json`. It sends the saved
  proof once, without another challenge or signature. A raced/lost response
  requires another status read.
- An expired or replaced challenge, denied tuple, inconsistent receipt or
  incomplete local state requires operator reconciliation. Automatic abandonment
  and replacement of that enrollment are not implemented in this slice.

Reconciliation input is trusted only when the station obtained it over its
authenticated fleet connection. A file copied from an untrusted source is not
an authenticated status read. Local state is not an independent audit record.

## Verification and remaining device work

Focused Go tests cover private state handling, restart enforcement, challenge
and certificate binding, lost replies, explicit saved-proof retries, current
access checks and transport failures. Native packaging is checked on x86_64
and ARM64. The fleet repository owns the real-service process rehearsal using
PostgreSQL, disposable PKI and synthetic eligible records. A process restart in
that rehearsal does not qualify a device reboot or an encrypted mount.

Before the device campaign, select and verify its encrypted state mount,
execution identity, executable provenance and temporary fleet configuration.
The software key is readable by its owning process and privileged software;
this client is not a secure element. It disables its own core dumps, but
filesystem encryption, swap, recovery images, backup/export paths and the
permitted-image boundary still require qualification. Actual device execution,
key creation, persistent writes and restart require the campaign's bounded
execution authority. The production-root eligibility decision and FA-01–FA-08
remain unresolved by a passing software rehearsal.

The selected next milestone is [Ace and Mako pilot enrollment](pilot-enrollment.md).
It needs explicit pilot client/authority support and a versioned adoption handoff.
The existing development mode, rehearsal audience and certificate profile cannot
be reused to label either real host enrolled in that pilot. Its acceptance tests
must distinguish process restart, physical cold boot and full qualification.
