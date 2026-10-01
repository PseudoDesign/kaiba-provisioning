# Explicit pilot trust continuation

`kaiba-pilot-device continue-trust` is a local, owner-reviewed operation for
continuing the embedded transport and issuer trust before their certificates
expire. It is not exposed by the renewal worker. It cannot replace a key,
change a device identity or recover expired or revoked membership.

Supply `--input` with the public `kaiba.pilot-device-trust-continuation/v1alpha1`
packet and `--trust-digest` with its independently reviewed canonical SHA-256.
The packet names the exact operation, owner evidence, enrollment, logical identity,
SPKI, current certificate digest, old issuer/server CA DER digests and successor
CA certificates. Its `valid_from`/`expires_at` approval window is at most twelve
hours. An uncertain system clock, unfinished renewal/recovery, unavailable current
membership or changed credential blocks application.

A successor CA must retain the exact signed subject, public key, algorithm and
constraints. Only its serial/signature and expiration may change. The original
NotBefore is retained to validate historical certificates; both CAs must be valid
at application and the new expiry cannot exceed ninety days from application.
Ordinary certificate validity checks still apply. Plan separate server and
management leaf-certificate renewal under those same authorities.

The client appends a durable receipt to its existing encrypted state and retains
the original configuration, key, bootstrap, renewal and recovery history. It uses
the latest validated continuation for transport and certificate verification.
Restarting and repeating the identical operation returns the same receipt. A
changed packet under the same ID is denied. Old client binaries cannot decode the
new history and must not be selected as a rollback after application.

Before a live continuation, capture a stopped-writer encrypted backup and deploy
a compatible client. Review the exact packet on the device without exporting its
private state. After application, use a new client process to verify authenticated
access and unchanged identity/key/history. Preserve the receipt and old CA bytes.
This command does not change membership validity, admit a thirty-day term, update
host guards or establish full hardware qualification.
