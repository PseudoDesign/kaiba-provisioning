# Public pilot enrollment reports

The GitHub Pages bundle includes `pilot/index.html`, linked from the provisioning
simulation. It shows dated enrollment/test summaries for Ace and Mako. It is a
historical report, not a station control surface or live fleet status endpoint.
A passed test does not renew authorization or establish full fleet qualification.

## Update after each milestone

Edit [pilot-reports.json](pilot-reports.json), the single reviewed public data
source. Keep the existing device slug stable; add a new device object for each
new pilot member. Set the report update date and the affected device's snapshot
date. Describe the completed test, its result and the basis for the claim.
Distinguish direct verification from an operator-reported privileged result.
Retain pending, failed or blocked results until a subsequent reviewed test
resolves them; do not translate missing evidence into success.

Update enrollment only after the corresponding authority workflow completes.
Keep recorded authorization expiry explicit. Report renewal only after its own
reviewed execution; the page must not imply that historic active membership is
current access. The present Ace authorization window is a recorded deadline,
not a promise that services are running. Mako must establish its own evidence.

Review remaining work whenever milestones complete. The September 25 snapshot
records Ace reboot persistence, a populated authority restore, diagnostic
submission and outage/dependency checks. The September 26 update adds same-key
recovery, normal renewal to revision 3, still-valid predecessor rejection on a
fresh connection, supervisor shutdown checks and guarded serving startup.
Privileged execution results are operator-reported; service activity was checked
independently after startup. The existing deadline is October 3 at 02:06:35 UTC.

The renewed-authority backup passed recovery unlock and read-only filesystem and
database checks. Isolated startup of that exact snapshot was not repeated.
A subsequent encrypted backup includes the active-serving controls; recovery
unlock, restored filesystem/database checks and authenticated access after
resume passed. The serving deadline did not change. Ongoing uptime,
remaining live loss/revocation/retirement cases, Mako enrollment, cross-device
isolation and full fleet qualification remain separate conditions. Do not mark
a prepared execution packet as a completed hardware or deployment result.

## Publication boundary

The public file contains device display names, dates, concise results and
limitations only. Do not copy raw private reports into it. Exclude device
serials, hardware/enrollment identifiers, SPKI or credential contents, addresses,
SSH details, private filesystem paths, raw captures, authority configurations,
and secret values. Review every text field before pushing: schema validation
rejects extra fields but cannot determine whether free text is sensitive.

This snapshot deliberately contains no private evidence hashes or download
links. Private reports remain on the management host. The page provides a JSON
download of exactly the reviewed public summary. Keep prior summaries available
through Git history; corrections should explain their changed claim in the PR.

## Validation and deployment

```sh
python3 -B -m unittest discover -s tests/pilot-reports -p 'test_*.py'
nix build --no-link .#kaiba-provision-station-pages
```

The generator validates the data, escapes all displayed text, and emits static
HTML plus the public JSON. No JavaScript, API calls or enrollment controls are
needed. The Nix build adds navigation only to the published static bundle;
embedded station runtime assets remain unchanged. Report data and renderer are
direct Pages build inputs, not added to the Go or hardware build inputs.
The existing Pages workflow publishes updates after merge into main.
