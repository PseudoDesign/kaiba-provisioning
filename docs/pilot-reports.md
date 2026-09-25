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

Review remaining work whenever tests complete. P-03 (Ace reboot persistence and
protected mount) and P-06 (populated authority restore) are complete in the
September 25 snapshot. The later diagnostic run exercised transport outage, dependency-denial and
recovery, reference submission, same-key repeat and changed-content rejection.
Its privileged results are operator-reported, with cleanup independently checked.
A fresh backup after that submission passed recovery unlock and read-only
filesystem/database checks; isolated service startup of that newer snapshot
was not repeated. Sustained serving,
credential lifecycle, staged/revoked cases, real cross-device isolation and
evidence review remain separate conditions.

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
