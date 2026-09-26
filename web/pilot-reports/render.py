#!/usr/bin/env python3
"""Render reviewed public summaries only; never ingest private evidence folders."""
import datetime
import html
import json
import re
import sys
from pathlib import Path

def fields(value, expected):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ValueError('unexpected report fields')

def text(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 2000:
        raise ValueError('invalid report text')
    return html.escape(value, quote=True)

def validate(data):
    fields(data, ['schema_version', 'updated', 'devices'])
    if data['schema_version'] != 'kaiba.public-pilot-reports/v1':
        raise ValueError('unsupported report version')
    updated = datetime.date.fromisoformat(data['updated'])
    if not isinstance(data['devices'], list) or not data['devices']:
        raise ValueError('devices required')
    slugs = set()
    for d in data['devices']:
        fields(d, ['slug', 'name', 'enrollment', 'as_of', 'authorization_expires_at', 'summary', 'tests', 'remaining'])
        if not isinstance(d['slug'], str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,39}', d['slug']) or d['slug'] in slugs:
            raise ValueError('invalid or duplicate slug')
        slugs.add(d['slug'])
        for key in ['name', 'enrollment', 'summary']:
            text(d[key])
        if d['enrollment'] not in ['Pilot enrolled', 'Not yet pilot enrolled']:
            raise ValueError('unsupported enrollment status')
        if datetime.date.fromisoformat(d['as_of']) > updated:
            raise ValueError('device newer than report')
        expiry = d['authorization_expires_at']
        if expiry is not None:
            if not isinstance(expiry, str) or not expiry.endswith('Z'):
                raise ValueError('expiry must use UTC')
            datetime.datetime.fromisoformat(expiry.replace('Z', '+00:00'))
        if not isinstance(d['tests'], list) or not d['tests'] or not isinstance(d['remaining'], list):
            raise ValueError('tests and remaining work must be lists')
        for t in d['tests']:
            fields(t, ['name', 'status', 'basis'])
            text(t['name']); text(t['basis'])
            if t['status'] not in ['passed', 'pending', 'failed', 'blocked']:
                raise ValueError('unsupported test status')
        for item in d['remaining']:
            text(item)
    return data

def render(data):
    validate(data)
    cards = []
    for d in data['devices']:
        rows = ''.join(f'<tr><th scope="row">{text(t["name"])}</th><td><span class="status {t["status"]}">{t["status"].capitalize()}</span></td><td>{text(t["basis"])}</td></tr>' for t in d['tests'])
        remaining = ''.join(f'<li>{text(x)}</li>' for x in d['remaining'])
        expiry = text(d['authorization_expires_at']) if d['authorization_expires_at'] else 'No enrolled credential window recorded'
        cards.append(f'''<section id="{d['slug']}" aria-labelledby="{d['slug']}-title">
<h2 id="{d['slug']}-title">{text(d['name'])}</h2>
<p class="enrollment">{text(d['enrollment'])} <span>· as of {text(d['as_of'])}</span></p>
<p>{text(d['summary'])}</p>
<dl><dt>Recorded authorization expiry (UTC)</dt><dd>{expiry}</dd><dt>Full fleet qualification</dt><dd>Not established</dd></dl>
<div class="table-scroll" role="region" aria-label="{text(d['name'])} test results" tabindex="0"><table><thead><tr><th scope="col">Test</th><th scope="col">Result</th><th scope="col">Evidence basis / limits</th></tr></thead><tbody>{rows}</tbody></table></div>
<h3>Remaining work</h3><ul>{remaining}</ul></section>''')
    nav = ' · '.join(f'<a href="#{d["slug"]}">{text(d["name"])}</a>' for d in data['devices'])
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'self'; base-uri 'none'; form-action 'none'">
<meta name="description" content="Dated Kaiba pilot enrollment test reports and remaining conditions.">
<title>Kaiba pilot enrollment reports</title><link rel="stylesheet" href="./styles.css"></head>
<body><a class="skip" href="#reports">Skip to reports</a><header><a href="../index.html">Kaiba provisioning simulation</a><h1>Pilot enrollment reports</h1>
<p>Reviewed snapshot updated {text(data['updated'])}. {nav}</p></header><main id="reports">
<aside><strong>Historical results, not live authorization.</strong> Enrollment records and passed tests do not extend policy or certificate expiry. Current access must be checked with fleet authority. Pilot exceptions do not establish full production qualification.</aside>
{''.join(cards)}
<section><h2>Keeping reports current</h2><p>Update the reviewed source after each completed test or enrollment. Preserve failed and pending outcomes, date each device snapshot, and state the evidence basis. These pages cannot start provisioning or enrollment operations.</p>
<p><a href="./reports.json">Download the public report data</a> · <a href="https://github.com/PseudoDesign/kaiba-provisioning/blob/main/docs/pilot-reports.md">Report maintenance guide</a> · <a href="https://github.com/PseudoDesign/kaiba-provisioning/pull/73">Client diagnostics PR #73</a></p></section>
</main><footer>Private captures, credentials, device identifiers and authority addresses are excluded from this summary.</footer></body></html>'''

def main():
    source, out, homepage = map(Path, sys.argv[1:])
    data = validate(json.loads(source.read_text()))
    out.mkdir(parents=True, exist_ok=True)
    (out/'index.html').write_text(render(data))
    (out/'reports.json').write_text(json.dumps(data, indent=2)+'\n')
    page = homepage.read_text()
    marker = '    <main id="station-workflow"'
    if page.count(marker) != 1:
        raise ValueError('station page navigation marker changed')
    page = page.replace(marker, '    <nav aria-label="Project reports"><a href="./pilot/index.html">Pilot enrollment reports</a></nav>\n\n'+marker)
    homepage.write_text(page)

if __name__ == '__main__':
    main()
