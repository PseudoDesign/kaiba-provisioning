#!/usr/bin/env python3
"""Verify the byte-identical approved wire snapshot; no network or readiness claim."""
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
wire = root / 'internal/appliancewire'
pin = json.loads((wire / 'PIN.json').read_text())
assert pin['schema_version'] == 'kaiba.appliance-wire-pin/v1'
assert pin['contract_version'] == '0.7.0-draft.1'
assert pin['source_repository'] == 'https://github.com/pd-codex/kaiba-contracts'
assert pin['source_path'] == 'runtime/appliancewire'
assert len(pin['source_revision']) == 40 and set(pin['source_revision']) <= set('0123456789abcdef')
actual = {p.name: 'sha256:' + hashlib.sha256(p.read_bytes()).hexdigest()
          for p in wire.glob('*.go')}
assert actual == pin['files'], 'appliance wire differs from the immutable contract pin'
print('appliance wire pin verified')
