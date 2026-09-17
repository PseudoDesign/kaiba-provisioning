"""File-only composition of a finalized experiment and its bounded host packet."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

spec = importlib.util.spec_from_file_location('capture', Path(__file__).with_name('runner.py'))
capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)
require, canonical, decode = capture.require, capture.canonical, capture.decode
MIB = 1024 * 1024
SCHEMA = 'kaiba.device-secret-execution-packet/v1alpha1'
NAMES = ('gpt-primary.img', 'boot-filesystem.img', 'root-data.img', 'root-hash.img',
         'experiment-zero.img', 'gpt-secondary.img')
ACTIONS = ('backup', 'stage', 'restore')


def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def load(path):
    return decode(capture.regular_bytes(path))


def hexdigest(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) and set(value) != {'0'}


def validate_host(h):
    capture.exact_fields(h, ('hostname', 'machine_id_sha256', 'disk_by_id', 'enclosure_by_id',
                            'disk_serial', 'enclosure_serial', 'usb_vendor', 'usb_product', 'state_directory'))
    require(isinstance(h['hostname'], str) and re.fullmatch('[a-z0-9][a-z0-9-]{0,62}', h['hostname']), 'host-name')
    require(hexdigest(h['machine_id_sha256']), 'host-id')
    for key in ('disk_by_id', 'enclosure_by_id'):
        require(isinstance(h[key], str) and re.fullmatch('/dev/disk/by-id/[A-Za-z0-9_.:-]+', h[key])
                and not h[key].endswith(('/.', '/..')), 'device-selector')
    require(h['disk_by_id'] != h['enclosure_by_id'], 'distinct-selectors-required')
    for key in ('disk_serial', 'enclosure_serial'):
        require(isinstance(h[key], str) and re.fullmatch('[A-Za-z0-9_.:-]{1,100}', h[key]), 'device-serial')
    for key in ('usb_vendor', 'usb_product'):
        require(isinstance(h[key], str) and re.fullmatch('[0-9a-f]{4}', h[key]), 'usb-id')
    require(isinstance(h['state_directory'], str) and
            re.fullmatch('/var/lib/kaiba-device-secret-[a-z0-9][a-z0-9-]{0,63}', h['state_directory']), 'state-directory')


def validate(p):
    capture.exact_fields(p, ('schema_version', 'experiment', 'capture_plan', 'host', 'capacity_bytes',
                            'spans', 'signing_input_sha256', 'reviews', 'execution_authority', 'hardware_qualified'))
    require(p['schema_version'] == SCHEMA and p['execution_authority'] is False and
            p['hardware_qualified'] is False, 'packet-kind')
    validate_host(p['host'])
    e, c = p['experiment'], p['capture_plan']
    capture.validate_plan(c)
    capture.exact_fields(e, ('schema_version', 'scheme', 'experiment_id', 'target_reference', 'source_revision',
                            'volume_uuid', 'partition_uuid', 'board_serial_sha256', 'disk_serial_sha256',
                            'nonce_hex', 'slot_id', 'expected_usage'))
    require(e['schema_version'] == 'kaiba.device-secret-target/v1alpha1' and
            e['scheme'] == 'kaiba-firmware-hmac-counter-v1', 'experiment-kind')
    require(type(e['slot_id']) is int and e['slot_id'] == 1 and type(e['expected_usage']) is int and
            e['expected_usage'] in (0, 8, 9, 10, 11, 12, 13, 14), 'slot-binding')
    require(all(e[k] == c[k] and type(e[k]) is type(c[k]) for k in
                ('experiment_id', 'target_reference', 'source_revision', 'volume_uuid', 'slot_id')), 'capture-binding')
    require(capture.valid_uuid(e['partition_uuid']) and e['partition_uuid'] != e['volume_uuid'], 'partition-uuid')
    require(all(hexdigest(e[k]) for k in ('nonce_hex', 'board_serial_sha256', 'disk_serial_sha256')), 'experiment-digest')
    require(hashlib.sha256(bytes.fromhex(e['nonce_hex'])).hexdigest() == c['nonce_sha256'], 'nonce-binding')
    require(hashlib.sha256(p['host']['disk_serial'].encode()).hexdigest() == e['disk_serial_sha256'], 'disk-binding')
    require(hexdigest(p['signing_input_sha256']), 'signing-input-binding')
    capture.exact_fields(p['reviews'], ('slot_suitability', 'authorized_images', 'recovery_route'))
    require(all(hexdigest(v) for v in p['reviews'].values()), 'missing-review-digest')
    capacity = p['capacity_bytes']
    require(type(capacity) is int and 256*MIB <= capacity <= 16*1024**4 and capacity % 512 == 0, 'capacity')
    require(type(p['spans']) is list and len(p['spans']) == 6, 'span-count')
    end = 0
    for name, s in zip(NAMES, p['spans']):
        capture.exact_fields(s, ('name', 'offset', 'size', 'sha256'))
        require(s['name'] == name and hexdigest(s['sha256']), 'span-name-or-digest')
        require(type(s['offset']) is int and type(s['size']) is int and s['offset'] >= end and
                s['size'] > 0 and s['offset'] % 512 == s['size'] % 512 == 0 and
                s['offset'] + s['size'] <= capacity, 'span-bounds')
        end = s['offset'] + s['size']
    spans = p['spans']
    require((spans[0]['offset'], spans[0]['size']) == (0, 34*512) and
            (spans[1]['offset'], spans[1]['size']) == (MIB, 128*MIB) and
            spans[2]['offset'] == 129*MIB and all(s['offset'] % MIB == 0 for s in spans[2:5]) and
            spans[4]['size'] == 65*MIB and
            (spans[5]['offset'], spans[5]['size']) == (capacity-33*512, 33*512), 'layout-bounds')
    return p


def compose(media, experiment, host, capture_settings, reviews, output):
    """Only regular files; media comes from the authenticated Nix finalizer."""
    require(not output.exists(), 'output-exists')
    e, h, cfg = load(experiment), load(host), load(capture_settings)
    base, signing = load(media/'media-plan.json'), load(media/'signing-input.json')
    require(base['schema_version'] == 'kaiba.provisioning.rpi5-native-offline-media-handoff/v1alpha1' and
            base['source_revision'] == signing['source_revision'] == e['source_revision'] and
            base['execution_authorized'] is False and base['hardware_observed'] is False, 'media-binding')
    capacity = base['required_capacity_bytes']
    require(type(capacity) is int and capacity % 512 == 0, 'capacity')
    # Signed review binds the experiment JSON, in addition to the boot/root bytes.
    review = load(media/'review/review.json')
    require(review.get('device_secret_experiment_digest') == 'sha256:' + sha(experiment), 'signed-experiment-review')
    require(sha(media/'review/review.json') == signing['review_digest'].removeprefix('sha256:'), 'review-binding')
    require(sha(media/'signing-input.json') == base['signing_input_digest'].removeprefix('sha256:'), 'signing-binding')
    require(sha(media/'verified-signing/boot.img') == signing['boot_image']['digest'].removeprefix('sha256:'), 'boot-binding')
    capture.exact_fields(cfg, ('uart_by_id', 'uart_by_path', 'idle_timeout_seconds', 'observation_seconds', 'maximum_bytes'))
    cp = dict(schema_version=capture.PLAN_SCHEMA, **cfg, **{k: e[k] for k in
              ('experiment_id', 'target_reference', 'source_revision', 'volume_uuid', 'slot_id')},
              boot_image_sha256=signing['boot_image']['digest'].removeprefix('sha256:'),
              verity_root_hash=signing['root_integrity_digest'].removeprefix('sha256:'),
              nonce_sha256=hashlib.sha256(bytes.fromhex(e['nonce_hex'])).hexdigest())
    require(len(base['partitions']) == 3 and len(base['writes']) == 5, 'base-layout')
    require(e['partition_uuid'] not in [s['guid'] for s in base['partitions']], 'duplicate-partuuid')
    start = max(s['offset_bytes'] + s['size_bytes'] for s in base['partitions'])
    start = ((start + MIB-1)//MIB)*MIB
    require(start + 65*MIB <= capacity-MIB, 'disposable-extent-does-not-fit')
    output.mkdir()
    for w in base['writes']:
        require(w['path'] in NAMES and (media/w['path']).is_file() and not (media/w['path']).is_symlink(), 'media-file')
        require((media/w['path']).stat().st_size == w['size_bytes'] and
                sha(media/w['path']) == w['digest'].removeprefix('sha256:'), 'media-digest')
        shutil.copyfile(media/w['path'], output/w['path'])
    with (output/'experiment-zero.img').open('xb') as f:
        f.truncate(65*MIB)
    with tempfile.TemporaryDirectory() as tmp:
        disk = Path(tmp)/'layout.img'
        with disk.open('xb') as f:
            f.truncate(capacity)
            for w in (base['writes'][0], base['writes'][-1]):
                f.seek(w['offset_bytes']); f.write((media/w['path']).read_bytes())
        subprocess.run(['sgdisk', f'--new=4:{start//512}:{(start+65*MIB)//512-1}', '--typecode=4:8309',
                        '--partition-guid=4:'+e['partition_uuid'], '--change-name=4:KAIBA_EXPERIMENT', str(disk)],
                       check=True, stdout=subprocess.DEVNULL)
        result = subprocess.check_output(['sgdisk', '--verify', str(disk)])
        require(b'No problems found' in result, 'gpt-validation')
        with disk.open('rb') as f:
            (output/NAMES[0]).write_bytes(f.read(34*512)); f.seek(capacity-33*512)
            (output/NAMES[-1]).write_bytes(f.read(33*512))
    offsets = {w['path']: w['offset_bytes'] for w in base['writes']}
    offsets['experiment-zero.img'] = start
    p = dict(schema_version=SCHEMA, experiment=e, capture_plan=cp, host=h, capacity_bytes=capacity,
             spans=[dict(name=n, offset=offsets[n], size=(output/n).stat().st_size, sha256=sha(output/n)) for n in NAMES],
             signing_input_sha256=sha(media/'signing-input.json'),
             reviews={k: sha(v) for k,v in reviews.items()}, execution_authority=False, hardware_qualified=False)
    validate(p)
    (output/'packet.json').write_bytes(canonical(p))
    (output/'capture-plan.json').write_bytes(canonical(cp))
    (output/'experiment.json').write_bytes(canonical(e))
    shutil.copytree(media/'verified-signing', output/'verified-signing')
    shutil.copyfile(media/'signing-input.json', output/'signing-input.json')
    review_dir = output/'reviews'; review_dir.mkdir()
    for key, value in reviews.items():
        shutil.copyfile(value, review_dir/(key+'.md'))
    (output/'review.md').write_text(render(p, sha(output/'packet.json')))
    return p


def render(p, packet_hash):
    rows = '\n'.join(f"| {s['name']} | {s['offset']} | {s['size']} | `{s['sha256']}` |" for s in p['spans'])
    return f'''# Prepared device-secret execution packet

Packet SHA-256: `{packet_hash}`. Source: `{p['experiment']['source_revision']}`.
This file is a review input, not an approval or hardware result.

Host: `{p['host']['hostname']}`. Selectors: `{p['host']['disk_by_id']}` and
`{p['host']['enclosure_by_id']}`. Capacity: {p['capacity_bytes']} bytes, 512-byte sectors.
Backup/state directory: `{p['host']['state_directory']}` (private, root-owned,
on an independent persistent filesystem). Every listed span is backed up fully.

| Span | Offset | Bytes | SHA-256 |
| --- | ---: | ---: | --- |
{rows}

Separate authority scopes:

- Signing: the existing exact native-image grant and authenticated receipt.
- Media: backup {sum(s['size'] for s in p['spans'])} bytes, stage the six spans,
  and optionally restore those exact preimages once. No writes outside these spans.
- Target: two cold boots; slot {p['experiment']['slot_id']}, existing usage
  {p['experiment']['expected_usage']}, negative raw/legacy reads, HMAC, fixed
  test signing and volatile lock changes as defined by the target harness.
  No generation, OTP write, usage change, EEPROM operation, or production identity.
- Physical: NVMe fitting/removal, two isolated cold boots and return to inspection
  SD using the reviewed route. Manual power/isolation observations remain necessary.

Review `reviews/slot_suitability.md`, `authorized_images.md`, and `recovery_route.md`.
Their hashes bind the text, not its truth or approval. Missing or rejected review
blocks live execution. The native signing receipt authorizes no media/secret action.

The executor accepts only status, backup, stage, verify, restore. It requires an
external root-owned `authorization.json` bound to this packet. Stage can create
fresh backups if none exist. An attempted/incomplete action cannot be repeated.
Restore is a separate, explicit action, never an automatic reaction to failure.
It restores the immediately preceding bytes, not a lost historical filesystem.

Before connecting media, mask/stop automount under the reviewed host procedure.
The executor requires this guard and a read-only, unmounted, unused USB disk.
It restores the read-only guard after each write attempt and invalidates the block
cache before independent full-span readback. Host reboot or disk replacement
never creates a new write allowance. After any ambiguous result, stop for review.

After stage, initialize the passive runner from `capture-plan.json`. Fit the NVMe,
confirm all power off for ten seconds and all network/data paths disconnected,
then arm capture and power from the separate supply. Repeat the off/isolation
check and capture for reopen. Return to SD by the reviewed physical route.
Do not rely on the boot menu. Keep raw evidence private. A public projection needs
separate review and does not establish hardware qualification or fleet admission.
'''


if __name__ == '__main__':
    try:
        require(len(sys.argv) == 10, 'arguments')
        media, experiment, host, settings, slot, images, recovery, output = map(Path, sys.argv[1:9])
        require(sys.argv[9] == 'compose-files-only', 'file-only-command')
        compose(media, experiment, host, settings,
                dict(slot_suitability=slot, authorized_images=images, recovery_route=recovery), output)
    except (capture.Rejected, OSError, ValueError, subprocess.SubprocessError):
        print('STOP: packet composition failed; no hardware operation occurred', file=sys.stderr)
        sys.exit(1)
