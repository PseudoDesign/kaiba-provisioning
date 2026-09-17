"""Private draft of allowlisted capture facts; never publishes or qualifies."""
import importlib.util
import os
from pathlib import Path
import sys

spec = importlib.util.spec_from_file_location('packet', Path(__file__).with_name('packet.py'))
p = importlib.util.module_from_spec(spec); spec.loader.exec_module(p)


def project(bundle, state):
    packet = p.validate(p.load(bundle/'packet.json'))
    p.require(state.is_dir(), 'existing-capture-required')
    store = p.capture.Store(state)
    try:
        plan, progress, _ = store.load()
        p.require(plan == packet['capture_plan'], 'packet-capture-mismatch')
        phases = []
        for saved in progress['completed']:
            r = store.read(saved['phase']+'.result.json')
            phases.append(dict(phase=saved['phase'], outcome=r['outcome'], checks=r['checks'],
                               raw_sha256=r['raw_sha256'], raw_bytes=r['raw_bytes'],
                               observation_seconds=r['observation_seconds']))
        return dict(schema_version='kaiba.device-secret-report-draft/v1alpha1',
                    source_revision=plan['source_revision'], experiment_id=plan['experiment_id'],
                    packet_sha256=p.sha(bundle/'packet.json'), boot_image_sha256=plan['boot_image_sha256'],
                    verity_root_hash=plan['verity_root_hash'], mode=progress['mode'], phases=phases,
                    needs_review=bool(progress['blocked'] or progress['active_phase']),
                    stop_reason=progress['blocked'] or ('interrupted-capture' if progress['active_phase'] else None),
                    physical_isolation='requires-separate-review', media_readback='requires-separate-review',
                    slot_and_image_suitability='requires-separate-review', hardware_qualified=False,
                    fleet_admission='unevaluated', publication_authorized=False)
    finally: store.close()


if __name__ == '__main__':
    try:
        p.require(len(sys.argv) == 4, 'arguments')
        bundle, state, output = map(Path, sys.argv[1:])
        value = project(bundle, state)
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(p.canonical(value)); f.flush(); os.fsync(f.fileno())
        parent = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try: os.fsync(parent)
        finally: os.close(parent)
        print('Private draft prepared; publication and hardware qualification remain unapproved.')
    except BaseException:
        print('STOP: report inputs incomplete or inconsistent; no publication occurred', file=sys.stderr)
        sys.exit(1)
