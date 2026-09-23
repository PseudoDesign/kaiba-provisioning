"""Synthetic executor faults; stdout/stderr must never enter a report."""
import json
from pathlib import Path
import sys
import time

request = json.load(sys.stdin)
kind = request['step_id']
with (Path.cwd()/('called-negative-'+kind)).open('x') as marker:
    marker.write('once')
if kind == 'stderr':
    print('private_key=synthetic-must-not-escape', file=sys.stderr)
    print('{}')
elif kind == 'oversize':
    print('x'*70000)
elif kind == 'invalid':
    print('{"private_key":"synthetic-must-not-escape"}')
elif kind == 'timeout':
    time.sleep(30)
else:
    sys.exit(7)
