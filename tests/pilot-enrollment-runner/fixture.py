"""Synthetic subprocess adapter. No network, hardware, sudo, or real identities."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import time

p=argparse.ArgumentParser();p.add_argument('--recovery-key-fd',type=int);args=p.parse_args()
q=json.load(sys.stdin);config=json.loads(Path(q['context']['path']).read_text())
key_actions=(q['action']=='check-credential' or (q['action']=='execute' and q['step']=='backup'))
if (args.recovery_key_fd is not None)!=key_actions:sys.exit(7)
if key_actions:
    key=os.read(args.recovery_key_fd,4096);os.close(args.recovery_key_fd)
    if hashlib.sha256(key).hexdigest()!=config['key_hash']:sys.exit(8)
    del key
if q['step']==config.get('hang'):time.sleep(30)
if q['step']==config.get('oversize'):sys.stdout.write('x'*70000);sys.exit(0)
db=sqlite3.connect(config['database'])
db.execute('CREATE TABLE IF NOT EXISTS operations (id TEXT PRIMARY KEY, step TEXT, target TEXT)')
outcome='complete'
if q['action']=='execute':
    db.execute('INSERT INTO operations VALUES (?,?,?)',(q['operation_id'],q['step'],q['target_digest']))
    db.commit()
    if q['step']=='backup':
        dest=sqlite3.connect(config['database']+'.backup');db.backup(dest);dest.close()
    if q['step']==config.get('lose_reply'):
        # This output must never appear in runner journals/progress/errors.
        print('SYNTHETIC-SENSITIVE-DIAGNOSTIC',file=sys.stderr);sys.exit(9)
elif q['action']=='reconcile':
    row=db.execute('SELECT target FROM operations WHERE id=?',(q['operation_id'],)).fetchone()
    outcome='complete' if row==(q['target_digest'],) else 'unknown'
db.close()
result={k:q[k] for k in ('schema_version','run_id','target_digest','operation_id','action','step')}
if q['step']==config.get('wrong_target'):result['target_digest']='d'*64
print(json.dumps(result|{'outcome':outcome}))
