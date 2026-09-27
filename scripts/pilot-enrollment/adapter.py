"""Dispatch fixed, reviewed enrollment commands and postcondition probes.

No shell command interpolation, general-purpose remote shell, PIN prompt, or
implicit retry. The packet author reviews every executable and argument. This
is execution authority code: command names alone do not constrain their effects.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

# Installed next to this module by Nix; -I excludes caller-controlled imports.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import runner as r

CONTEXT_SCHEMA = 'kaiba.pilot-enrollment-adapter/v1alpha1'


def command(value):
    r.fields(value, ('argv', 'sha256'))
    argv = value['argv']
    r.require(isinstance(argv, list) and 1 <= len(argv) <= 24 and
              all(isinstance(x, str) and 0 < len(x) <= 2048 and
                  all(ord(c) >= 32 for c in x) for x in argv), 'invalid-command')
    r.require(argv[0].startswith('/nix/store/'), 'command-not-immutable')
    r.require(isinstance(value['sha256'], str) and r.HEX.fullmatch(value['sha256']), 'invalid-command-hash')
    # Nix executables can be symlinks within their immutable store closure.
    resolved = Path(argv[0]).resolve(strict=True)
    r.require(str(resolved).startswith('/nix/store/'), 'command-escaped-store')
    r.require(hashlib.sha256(resolved.read_bytes()).hexdigest() == value['sha256'], 'command-changed')


def validate(context, request):
    r.fields(context, ('schema_version', 'run_id', 'target_digest', 'inputs', 'operations'))
    r.require(context['schema_version'] == CONTEXT_SCHEMA and
              context['run_id'] == request['run_id'] and
              context['target_digest'] == request['target_digest'], 'context-binding')
    r.require(isinstance(context['inputs'], list) and len(context['inputs']) <= 128, 'invalid-inputs')
    for item in context['inputs']:
        r.fields(item, ('path', 'sha256'))
        r.require(isinstance(item['path'], str) and item['path'].startswith('/') and
                  isinstance(item['sha256'], str) and r.HEX.fullmatch(item['sha256']), 'invalid-input')
        r.trusted_parent(Path(item['path']).parent, 0)
        raw = r.read_file(item['path'], maximum=16*1024*1024, owner=0)
        r.require(r.sha(raw) == item['sha256'], 'adapter-input-changed')
    r.fields(context['operations'], (*r.STEPS, 'preflight', 'check-credential', 'safe-stop'))
    for name, operation in context['operations'].items():
        r.fields(operation, ('execute', 'probe'))
        if name == 'preflight':
            r.require(operation['execute'] is None, 'preflight-must-only-probe')
        else:
            command(operation['execute'])
        command(operation['probe'])


def invoke(cmd, request, keyfd=None):
    argv = list(cmd['argv'])
    if keyfd is not None:
        argv += ['--recovery-key-fd', str(keyfd)]
    # The outer runner bounds runtime/output and kills the whole process group.
    # exec inherits that group; only backup gets the one-use credential descriptor.
    process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, close_fds=True,
                               pass_fds=() if keyfd is None else (keyfd,),
                               env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
    try:
        process.stdin.write(r.canonical(request)); process.stdin.close()
        raw = process.stdout.read(r.MAX_JSON + 1)
        r.require(len(raw) <= r.MAX_JSON, 'command-response-too-large')
        r.require(process.wait() == 0, 'command-failed')
        result = r.decode(raw)
        r.fields(result, ('outcome',))
        r.require(result['outcome'] in ('complete', 'unknown', 'blocked'), 'invalid-command-result')
        return result['outcome']
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        process.stdin.close()
        process.stdout.close()


def dispatch(context, request, keyfd=None):
    action, step = request['action'], request['step']
    if action == 'preflight':
        r.require(step == 'preflight' and keyfd is None, 'invalid-preflight')
    elif action == 'check-credential':
        r.require(step == 'check-credential' and keyfd is not None, 'invalid-credential-check')
    elif action == 'safe-stop':
        r.require(step == 'safe-stop' and keyfd is None, 'invalid-safe-stop')
    else:
        r.require(action in ('execute', 'reconcile') and step in r.STEPS, 'invalid-action')
    r.require((keyfd is not None) == ((action == 'execute' and step == 'backup') or action == 'check-credential'), 'credential-scope')
    operation = context['operations'][step]
    if action in ('execute', 'safe-stop', 'check-credential'):
        outcome = invoke(operation['execute'], request, keyfd)
        if outcome != 'complete':
            return outcome
    # Execute success alone is not completion: verify the actual postcondition.
    return invoke(operation['probe'], {**request, 'action': 'reconcile'})


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--recovery-key-fd', type=int)
    args = p.parse_args()
    r.require(os.geteuid() == 0, 'root-adapter-required')
    raw = sys.stdin.buffer.read(4097); r.require(len(raw) <= 4096, 'oversize-request')
    request = r.decode(raw)
    r.fields(request, ('schema_version', 'packet_sha256', 'run_id', 'target_digest',
                       'context', 'action', 'step', 'operation_id'))
    r.require(request['schema_version'] == r.SCHEMA, 'wrong-schema')
    r.require(isinstance(request['packet_sha256'], str) and r.HEX.fullmatch(request['packet_sha256']) and
              request['operation_id'] == r.sha(r.canonical([request['packet_sha256'], request['step']])), 'operation-binding')
    r.fields(request['context'], ('path', 'sha256'))
    path = request['context']['path']; r.trusted_parent(Path(path).parent, 0)
    raw = r.read_file(path, owner=0, mode=0o600)
    r.require(r.sha(raw) == request['context']['sha256'], 'context-changed')
    context = r.decode(raw); validate(context, request)
    if args.recovery_key_fd is not None:
        r.require(args.recovery_key_fd > 2 and stat.S_ISFIFO(os.fstat(args.recovery_key_fd).st_mode), 'credential-not-pipe')
    try:
        outcome = dispatch(context, request, args.recovery_key_fd)
    finally:
        if args.recovery_key_fd is not None:
            os.close(args.recovery_key_fd)
    print(json.dumps({k: request[k] for k in ('schema_version', 'run_id', 'target_digest',
                     'operation_id', 'action', 'step')} | {'outcome': outcome}))


if __name__ == '__main__':
    try:
        main()
    except (r.Stop, OSError, ValueError, subprocess.SubprocessError):
        # Underlying output is never forwarded; retain detailed non-secret diagnostics
        # in the reviewed hook's private journal, not the passphrase-handling channel.
        print('adapter stopped; authoritative reconciliation required', file=sys.stderr)
        sys.exit(1)
