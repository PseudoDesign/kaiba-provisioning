{
  pkgs,
  campaign,
  station,
  client,
}:
let
  python = pkgs.python3.withPackages (p: [ p.cryptography ]);
  executor = pkgs.runCommand "kaiba-guided-campaign-software-executor" { } ''
    mkdir -p "$out/bin"
    printf '#!${python}/bin/python3 -I\n' > "$out/bin/run"
    substitute ${./guided-campaign/executor.py} "$out/body" --replace-fail '@client@' '${client}/bin/kaiba-device-enrollment'
    cat "$out/body" >> "$out/bin/run"
    rm "$out/body"
    chmod 0555 "$out/bin/run"
  '';
  plan =
    pkgs.runCommand "kaiba-guided-campaign-software-plan.json" { nativeBuildInputs = [ pkgs.python3 ]; }
      ''
        export TEST_EXECUTOR=${executor}/bin/run
        python3 - <<'PY'
        import hashlib, json, os, pathlib
        executable = os.environ['TEST_EXECUTOR']
        program = dict(path=executable, sha256='sha256:'+hashlib.sha256(pathlib.Path(executable).read_bytes()).hexdigest(), timeout_seconds=30)
        steps = []
        for name, title, result in [
          ('inspect','Check the test device','Disposable client configuration is present.'),
          ('create_identity','Create the test identity','The client generated and retained its own operational key.'),
          ('restart_client','Check identity continuity','A fresh client process opened the same identity.'),
          ('verify_identity','Finish the software campaign','Identity continuity checked. Physical qualification remains pending.')]:
            step = dict(id=name, title=title, instruction='This is a software rehearsal using disposable state.', button='Check identity', execute=program, outputs=dict(passed=result))
            if name == 'restart_client':
                step['input'] = dict(label='Continue with a fresh client process?', choices=[dict(value='ready',label='Ready to check')])
            steps.append(step)
        plan = dict(schema_version='kaiba.station-campaign-plan/v1alpha1', campaign_id='software-campaign', station_id='software-station', lane_id='lane-1', mode='software_rehearsal', device_label='Software test device', target_reference='synthetic-target', profile_label='Disposable enrollment client', execution_packet_digest='sha256:'+'b'*64, expires_at='2050-01-01T00:00:00Z', steps=steps)
        pathlib.Path(os.environ['out']).write_text(json.dumps(plan))
        PY
      '';
  failureExecutor = pkgs.writeScript "kaiba-guided-campaign-failure" ''
    #!${python}/bin/python3 -I
    ${builtins.readFile ./guided-campaign/failure.py}
  '';
  negativePlans = pkgs.runCommand "kaiba-guided-campaign-negative-plans" { } ''
    ${python}/bin/python3 - <<'PY'
    import hashlib, json, pathlib, os
    baseline = json.loads(pathlib.Path('${plan}').read_text())
    program = '${failureExecutor}'
    digest = 'sha256:'+hashlib.sha256(pathlib.Path(program).read_bytes()).hexdigest()
    destination = pathlib.Path(os.environ['out'])
    destination.mkdir()
    for kind in ('digest', 'stderr', 'oversize', 'invalid', 'timeout', 'nonzero'):
        candidate = dict(baseline)
        candidate['campaign_id'] = 'negative-'+kind
        candidate['steps'] = [dict(id=kind, title='Synthetic executor fault', instruction='Software check only.', button='Begin', execute=dict(path=program, sha256=('sha256:'+'0'*64) if kind == 'digest' else digest, timeout_seconds=1), outputs=dict(passed='Unexpected success.'))]
        (destination/(kind+'.json')).write_text(json.dumps(candidate))
    PY
  '';
in
pkgs.runCommand "kaiba-guided-campaign-native-check" { } ''
  ${python}/bin/python3 -I -B ${./guided-campaign/integration.py} \
    --campaign ${campaign}/bin/kaiba-provision-campaign \
    --station ${station}/bin/kaiba-provision-station \
    --plan ${plan} --negative-plans ${negativePlans} --output "$out"
''
