{
  pkgs,
  fixtureMedia,
  factories,
}:
let
  fixture =
    pkgs.runCommand "device-secret-media-synthetic-fixture"
      {
        passthru.kaibaDeviceSecretPacket = true;
        nativeBuildInputs = [
          pkgs.python3
          pkgs.gptfdisk
        ];
      }
      ''
        export KAIBA_EXECUTION_SOURCE=${../scripts/device-secret}
        export KAIBA_EXECUTION_MEDIA=${fixtureMedia}
        python3 - <<'PYTHON'
        import importlib.util, os, shutil
        from pathlib import Path
        spec = importlib.util.spec_from_file_location("test", "${../tests/device-secret-execution/test_execution.py}")
        test = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(test)
        bundle, _ = test.create_packet(Path.cwd())
        shutil.copytree(bundle, os.environ["out"])
        PYTHON
      '';
  executor = factories.mkExecutor { packet = fixture; };
  reporter = factories.mkReport { packet = fixture; };
in
pkgs.runCommand "kaiba-device-secret-execution-tests"
  {
    passthru = { inherit fixture; };
    nativeBuildInputs = [
      pkgs.python3
      pkgs.gptfdisk
      executor
      reporter
    ];
  }
  ''
    export KAIBA_EXECUTION_SOURCE=${../scripts/device-secret}
    export KAIBA_EXECUTION_MEDIA=${fixtureMedia}
    python3 -B -m unittest discover -s ${../tests/device-secret-execution} -p 'test_*.py' -v
    kaiba-device-secret-media describe > describe.json
    if kaiba-device-secret-media stage extra; then exit 1; fi
    if kaiba-device-secret-report; then exit 1; fi
    mkdir "$out"
    cp describe.json "$out/"
    printf '%s\n' 'software-only; hardware pending' > "$out/result"
  ''
