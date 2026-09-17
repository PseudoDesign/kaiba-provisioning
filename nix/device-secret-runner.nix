{ pkgs }:
let
  source = ../scripts/device-secret/runner.py;
  package = pkgs.writeShellApplication {
    name = "kaiba-device-secret-runner";
    text = ''
      exec ${pkgs.python3}/bin/python3 -I ${source} "$@"
    '';
  };
  check =
    pkgs.runCommand "kaiba-device-secret-runner-tests"
      {
        nativeBuildInputs = [
          pkgs.python3
          package
        ];
      }
      ''
        export KAIBA_DEVICE_SECRET_RUNNER_SOURCE=${source}
        export KAIBA_DEVICE_SECRET_RUNNER_COMMAND=${package}/bin/kaiba-device-secret-runner
        python3 -B -m unittest discover \
          -s ${../tests/device-secret-runner} -p 'test_*.py' -v
        kaiba-device-secret-runner --help > help.txt
        grep -F 'rehearse' help.txt
        mkdir -p "$out"
        cp help.txt "$out/"
      '';
in
{
  inherit package check;
}
