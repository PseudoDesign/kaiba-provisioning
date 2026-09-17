{
  deployment,
  pkgs,
  station,
}:

pkgs.runCommand "kaiba-station-observation-integration"
  {
    nativeBuildInputs = [
      pkgs.bash
      pkgs.coreutils
      pkgs.diffutils
      pkgs.findutils
      pkgs.gawk
      pkgs.openssl
      pkgs.python3
    ];
  }
  ''
    export KAIBA_AUTHORITY_TEST_PATH="$PATH"
    python3 ${./deployment/station_observation_test.py} \
      --deployment ${deployment} \
      --station ${station}/bin/kaiba-provision-station
    mkdir -p "$out"
    printf '%s\n' 'station observation against packaged control authority: pass' > "$out/result.txt"
  ''
