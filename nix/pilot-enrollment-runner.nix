{ pkgs }:
let
  source = ../scripts/pilot-enrollment;
  package = pkgs.runCommand "kaiba-pilot-enrollment-runner" { } ''
    mkdir -p "$out/bin" "$out/libexec"
    cp ${source}/*.py "$out/libexec/"
    for entry in runner adapter; do
      name="kaiba-pilot-enrollment-$entry"
      cat > "$out/bin/$name" <<EOF
    #!${pkgs.runtimeShell}
    exec ${pkgs.python3}/bin/python3 -I -B "$out/libexec/$entry.py" "\$@"
    EOF
      chmod 0555 "$out/bin/$name"
    done
  '';
  check =
    pkgs.runCommand "kaiba-pilot-enrollment-runner-tests"
      {
        nativeBuildInputs = [ pkgs.python3 ];
      }
      ''
        export KAIBA_PILOT_RUNNER_SOURCE=${source}
        python3 -B -m unittest discover -s ${../tests/pilot-enrollment-runner} -p 'test_*.py' -v
        ${package}/bin/kaiba-pilot-enrollment-runner --help > help.txt
        ${package}/bin/kaiba-pilot-enrollment-adapter --help > adapter-help.txt
        mkdir -p "$out"
        cp help.txt adapter-help.txt "$out/"
      '';
in
{
  inherit package check;
}
