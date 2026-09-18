{ pkgs }:
let
  crypto = import ./rpi5-fwcrypto.nix { inherit pkgs; };
  firmware = ../tools/device-secret-target;
  source = ../tools/device-secret-development;
  helper = pkgs.pkgsStatic.stdenv.mkDerivation {
    pname = "kaiba-device-secret-development-helper";
    version = "0.1.0";
    src = source;
    buildPhase = ''
      $CC -std=c11 -Wall -Wextra -Werror -O2 -static -ffunction-sections -fdata-sections \
        -I${crypto.library}/include -I${firmware} main.c ${firmware}/firmware.c \
        -Wl,--gc-sections -o kaiba-device-secret-development
    '';
    installPhase = ''
      install -Dm0555 kaiba-device-secret-development "$out/bin/kaiba-device-secret-development"
    '';
    meta.mainProgram = "kaiba-device-secret-development";
  };
  scripts = pkgs.runCommand "kaiba-device-secret-development-scripts" { } ''
    mkdir -p "$out"
    cp ${../scripts/device-secret/development.py} "$out/development.py"
    cp ${../scripts/device-secret/runner.py} "$out/runner.py"
  '';
  package = pkgs.writeShellApplication {
    name = "kaiba-device-secret-development-session";
    runtimeInputs = [ pkgs.openssh ];
    text = ''
      exec ${pkgs.python3}/bin/python3 -I -c \
        'import runpy, sys; sys.path.insert(0, "${scripts}"); runpy.run_module("development", run_name="__main__")' "$@"
    '';
  };
  check =
    pkgs.runCommand "kaiba-device-secret-development-check"
      {
        nativeBuildInputs = [
          pkgs.stdenv.cc
          pkgs.python3
          pkgs.binutils
        ];
      }
      ''
        $CC -std=c11 -Wall -Wextra -Werror -O2 -DKAIBA_TESTING \
          -I${crypto.library}/include -I${firmware} ${source}/main.c ${firmware}/firmware.c \
          ${../tests/device-secret-development/firmware-fixture.c} -o fixture
        python3 ${../tests/device-secret-development/test_helper.py} ./fixture ${helper}/bin/kaiba-device-secret-development
        export KAIBA_DEVELOPMENT_SCRIPTS=${scripts}
        python3 -B -m unittest discover -s ${../tests/device-secret-development} -p 'test_session.py' -v
        ${package}/bin/kaiba-device-secret-development-session --help > help.txt
        readelf -l ${helper}/bin/kaiba-device-secret-development > segments
        ! grep -q INTERP segments
        readelf -d ${helper}/bin/kaiba-device-secret-development > dynamic
        ! grep -q NEEDED dynamic
        nm ${helper}/bin/kaiba-device-secret-development > symbols
        ! grep -E 'test_exchange|fw_sign|fw_legacy_read|rpi_fw_crypto_(gen|set_key_usage)' symbols
        mkdir -p "$out"
        cp help.txt segments dynamic symbols "$out/"
      '';
in
{
  inherit helper package check;
}
