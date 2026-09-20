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
  lockHelper = helper.overrideAttrs (old: {
    pname = "kaiba-device-secret-lock-checks";
    meta = old.meta // {
      mainProgram = "kaiba-device-secret-lock-checks";
    };
    buildPhase =
      builtins.replaceStrings [ "-O2 -static" ] [ "-O2 -static -DKAIBA_LOCK_CHECKS" ]
        old.buildPhase;
    installPhase = ''
      install -Dm0555 kaiba-device-secret-development "$out/bin/kaiba-device-secret-lock-checks"
    '';
  });
  scripts = pkgs.runCommand "kaiba-device-secret-development-scripts" { } ''
    mkdir -p "$out"
    cp ${../scripts/device-secret/development.py} "$out/development.py"
    cp ${../scripts/device-secret/lock_checks.py} "$out/lock_checks.py"
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
  lockAssessor = pkgs.writeShellApplication {
    name = "kaiba-device-secret-lock-assess";
    text = ''
      exec ${pkgs.python3}/bin/python3 -I -c \
        'import runpy, sys; sys.path.insert(0, "${scripts}"); runpy.run_module("lock_checks", run_name="__main__")' "$@"
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
        $CC -std=c11 -Wall -Wextra -Werror -O2 -DKAIBA_TESTING -DKAIBA_LOCK_CHECKS \
          -I${crypto.library}/include -I${firmware} ${source}/main.c ${firmware}/firmware.c \
          ${../tests/device-secret-development/firmware-fixture.c} -o lock-fixture
        python3 ${../tests/device-secret-development/test_locks.py} ./lock-fixture ${lockHelper}/bin/kaiba-device-secret-lock-checks
        $CC -std=c11 -Wall -Wextra -Werror -O2 -DKAIBA_TESTING \
          -I${crypto.library}/include -I${firmware} ${firmware}/firmware.c \
          ${../tests/device-secret-development/validation-reasons.c} -o validation-reasons
        ./validation-reasons
        for mode in strict development; do
          define=""
          if test "$mode" = development; then define=-DKAIBA_LOCK_CHECKS; fi
          $CC -std=c11 -Wall -Wextra -Werror -O2 -DKAIBA_TESTING $define \
            -I${crypto.library}/include -I${firmware} ${firmware}/firmware.c \
            ${../tests/device-secret-development/signature-compat.c} -o signature-$mode
          ./signature-$mode
        done
        export KAIBA_DEVELOPMENT_SCRIPTS=${scripts}
        python3 -B -m unittest discover -s ${../tests/device-secret-development} -p 'test_session.py' -v
        KAIBA_LOCK_FIXTURE="$PWD/lock-fixture" python3 -B -m unittest discover -s ${../tests/device-secret-development} -p 'test_lock_assessment.py' -v
        ${lockAssessor}/bin/kaiba-device-secret-lock-assess --help > lock-help.txt
        readelf -l ${lockHelper}/bin/kaiba-device-secret-lock-checks > lock-segments
        ! grep -q INTERP lock-segments

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
  inherit
    helper
    lockHelper
    lockAssessor
    package
    check
    ;
}
