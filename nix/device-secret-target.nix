{ pkgs }:
let
  crypto = import ./rpi5-fwcrypto.nix { inherit pkgs; };
  source = ../tools/device-secret-target;
  package = pkgs.stdenv.mkDerivation {
    pname = "kaiba-device-secret-target";
    version = "0.1.0";
    src = source;
    nativeBuildInputs = [ pkgs.pkg-config ];
    buildInputs = [
      crypto.library
      pkgs.jansson
      pkgs.openssl
      pkgs.cryptsetup
      pkgs.lvm2
    ];
    buildPhase = ''
      $CC -std=c11 -Wall -Wextra -Werror -O2 \
        $(pkg-config --cflags jansson openssl libcryptsetup devmapper) \
        -I${crypto.library}/include main.c config.c crypto.c firmware.c runtime.c storage.c \
        $(pkg-config --libs jansson openssl libcryptsetup devmapper) -o kaiba-device-secret-target
    '';
    installPhase = ''
      install -Dm0555 kaiba-device-secret-target "$out/bin/kaiba-device-secret-target"
    '';
    meta.mainProgram = "kaiba-device-secret-target";
  };
  fixture = package.overrideAttrs (_: {
    pname = "kaiba-device-secret-target-test-firmware";
    buildPhase = ''
      $CC -std=c11 -Wall -Wextra -Werror -O2 -DKAIBA_TESTING \
        $(pkg-config --cflags jansson openssl libcryptsetup devmapper) \
        -I${crypto.library}/include main.c config.c crypto.c firmware.c runtime.c storage.c \
        ${../tests/device-secret-target/firmware-fixture.c} -I. \
        $(pkg-config --libs jansson openssl libcryptsetup devmapper) -o kaiba-device-secret-target
    '';
  });
  check =
    pkgs.runCommand "kaiba-device-secret-target-check"
      {
        nativeBuildInputs = [
          pkgs.stdenv.cc
          pkgs.pkg-config
          pkgs.python3
          pkgs.binutils
        ];
        buildInputs = [
          pkgs.jansson
          pkgs.openssl
        ];
      }
      ''
        set -euo pipefail
        $CC -std=c11 -Wall -Wextra -Werror -O2 -DKAIBA_TESTING \
          $(pkg-config --cflags jansson openssl) -I${crypto.library}/include -I${source} \
          ${source}/crypto.c ${source}/config.c ${source}/firmware.c \
          ${../tests/device-secret-target/firmware-fixture.c} ${../tests/device-secret-target/check.c} \
          $(pkg-config --libs jansson openssl) -o check
        python3 ${../tests/device-secret-target/test.py} ./check ${package}/bin/kaiba-device-secret-target
        ${fixture}/bin/kaiba-device-secret-target --version
        # Production binary has no synthetic transport or general firmware API.
        nm ${package}/bin/kaiba-device-secret-target > symbols
        if grep -E 'test_exchange|rpi_fw_crypto_(gen|set_key_usage)' symbols; then exit 1; fi
        mkdir -p "$out"
        cp symbols "$out/"
      '';
in
{
  inherit package fixture check;
}
