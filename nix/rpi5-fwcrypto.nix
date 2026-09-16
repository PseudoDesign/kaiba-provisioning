{ pkgs }:
let
  revision = "292dbe7e35296e556d839a0b9ae2ca957ac8c961";
  library = pkgs.stdenv.mkDerivation {
    pname = "kaiba-rpifwcrypto";
    version = "2026-07-24";
    src = pkgs.fetchFromGitHub {
      owner = "raspberrypi";
      repo = "utils";
      rev = revision;
      hash = "sha256-8F4dJDsYqiJWBYqfVHKPpYgATQQM5QohcxhtJ7EQH3o=";
    };
    sourceRoot = "source/rpifwcrypto";
    nativeBuildInputs = [ pkgs.cmake ];
    buildInputs = [ pkgs.gnutls ];
    # Build the library and upstream CLI explicitly. The platform's general
    # raspberrypi-utils package can silently omit this subdirectory.
    postInstall = ''
      test -x "$out/bin/rpi-fw-crypto"
      test -f "$out/include/rpifwcrypto.h"
      test -e "$out/lib/librpifwcrypto.so"
    '';
    meta = {
      platforms = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      license = pkgs.lib.licenses.bsd3;
    };
  };
  probe = pkgs.stdenv.mkDerivation {
    pname = "kaiba-device-secret-capabilities";
    version = "0.1.0";
    src = ../tools/device-secret-capabilities;
    buildInputs = [ library ];
    buildPhase = ''
      $CC -std=c11 -Wall -Wextra -Werror -O2 \
        -DFWCRYPTO_REVISION='"${revision}"' main.c -lrpifwcrypto \
        -o kaiba-device-secret-capabilities
    '';
    installPhase = ''
      install -Dm0555 kaiba-device-secret-capabilities "$out/bin/kaiba-device-secret-capabilities"
    '';
  };
in
{
  inherit revision library probe;
}
