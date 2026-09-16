{ pkgs, crypto }:
pkgs.runCommand "kaiba-device-secret-capabilities-check"
  {
    nativeBuildInputs = [
      pkgs.stdenv.cc
      pkgs.python3
      pkgs.binutils
    ];
  }
  ''
    set -euo pipefail
    $CC -std=c11 -Wall -Wextra -Werror -I${crypto.library}/include \
      ${../tools/device-secret-capabilities/main.c} ${./device-secret-capabilities/stub.c} -o probe
    python3 ${./device-secret-capabilities/test.py} ./probe
    ${crypto.probe}/bin/kaiba-device-secret-capabilities --version
    # Ensure the actual dynamic binary only imports the three allowed APIs.
    nm -D ${crypto.probe}/bin/kaiba-device-secret-capabilities | \
      awk '/ U rpi_fw_crypto_/ {print $2}' | sort > actual
    printf '%s\n' rpi_fw_crypto_get_key_status rpi_fw_crypto_get_key_usage rpi_fw_crypto_get_num_otp_keys > expected
    diff -u expected actual
    mkdir -p "$out"
    cp actual "$out/allowed-api-imports.txt"
  ''
