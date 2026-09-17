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
    $CC -std=c11 -Wall -Wextra -Werror -I${crypto.library}/include \
      -DPROBE_NAME='"kaiba-device-secret-metadata"' \
      -DPROBE_TRANSPORT='"vcio-metadata-only"' \
      ${../tools/device-secret-capabilities/main.c} \
      ${../tools/device-secret-capabilities/metadata.c} \
      ${./device-secret-capabilities/mailbox-stub.c} \
      -Wl,--wrap=geteuid,--wrap=open,--wrap=fstat,--wrap=close,--wrap=ioctl -o metadata-probe
    python3 ${./device-secret-capabilities/test_mailbox.py} ./metadata-probe
    ${crypto.probe}/bin/kaiba-device-secret-metadata --version
    # This companion has no runtime library dependency or general crypto CLI.
    readelf -l ${crypto.probe}/bin/kaiba-device-secret-metadata > segments
    if grep -q INTERP segments; then echo "metadata probe is not static" >&2; exit 1; fi
    readelf -d ${crypto.probe}/bin/kaiba-device-secret-metadata > dynamic
    if grep -q NEEDED dynamic; then echo "metadata probe links a shared library" >&2; exit 1; fi
    nm --defined-only ${crypto.probe}/bin/kaiba-device-secret-metadata | \
      awk '$3 ~ /^rpi_fw_crypto_/ {print $3}' | sort > metadata-actual
    diff -u expected metadata-actual
    mkdir -p "$out"
    cp actual "$out/allowed-api-imports.txt"
  ''
