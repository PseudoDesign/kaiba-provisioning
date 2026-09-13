{ pkgs }:

let
  decoder = import ../nix/boot-image-hash-decoder.nix { inherit pkgs; };
in
pkgs.runCommand "kaiba-rpi5-boot-image-hash-decoder-check"
  {
    nativeBuildInputs = [
      decoder
      pkgs.coreutils
      pkgs.xxd
    ];
  }
  ''
    set -euo pipefail
    export LC_ALL=C

    readonly digest=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
    printf '%s' "$digest" | xxd -r -p > property
    head --bytes=32 /dev/zero >> property
    test "$(stat --format=%s property)" -eq 64
    test "$(kaiba-rpi5-boot-image-hash-decode property)" = "$digest"

    expect_rejected() {
      local candidate="$1"
      set +e
      kaiba-rpi5-boot-image-hash-decode "$candidate" > rejected.stdout 2> rejected.stderr
      local status="$?"
      set -e
      test "$status" -eq 1
      test ! -s rejected.stdout
      test -s rejected.stderr
    }

    printf '%s' "$digest" | xxd -r -p > raw-only
    expect_rejected raw-only

    printf '%s' "$digest" > ascii-hex
    expect_rejected ascii-hex

    printf '%s\0' "$digest" > ascii-hex-nul
    expect_rejected ascii-hex-nul

    head --bytes=63 property > short-property
    expect_rejected short-property

    cp property long-property
    printf '\0' >> long-property
    expect_rejected long-property

    cp property nonzero-reserved
    printf '\1' | dd of=nonzero-reserved bs=1 seek=63 conv=notrunc status=none
    expect_rejected nonzero-reserved

    ln -s property property-link
    expect_rejected property-link

    set +e
    kaiba-rpi5-boot-image-hash-decode > usage.stdout 2> usage.stderr
    usage_status="$?"
    set -e
    test "$usage_status" -eq 2
    test ! -s usage.stdout
    grep -Fx 'usage: kaiba-rpi5-boot-image-hash-decode PROPERTY' usage.stderr

    mkdir "$out"
    touch "$out/passed"
  ''
