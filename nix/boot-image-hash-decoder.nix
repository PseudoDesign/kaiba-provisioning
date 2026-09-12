{ pkgs }:

pkgs.writeShellApplication {
  name = "kaiba-rpi5-boot-image-hash-decode";
  runtimeInputs = [ pkgs.coreutils ];
  text = ''
    set -euo pipefail
    export LC_ALL=C

    fail() {
      printf 'boot-image-hash decode: %s\n' "$1" >&2
      exit 1
    }

    if test "$#" -ne 1; then
      printf 'usage: kaiba-rpi5-boot-image-hash-decode PROPERTY\n' >&2
      exit 2
    fi

    readonly property="$1"
    test -f "$property" && test ! -L "$property" && test -r "$property" \
      || fail 'property must be one readable non-symlink regular file'
    test "$(stat --format=%s "$property")" -eq 64 \
      || fail 'property must use the pinned 64-byte firmware representation'

    property_hex="$(od -An -tx1 -v "$property" | tr -d ' \n')"
    test "''${#property_hex}" -eq 128 \
      || fail 'property did not encode to exactly 128 lowercase hex characters'
    case "$property_hex" in
      (*[!0-9a-f]*) fail 'property hex encoding is not canonical lowercase' ;;
    esac

    readonly digest_hex="''${property_hex:0:64}"
    readonly reserved_hex="''${property_hex:64:64}"
    readonly zero_reserved=0000000000000000000000000000000000000000000000000000000000000000
    test "$reserved_hex" = "$zero_reserved" \
      || fail 'property reserved suffix is not exactly 32 NUL bytes'

    printf '%s\n' "$digest_hex"
  '';
}
