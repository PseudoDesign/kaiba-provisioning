{ pkgs }:
let
  shared = ../tools/device-secret-target;
  crypto = import ./rpi5-fwcrypto.nix { inherit pkgs; };
  static = pkgs.pkgsStatic;
  jansson = static.jansson.overrideAttrs (old: {
    env = (old.env or { }) // {
      NIX_CFLAGS_COMPILE = "-Djson_object_get=kaiba_jansson_object_get";
    };
  });
  helper = static.stdenv.mkDerivation {
    pname = "kaiba-enrollment-storage";
    version = "0.1.0";
    src = ../tools/enrollment-storage;
    nativeBuildInputs = [ pkgs.pkg-config ];
    buildInputs = [
      jansson
      static.openssl
      static.cryptsetup
      static.lvm2
      static.e2fsprogs
    ];
    fixtureFlags = "";
    fixtureSource = "";
    dontStrip = true; # Preserve the exact pinned tool bytes in the portable bundle.
    buildPhase = ''
      mkdir -p libexec
      cp ${static.e2fsprogs.bin}/bin/mke2fs libexec/mke2fs
      cp ${static.e2fsprogs.bin}/bin/e2fsck libexec/e2fsck
      chmod 0555 libexec/*
      printf '#define MKFS_SHA256 "%s"\n#define FSCK_SHA256 "%s"\n' \
        "$(sha256sum libexec/mke2fs | cut -d' ' -f1)" \
        "$(sha256sum libexec/e2fsck | cut -d' ' -f1)" > tool-digests.h
      $CC -std=c11 -Wall -Wextra -Werror -O2 -static -ffunction-sections -fdata-sections \
        -Djson_object_get=kaiba_jansson_object_get \
        $fixtureFlags $(pkg-config --cflags jansson openssl libcryptsetup devmapper ext2fs) \
        -I${crypto.library}/include -I${shared} main.c \
        ${shared}/config.c ${shared}/crypto.c ${shared}/firmware.c ${shared}/runtime.c ${shared}/storage.c \
        $fixtureSource -Wl,--gc-sections \
        $(pkg-config --libs --static jansson openssl libcryptsetup devmapper) \
        -o kaiba-enrollment-storage
    '';
    installPhase = ''
      install -Dm0555 kaiba-enrollment-storage "$out/bin/kaiba-enrollment-storage"
      install -Dm0555 libexec/mke2fs "$out/libexec/mke2fs"
      install -Dm0555 libexec/e2fsck "$out/libexec/e2fsck"
    '';
    meta.mainProgram = "kaiba-enrollment-storage";
  };
  fixture = helper.overrideAttrs (_: {
    pname = "kaiba-enrollment-storage-test-firmware";
    fixtureFlags = "-DKAIBA_TESTING";
    fixtureSource = ../tests/device-secret-storage-development/firmware-fixture.c;
  });
  check =
    pkgs.runCommand "kaiba-enrollment-storage-check"
      {
        nativeBuildInputs = [ pkgs.binutils ];
      }
      ''
        ${helper}/bin/kaiba-enrollment-storage --version > version
        for exe in ${helper}/bin/* ${helper}/libexec/*; do
          readelf -l "$exe" > segments
          ! grep -q INTERP segments
          readelf -d "$exe" > dynamic
          ! grep -q NEEDED dynamic
        done
        nm ${helper}/bin/kaiba-enrollment-storage > symbols
        ! grep -E 'test_exchange|fw_raw_read|fw_legacy_read|fw_sign|rpi_fw_crypto_(gen|set_key_usage)' symbols
        mkdir -p "$out"
        cp version symbols "$out/"
      '';
in
{
  inherit helper fixture check;
}
