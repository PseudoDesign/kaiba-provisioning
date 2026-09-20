{ pkgs }:
let
  crypto = import ./rpi5-fwcrypto.nix { inherit pkgs; };
  shared = ../tools/device-secret-target;
  static = pkgs.pkgsStatic;
  # libcryptsetup brings json-c. Its json_object_get symbol collides with
  # Jansson only when statically linked. Rename Jansson's symbol consistently
  # in this private library and its callers; shared qualification builds retain
  # their original dependencies and ABI.
  jansson = static.jansson.overrideAttrs (old: {
    env = (old.env or { }) // {
      NIX_CFLAGS_COMPILE = "-Djson_object_get=kaiba_jansson_object_get";
    };
  });
  helper = static.stdenv.mkDerivation {
    pname = "kaiba-device-secret-storage-development";
    version = "0.1.0";
    src = ../tools/device-secret-storage-development;
    nativeBuildInputs = [ pkgs.pkg-config ];
    buildInputs = [
      jansson
      static.openssl
      static.cryptsetup
      static.lvm2
    ];
    buildPhase = ''
      $CC -std=c11 -Wall -Wextra -Werror -O2 -static -ffunction-sections -fdata-sections \
        -Djson_object_get=kaiba_jansson_object_get \
        $fixtureFlags $(pkg-config --cflags jansson openssl libcryptsetup devmapper) \
        -I${crypto.library}/include -I${shared} main.c \
        ${shared}/config.c ${shared}/crypto.c ${shared}/firmware.c ${shared}/runtime.c ${shared}/storage.c \
        $fixtureSource -Wl,--gc-sections \
        $(pkg-config --libs --static jansson openssl libcryptsetup devmapper) \
        -o kaiba-device-secret-storage-development
    '';
    fixtureFlags = "";
    fixtureSource = "";
    installPhase = ''
      install -Dm0555 kaiba-device-secret-storage-development "$out/bin/kaiba-device-secret-storage-development"
    '';
    meta.mainProgram = "kaiba-device-secret-storage-development";
  };
  fixture = helper.overrideAttrs (_: {
    pname = "kaiba-device-secret-storage-development-test-firmware";
    fixtureFlags = "-DKAIBA_TESTING";
    fixtureSource = ../tests/device-secret-storage-development/firmware-fixture.c;
  });
  scripts = pkgs.runCommand "kaiba-device-secret-storage-development-scripts" { } ''
    mkdir -p "$out"
    cp ${../scripts/device-secret/storage_development.py} "$out/storage_development.py"
    cp ${../scripts/device-secret/development.py} "$out/development.py"
    cp ${../scripts/device-secret/runner.py} "$out/runner.py"
  '';
  package = pkgs.writeShellApplication {
    name = "kaiba-device-secret-storage-session";
    runtimeInputs = [ pkgs.openssh ];
    text = ''
      exec ${pkgs.python3}/bin/python3 -I -c \
        'import runpy, sys; sys.path.insert(0, "${scripts}"); runpy.run_module("storage_development", run_name="__main__")' "$@"
    '';
  };
  check =
    pkgs.runCommand "kaiba-device-secret-storage-development-check"
      {
        nativeBuildInputs = [
          pkgs.python3
          pkgs.binutils
        ];
      }
      ''
        export KAIBA_DEVELOPMENT_SCRIPTS=${scripts}
        export KAIBA_STORAGE_HELPER=${helper}/bin/kaiba-device-secret-storage-development
        python3 -B -m unittest discover -s ${../tests/device-secret-storage-development} -p 'test_*.py' -v
        ${package}/bin/kaiba-device-secret-storage-session --help > help.txt
        ${fixture}/bin/kaiba-device-secret-storage-development --version > fixture.txt
        readelf -l "$KAIBA_STORAGE_HELPER" > segments
        ! grep -q INTERP segments
        readelf -d "$KAIBA_STORAGE_HELPER" > dynamic
        ! grep -q NEEDED dynamic
        nm "$KAIBA_STORAGE_HELPER" > symbols
        ! grep -E 'test_exchange|fw_raw_read|fw_legacy_read|fw_sign|rpi_fw_crypto_(gen|set_key_usage)' symbols
        mkdir -p "$out"
        cp help.txt fixture.txt segments dynamic symbols "$out/"
      '';
in
{
  inherit
    helper
    fixture
    package
    check
    ;
}
