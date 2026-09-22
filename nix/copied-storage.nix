{ pkgs }:
let
  storage = import ./device-secret-storage-development.nix { inherit pkgs; };
  helper = storage.helper.overrideAttrs (old: {
    pname = "kaiba-copied-storage";
    src = ../tools/copied-storage;
    buildPhase =
      builtins.replaceStrings
        [ "${../tools/device-secret-target}/storage.c " "kaiba-device-secret-storage-development" ]
        [ "" "kaiba-copied-storage" ]
        old.buildPhase;
    installPhase = ''
      install -Dm0555 kaiba-copied-storage "$out/bin/kaiba-copied-storage"
    '';
    meta.mainProgram = "kaiba-copied-storage";
  });
  fixture = helper.overrideAttrs (_: {
    pname = "kaiba-copied-storage-test-firmware";
    fixtureFlags = "-DKAIBA_TESTING";
    fixtureSource = ../tests/copied-storage/firmware-fixture.c;
  });
  cleanupFixture = helper.overrideAttrs (old: {
    pname = "kaiba-copied-storage-loop-cleanup-test";
    buildPhase = ''
      cp ${../tests/copied-storage/loop-cleanup.c} loop-cleanup.c
    ''
    + builtins.replaceStrings [ " main.c " ] [ " loop-cleanup.c " ] old.buildPhase;
  });
  python = pkgs.python3.withPackages (p: [ p.cryptography ]);
  assessor = pkgs.writeShellApplication {
    name = "kaiba-copied-storage-assess";
    text = ''
      exec ${python}/bin/python3 -I -B ${../scripts/device-secret/copied_storage.py} "$@"
    '';
  };
  check =
    pkgs.runCommand "kaiba-copied-storage-check"
      {
        nativeBuildInputs = [
          python
          pkgs.binutils
        ];
      }
      ''
        export KAIBA_COMPARISON_HELPER=${helper}/bin/kaiba-copied-storage
        export KAIBA_COMPARISON_ASSESSOR=${../scripts/device-secret/copied_storage.py}
        python3 -B -m unittest discover -s ${../tests/copied-storage} -p 'test_*.py' -v
        readelf -l "$KAIBA_COMPARISON_HELPER" > segments
        ! grep -q INTERP segments
        nm "$KAIBA_COMPARISON_HELPER" > symbols
        ! grep -E 'test_exchange|fw_raw_read|fw_legacy_read|fw_sign|storage_intent|storage_complete|rpi_fw_crypto_(gen|set_key_usage)' symbols
        ${assessor}/bin/kaiba-copied-storage-assess --help > help.txt
        mkdir -p "$out"
        cp segments symbols help.txt "$out/"
      '';
in
{
  inherit
    helper
    fixture
    cleanupFixture
    assessor
    check
    ;
}
