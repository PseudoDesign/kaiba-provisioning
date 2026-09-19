{ pkgs, lib }:
let
  root = import ../nix/reproducible-ext4-image.nix {
    inherit lib;
    image = pkgs.callPackage (pkgs.path + "/nixos/lib/make-ext4-fs.nix") {
      storePaths = [ ];
      volumeLabel = "KAIBA_TEST";
      uuid = "4b414942-4152-4f4f-9488-888888888888";
      populateImageCommands = ''
        mkdir -p ./files/etc
        printf '%s\n' 'synthetic reproducibility fixture' > ./files/etc/fixture
      '';
    };
  };
  first = root.overrideAttrs { name = "kaiba-reproducible-root-first.img"; };
  second = root.overrideAttrs (old: {
    name = "kaiba-reproducible-root-second.img";
    # Force independent builds at different wall-clock times. No actual
    # device or foreign-architecture execution is involved on either runner.
    buildCommand = ''
      test -s ${first}
      sleep 2
    ''
    + old.buildCommand;
  });
in
pkgs.runCommand "kaiba-reproducible-ext4-image-check" { nativeBuildInputs = [ pkgs.e2fsprogs ]; } ''
  cmp ${first} ${second}
  e2fsck -fn ${first}
  e2fsck -fn ${second}
  debugfs -R 'cat /etc/fixture' ${first} > contents
  printf '%s\n' 'synthetic reproducibility fixture' > expected
  cmp contents expected
  mkdir "$out"
  sha256sum ${first} ${second} > "$out/hashes.txt"
  dumpe2fs -h ${first} > "$out/header.txt"
''
