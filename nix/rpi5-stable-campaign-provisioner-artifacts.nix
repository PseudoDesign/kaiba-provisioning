{
  buildPkgs,
  lib,
  provisionerSystem,
}:

let
  developmentPosture = builtins.fromJSON (
    builtins.readFile ../policies/raspberry-pi-5-development-posture-v1alpha1.json
  );
  bootImageSizeMiB = 96;
  bootOrderPolicy = developmentPosture.boot_order.policy;
  rootDataPartitionGUID = "bdd5be20-f7ea-56e7-ae90-4465ae950596";
  rootHashPartitionGUID = "62616022-71fb-5036-8cc4-b7949cc6e52c";
  targetConfig = provisionerSystem.nixosSystem.config;
  bootCommandLinePath = "nixos/default/cmdline.txt";
  # Keep this list literal. The target profile narrows the base DTB and
  # disables optional overlays; these four overlay-directory files are the
  # only revision-matched additions required by the pinned Pi 5 kernel.
  firmwareAllowlist = [
    "config.txt"
    "nixos/default/bcm2712-rpi-5-b.dtb"
    "nixos/default/cmdline.txt"
    "nixos/default/initrd"
    "nixos/default/kernel.img"
    "nixos/default/overlays/README"
    "nixos/default/overlays/bcm2712d0.dtbo"
    "nixos/default/overlays/dwc2.dtbo"
    "nixos/default/overlays/overlay_map.dtb"
  ];
  firmwareBuildPkgs = provisionerSystem.nixosSystem.pkgs.buildPackages;
  firmwareTree =
    firmwareBuildPkgs.runCommand "kaiba-rpi5-stable-campaign-provisioner-firmware-tree"
      {
        nativeBuildInputs = with firmwareBuildPkgs; [
          coreutils
          diffutils
          findutils
        ];
        preferLocalBuild = true;
      }
      ''
        set -euo pipefail
        export LC_ALL=C
        export TZ=UTC

        mkdir -p firmware
        ${targetConfig.sdImage.populateFirmwareCommands}

        # Pi 5 loads its firmware from EEPROM. Remove the generic SD-image
        # module's Pi 1-4 boot firmware and generation-only symlinks before the
        # tree is compared with the explicit signed-image allowlist.
        rm -f -- \
          firmware/bootcode.bin \
          firmware/fixup.dat \
          firmware/fixup4.dat \
          firmware/fixup4cd.dat \
          firmware/fixup4db.dat \
          firmware/fixup4x.dat \
          firmware/fixup_cd.dat \
          firmware/fixup_db.dat \
          firmware/fixup_x.dat \
          firmware/start.elf \
          firmware/start4.elf \
          firmware/start4cd.elf \
          firmware/start4db.elf \
          firmware/start4x.elf \
          firmware/start_cd.elf \
          firmware/start_db.elf \
          firmware/start_x.elf \
          firmware/nixos/default/kernel-link \
          firmware/nixos/default/system-link

        mkdir -p firmware/nixos/default/overlays
        for revision_file in README bcm2712d0.dtbo dwc2.dtbo overlay_map.dtb; do
          source_file=${targetConfig.hardware.deviceTree.dtbSource}/overlays/"$revision_file"
          if ! test -f "$source_file"; then
            echo "Raspberry Pi kernel DTBs are missing $revision_file" >&2
            exit 1
          fi
          cp --no-preserve=mode,ownership -- \
            "$source_file" \
            firmware/nixos/default/overlays/"$revision_file"
        done

        if test -n "$(find firmware -type l -print -quit)"; then
          echo "Raspberry Pi firmware population produced a symbolic link" >&2
          exit 1
        fi
        if test -n "$(find firmware ! -type d ! -type f -print -quit)"; then
          echo "Raspberry Pi firmware population produced an unsupported filesystem object" >&2
          exit 1
        fi

        find firmware -type f -printf '%P\n' | sort > actual-files
        {
          ${lib.concatMapStringsSep "\n" (path: "printf '%s\\n' ${lib.escapeShellArg path}") (
            lib.sort builtins.lessThan firmwareAllowlist
          )}
        } > expected-files
        if ! cmp expected-files actual-files; then
          echo "Raspberry Pi firmware population differs from the explicit allowlist" >&2
          exit 1
        fi

        find firmware -exec touch --date=@315532800 '{}' +
        find firmware -type d -exec chmod 0555 '{}' +
        find firmware -type f -exec chmod 0444 '{}' +
        mkdir -p "$out"
        cp -R --no-preserve=ownership firmware/. "$out/"
      '';
  secureBootArtifactsBuilder = import ./secure-boot-artifacts.nix {
    inherit lib;
    pkgs = buildPkgs;
  };
  unsignedArtifacts = secureBootArtifactsBuilder {
    inherit
      bootCommandLinePath
      bootImageSizeMiB
      bootOrderPolicy
      firmwareAllowlist
      firmwareTree
      rootDataPartitionGUID
      rootHashPartitionGUID
      ;
    expectedCustomerKeyHash = provisionerSystem.expectedCustomerKeyHash;
    rootImage = provisionerSystem.rootImage;
    rootDeviceBinding = "rpi5-sd-card";
    sourceRevision = provisionerSystem.sourceRevision;
    name = "kaiba-rpi5-stable-campaign-provisioner-unsigned-artifacts";
  };
in
provisionerSystem
// {
  inherit
    bootCommandLinePath
    firmwareAllowlist
    firmwareTree
    rootDataPartitionGUID
    rootHashPartitionGUID
    unsignedArtifacts
    ;
}
