{
  nixosRaspberryPi,
  stableVerifierModule,
  stableVerifierPackage,
}:

{
  policy,
  rootPublicKey,
  authorityCACertificate,
  verifierVersion,
  cohortID,
  slotID,
  minimumSecurityEpoch,
  authorityURL,
  authorityKeyID,
  audience,
  logicalIdentity,
  releaseDevice ? "/dev/disk/by-partlabel/KAIBA_RELEASE",
  releaseFileSystem ? "ext4",
  networkInterface ? "end0",
  extraModules ? [ ],
}:

let
  platformRevision = "7e39508bcf9c1da82cf11c1e22f74f9d9fd0fe10";
  platformNarHash = "sha256-KT/OleUMpSKsWgi0eTuqS/0GD4ucPQcvLgmvlw8ZuCM=";
  nixosSystem = nixosRaspberryPi.lib.nixosSystem {
    modules = [
      nixosRaspberryPi.nixosModules.raspberry-pi-5.base
      stableVerifierModule
      (
        { config, lib, ... }:
        {
          boot.loader.raspberry-pi = {
            enable = true;
            # The stable verifier is the first and only Linux gate. The Pi
            # firmware loads its kernel and initramfs directly; no U-Boot or
            # FIT layer participates in this spike.
            bootloader = "kernelboot-legacy-unsupported";
            useGenerationDeviceTree = false;
          };

          # This verifier is headless and does not need the desktop-oriented
          # firmware defaults. Keeping those defaults would also make
          # config.txt refer to an overlay outside the deliberately small
          # authenticated boot tree.
          hardware.raspberry-pi.config.all = {
            options = {
              camera_auto_detect.enable = lib.mkForce false;
              display_auto_detect.enable = lib.mkForce false;
              max_framebuffers.enable = lib.mkForce false;
            };
            base-dt-params.audio.enable = lib.mkForce false;
            dt-overlays.vc4-kms-v3d.enable = lib.mkForce false;
          };
          hardware.raspberry-pi.config.cm5.dt-overlays.dwc2.enable = lib.mkForce false;

          # A complete delegated kernel plus its augmented one-boot initramfs
          # does not fit reliably in the vendor kernel's 32 MiB CMA default.
          # The experimental file-mode loader is kernel-enforced fail closed,
          # but reserve enough contiguous memory for the intended 128 MiB
          # direct-handoff envelope.
          boot.kernelParams = [ "cma=128M" ];

          # arm64 exposes the segment-based kexec_load syscall only when
          # PM_SLEEP_SMP makes ARCH_SUPPORTS_KEXEC available. The verifier
          # intentionally uses that syscall because kexec_file_load cannot
          # consume the separately authenticated device tree. The reviewed
          # vendor default enables only KEXEC_FILE, which makes the retained
          # DTB handoff fail with ENOSYS on physical Pi 5 hardware.
          boot.kernelPatches = [
            {
              name = "kaiba-rpi5-stable-verifier-kexec-load";
              patch = null;
              structuredExtraConfig = with lib.kernel; {
                SUSPEND = yes;
                KEXEC = yes;
              };
            }
            {
              # The verifier still uses legacy kexec_load by default. Keep a
              # future file-mode experiment fail closed: a successful
              # kexec_file_load must select arm64's direct, non-relocating
              # IND_DONE path rather than silently falling back to relocation.
              name = "kaiba-rpi5-stable-verifier-kexec-file-require-in-place";
              patch = ./patches/arm64-kexec-file-require-in-place.patch;
              structuredExtraConfig = with lib.kernel; {
                ARM64_KEXEC_FILE_REQUIRE_IN_PLACE = yes;
              };
            }
          ];

          fileSystems."/" = {
            device = "none";
            fsType = "tmpfs";
            options = [ "x-initrd.mount" ];
          };

          kaiba.stableVerifierSpike = {
            enable = true;
            package = stableVerifierPackage;
            inherit
              policy
              rootPublicKey
              verifierVersion
              cohortID
              slotID
              minimumSecurityEpoch
              authorityURL
              authorityCACertificate
              authorityKeyID
              audience
              logicalIdentity
              releaseDevice
              releaseFileSystem
              networkInterface
              ;
            # On the reviewed vendor kernel the NVMe, PCIe host, and macb
            # Ethernet drivers are built in. Keep NVMe explicit so a future
            # platform pin that modularizes it still copies it to the initrd.
            initrdKernelModules = [ "nvme" ];
          };

          networking.hostName = "kaiba-rpi5-stable-verifier";
          system.stateVersion = "26.05";

          assertions = [
            {
              assertion = lib.versionAtLeast config.boot.kernelPackages.kernel.version "6.18";
              message = "the stable-verifier Pi platform requires the reviewed 6.18 kernel family";
            }
          ];
        }
      )
    ]
    ++ extraModules;
  };

  firmwareTree =
    nixosSystem.pkgs.runCommand "kaiba-rpi5-stable-verifier-firmware-tree"
      {
        passthru.kaibaRpi5StableVerifierPlatform = {
          inherit platformRevision platformNarHash;
          hardwareObserved = false;
          productionReady = false;
        };
        preferLocalBuild = true;
      }
      ''
        set -euo pipefail
        readonly populated="$TMPDIR/populated"
        mkdir -p "$populated" "$out/overlays"
        ${nixosSystem.config.boot.loader.raspberry-pi.firmwarePopulateCmd} \
          -c ${nixosSystem.config.system.build.toplevel} \
          -f "$populated"

        # kernelboot's legacy deployment helper emits every vendor board DTB,
        # every overlay, generation bookkeeping, and a copied stage-2 init.
        # The stable verifier instead authenticates one immutable, initramfs-
        # only Pi 5 boot tree. Copy only the files required by that boundary.
        for file in \
          bcm2712-rpi-5-b.dtb \
          config.txt \
          initrd \
          kernel.img
        do
          install -m 0444 "$populated/$file" "$out/$file"
        done
        for file in README bcm2712d0.dtbo overlay_map.dtb; do
          install -m 0444 "$populated/overlays/$file" "$out/overlays/$file"
        done

        # The helper appends `init=<stage-2-system>/init`, but this image has
        # no stage-2 root or store. Let the kernel execute the initramfs /init
        # that NixOS already placed in the archive.
        sed -E \
          -e 's/(^|[[:space:]])init=[^[:space:]]+//g' \
          -e 's/^[[:space:]]+//' \
          -e 's/[[:space:]]+/ /g' \
          -e 's/[[:space:]]+$//' \
          "$populated/cmdline.txt" > "$out/cmdline.txt"
        test -s "$out/cmdline.txt"
        if grep -Eq '(^|[[:space:]])init=' "$out/cmdline.txt"; then
          echo "stable-verifier cmdline still selects a stage-2 init" >&2
          exit 1
        fi
      '';
in
{
  inherit
    firmwareTree
    nixosSystem
    platformNarHash
    platformRevision
    ;
  kernel = nixosSystem.config.boot.kernelPackages.kernel;
  kernelVersion = nixosSystem.config.boot.kernelPackages.kernel.version;
  firmwarePackage = nixosSystem.config.boot.loader.raspberry-pi.firmwarePackage;
}
