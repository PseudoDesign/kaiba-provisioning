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
  kexecMode ? "legacy-explicit-dtb",
  releaseDevice ? "/dev/disk/by-partlabel/KAIBA_RELEASE",
  releaseFileSystem ? "ext4",
  networkInterface ? "end0",
  extraModules ? [ ],
}:

let
  supportedKexecModes = [
    "legacy-explicit-dtb"
    "experimental-file-live-fdt"
  ];
  validatedKexecMode =
    if !builtins.isString kexecMode then
      throw "stable-verifier hardware kexecMode must be a string"
    else if !(builtins.elem kexecMode supportedKexecModes) then
      throw "stable-verifier hardware kexecMode must be legacy-explicit-dtb or experimental-file-live-fdt"
    else
      kexecMode;
  usesLegacyExplicitDeviceTree = validatedKexecMode == "legacy-explicit-dtb";
  firmwareTreeName =
    if usesLegacyExplicitDeviceTree then
      "kaiba-rpi5-stable-verifier-firmware-tree"
    else
      "kaiba-rpi5-stable-verifier-file-live-fdt-hardware-candidate-firmware-tree";
  firmwareOverlayFiles = [
    "README"
    "bcm2712d0.dtbo"
    "overlay_map.dtb"
  ]
  ++ (if usesLegacyExplicitDeviceTree then [ ] else [ "dwc2.dtbo" ]);
  # The pinned nixos-raspberrypi v6.18.34 bundle selects the upstream
  # raspberrypi/firmware 1.20260521 tag.  That tag is the lightweight tag for
  # this commit; expose the commit separately from the platform-source pin so
  # physical evidence never has to infer or invent firmware provenance.
  firmwareRevision = "09267f5354d40519d82fbd2193b9e211ec304055";
  platformRevision = "7e39508bcf9c1da82cf11c1e22f74f9d9fd0fe10";
  platformNarHash = "sha256-KT/OleUMpSKsWgi0eTuqS/0GD4ucPQcvLgmvlw8ZuCM=";
  nixosSystem = nixosRaspberryPi.lib.nixosSystem {
    modules = [
      nixosRaspberryPi.nixosModules.raspberry-pi-5.base
      stableVerifierModule
      (
        { config, lib, ... }:
        let
          verifierConfig = config.kaiba.stableVerifierSpike;
          verifierService = config.boot.initrd.systemd.services.kaiba-stable-verifier;
          verifierExecStart = verifierService.serviceConfig.ExecStart;
          fileModePatchCount = lib.count (
            patch:
            patch.name == "kaiba-rpi5-stable-verifier-kexec-file-require-in-place"
            && (patch.patch or null) != null
            && toString patch.patch == toString ./patches/arm64-kexec-file-require-in-place.patch
            && (patch.structuredExtraConfig.ARM64_KEXEC_FILE_REQUIRE_IN_PLACE or null) == lib.kernel.yes
          ) config.boot.kernelPatches;
        in
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
            dt-overlays = {
              vc4-kms-v3d.enable = lib.mkForce false;
            }
            // lib.optionalAttrs (!usesLegacyExplicitDeviceTree) {
              # File/live-FDT handoff passes this firmware-resolved tree to
              # the released development OS. Keep its fixed USB gadget
              # management lane present so post-handoff evidence can be
              # collected without widening the verifier's DHCP-only RP1
              # Ethernet policy.
              dwc2 = {
                enable = true;
                params.dr_mode = {
                  enable = true;
                  value = "peripheral";
                };
              };
            };
          };
          hardware.raspberry-pi.config.cm5.dt-overlays.dwc2.enable = lib.mkForce false;

          # A complete delegated kernel plus its augmented one-boot initramfs
          # does not fit reliably in the vendor kernel's 32 MiB CMA default.
          # Reserve exactly the reviewed 128 MiB direct-handoff envelope.
          boot.kernelParams = [ "cma=128M" ];

          # Keep segment-based kexec_load available only for the generic
          # constructor's legacy default. The file/live-FDT hardware candidate
          # uses the vendor's KEXEC_FILE support and cannot hand a userspace
          # device tree to the next kernel.
          boot.kernelPatches =
            lib.optional usesLegacyExplicitDeviceTree {
              name = "kaiba-rpi5-stable-verifier-kexec-load";
              patch = null;
              structuredExtraConfig = with lib.kernel; {
                SUSPEND = yes;
                KEXEC = yes;
              };
            }
            ++ [
              {
                # File mode must select arm64's direct, non-relocating IND_DONE
                # path rather than silently falling back to relocation. Keep the
                # reviewed patch present in both modes so selecting file mode at
                # the typed module boundary cannot weaken this kernel policy.
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
            kexecMode = validatedKexecMode;
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
            {
              assertion = verifierConfig.kexecMode == validatedKexecMode;
              message = "the stable-verifier Pi platform handoff mode must match the hardware constructor selection";
            }
          ]
          ++ lib.optionals (!usesLegacyExplicitDeviceTree) [
            {
              assertion =
                lib.count (parameter: parameter == "cma=128M") config.boot.kernelParams == 1
                && lib.all (
                  parameter: !(lib.hasPrefix "cma=" parameter) || parameter == "cma=128M"
                ) config.boot.kernelParams;
              message = "the file/live-FDT stable-verifier Pi platform requires exactly cma=128M";
            }
            {
              assertion = fileModePatchCount == 1;
              message = "the file/live-FDT stable-verifier Pi platform requires the exact reviewed in-place kexec patch";
            }
            {
              assertion = verifierConfig.networkInterface == "end0";
              message = "the file/live-FDT stable-verifier Pi platform requires the RP1 end0 authorization interface";
            }
            {
              assertion =
                verifierService.serviceConfig.CapabilityBoundingSet == [ "CAP_SYS_BOOT" ]
                && verifierService.serviceConfig.AmbientCapabilities == [ "CAP_SYS_BOOT" ];
              message = "the file/live-FDT stable-verifier service requires only CAP_SYS_BOOT";
            }
            {
              assertion =
                lib.hasInfix ''"--kexec-mode" "experimental-file-live-fdt"'' verifierExecStart
                && !(lib.hasInfix "--dtb" verifierExecStart)
                && !(lib.hasInfix "--device-tree" verifierExecStart);
              message = "the file/live-FDT stable-verifier service must select file mode without a userspace DTB argument";
            }
            {
              assertion =
                config.hardware.raspberry-pi.config.all.dt-overlays.dwc2.enable
                && config.hardware.raspberry-pi.config.all.dt-overlays.dwc2.params.dr_mode.enable
                && config.hardware.raspberry-pi.config.all.dt-overlays.dwc2.params.dr_mode.value == "peripheral";
              message = "the file/live-FDT stable-verifier Pi platform requires the dwc2 peripheral overlay";
            }
          ];
        }
      )
    ]
    ++ extraModules;
  };

  firmwareTree =
    nixosSystem.pkgs.runCommand firmwareTreeName
      {
        passthru.kaibaRpi5StableVerifierPlatform = {
          inherit firmwareRevision platformRevision platformNarHash;
          kexecMode = validatedKexecMode;
          liveFirmwareDeviceTreeHandoff = !usesLegacyExplicitDeviceTree;
          userspaceDeviceTreeHandoff = usesLegacyExplicitDeviceTree;
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
        for file in ${builtins.concatStringsSep " " firmwareOverlayFiles}; do
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
    firmwareRevision
    nixosSystem
    platformNarHash
    platformRevision
    ;
  kexecMode = validatedKexecMode;
  kernel = nixosSystem.config.boot.kernelPackages.kernel;
  kernelVersion = nixosSystem.config.boot.kernelPackages.kernel.version;
  firmwarePackage = nixosSystem.config.boot.loader.raspberry-pi.firmwarePackage;
}
