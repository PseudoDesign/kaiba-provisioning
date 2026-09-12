{
  buildPlatformSystem,
  nixosRaspberryPi,
  secureBootTargetModule,
  stableCampaignGPTInspector,
}:

{
  expectedCustomerKeyHash,
  sourceRevision,
}:

let
  hostname = "kaiba-rpi5-provisioner";
  developmentSSHAuthorizedKeyPath = ../keys/codex-rpi5-development-2026-09-05.pub;
  nixosSystem = nixosRaspberryPi.lib.nixosSystem {
    trustCaches = false;
    modules = [
      nixosRaspberryPi.nixosModules.sd-image
      nixosRaspberryPi.nixosModules.raspberry-pi-5.base
      nixosRaspberryPi.nixosModules.raspberry-pi-5.page-size-16k
      nixosRaspberryPi.nixosModules.usb-gadget-ethernet
      secureBootTargetModule
      (
        {
          config,
          lib,
          modulesPath,
          pkgs,
          ...
        }:
        let
          developmentSSHAuthorizedKey = lib.removeSuffix "\n" (
            builtins.readFile developmentSSHAuthorizedKeyPath
          );
          enabledFileSystemUsesOnlyExpectedDevice =
            fileSystem:
            let
              enabled = fileSystem.enable or true;
              device = fileSystem.device or "";
            in
            !enabled
            || (
              builtins.isString device
              && builtins.elem device [
                "/dev/mapper/root"
                "tmpfs"
              ]
            );
          swapUsesNVMe =
            swap:
            let
              device = swap.device or "";
            in
            builtins.isString device && lib.hasPrefix "/dev/nvme" device;
        in
        {
          # The generic SD-image module is used only as a deterministic root
          # image and firmware-population interface. The inspected NVMe is not
          # part of this system's storage graph.
          disabledModules = [
            (modulesPath + "/profiles/base.nix")
            (modulesPath + "/profiles/all-hardware.nix")
          ];

          assertions = [
            {
              assertion = builtins.match "([0-9a-f]{40}|[0-9a-f]{64})" sourceRevision != null;
              message = "the stable-campaign provisioner source revision must be canonical lowercase hex";
            }
            {
              assertion = config.nixpkgs.hostPlatform.system == "aarch64-linux";
              message = "the stable-campaign provisioner must remain an AArch64 Raspberry Pi system";
            }
            {
              assertion = config.nixpkgs.buildPlatform.system == buildPlatformSystem;
              message = "the stable-campaign provisioner must use its selected build platform";
            }
            {
              assertion =
                stableCampaignGPTInspector.stdenv.buildPlatform.system == buildPlatformSystem
                && stableCampaignGPTInspector.stdenv.hostPlatform.system == "aarch64-linux";
              message = "the stable-campaign GPT inspector must target AArch64 from the selected build platform";
            }
            {
              assertion = builtins.elem stableCampaignGPTInspector config.environment.systemPackages;
              message = "the stable-campaign provisioner must install the read-only GPT inspector";
            }
            {
              assertion = config.networking.hostName == hostname;
              message = "the stable-campaign inspector is fixed to hostname kaiba-rpi5-provisioner";
            }
            {
              assertion = config.sdImage.compressImage == false;
              message = "the stable-campaign provisioner root filesystem image must remain uncompressed ext4";
            }
            {
              assertion = config.hardware.deviceTree.filter == "bcm2712-rpi-5-b.dtb";
              message = "the stable-campaign provisioner base-DTB set must contain only Raspberry Pi 5 Model B";
            }
            {
              assertion = config.hardware.raspberry-pi.usb-gadget-ethernet.enable;
              message = "the stable-campaign provisioner must expose its fixed development USB Ethernet lane";
            }
            {
              assertion =
                config.hardware.raspberry-pi.config.all.dt-overlays.dwc2.enable
                && config.hardware.raspberry-pi.config.all.dt-overlays.dwc2.params.dr_mode.enable
                && config.hardware.raspberry-pi.config.all.dt-overlays.dwc2.params.dr_mode.value == "peripheral";
              message = "the stable-campaign provisioner USB-C controller must remain in peripheral mode";
            }
            {
              assertion =
                !config.hardware.raspberry-pi.config.all.options.camera_auto_detect.enable
                && !config.hardware.raspberry-pi.config.all.options.display_auto_detect.enable
                && !config.hardware.raspberry-pi.config.all.options.max_framebuffers.enable
                && !config.hardware.raspberry-pi.config.all.base-dt-params.audio.enable
                && !config.hardware.raspberry-pi.config.all.dt-overlays.vc4-kms-v3d.enable;
              message = "the headless stable-campaign provisioner must not request optional firmware overlays";
            }
            {
              assertion = config.fileSystems."/".device == "/dev/mapper/root";
              message = "the stable-campaign provisioner root must remain the dm-verity mapper";
            }
            {
              assertion = lib.all enabledFileSystemUsesOnlyExpectedDevice (
                builtins.attrValues config.fileSystems
              );
              message = "the provisioner may enable only its dm-verity root and tmpfs filesystems";
            }
            {
              assertion = !(config.fileSystems ? "/boot/firmware");
              message = "the generic label-selected firmware filesystem must remain disabled";
            }
            {
              assertion = !lib.any swapUsesNVMe config.swapDevices && !config.zramSwap.enable;
              message = "the stable-campaign provisioner must not use the inspected NVMe or zram for swap";
            }
            {
              assertion = builtins.elem "systemd.gpt_auto=no" config.boot.kernelParams;
              message = "the provisioner must disable systemd GPT auto-discovery before inspecting NVMe";
            }
            {
              assertion =
                builtins.elem "nvme" config.boot.initrd.availableKernelModules
                && builtins.elem "nvme" config.boot.kernelModules;
              message = "the stable-campaign provisioner must carry and request the NVMe driver";
            }
            {
              assertion = !lib.any (parameter: lib.hasInfix "/dev/nvme" parameter) config.boot.kernelParams;
              message = "the provisioner kernel command line must not consume the inspected NVMe";
            }
            {
              assertion =
                !config.hardware.enableAllFirmware
                && !config.hardware.enableRedistributableFirmware
                && !config.hardware.wirelessRegulatoryDatabase;
              message = "the headless provisioner must not carry unrelated redistributable firmware";
            }
          ];

          kaiba.secureBootTarget = {
            enable = true;
            inherit expectedCustomerKeyHash sourceRevision;
            developmentAccess = {
              enable = true;
              authorizedKey = developmentSSHAuthorizedKey;
            };
          };

          documentation.enable = false;
          nixpkgs.buildPlatform = buildPlatformSystem;
          environment = {
            etc."machine-id" = {
              mode = "0444";
              text = "";
            };
            systemPackages = [ stableCampaignGPTInspector ];
          };
          networking = {
            hostName = hostname;
            # The fixed USB management lane is route-free and does not need a
            # resolver. resolvconf cannot mutate the immutable metadata mount.
            resolvconf.enable = false;
          };
          services.dbus.implementation = "dbus";
          nix = {
            enable = false;
            # The generic image builder still needs these two legacy commands
            # while constructing the filesystem database.
            package = pkgs.nix.nix-cli;
          };

          boot = {
            loader.raspberry-pi = {
              bootloader = "kernel";
              configurationLimit = 0;
              useGenerationDeviceTree = true;
            };
            # The inspector runs after switch-root. Keep the reviewed driver
            # explicit even though it is built into the current vendor kernel.
            initrd.availableKernelModules = [ "nvme" ];
            kernelModules = [ "nvme" ];
          };

          hardware = {
            enableAllHardware = lib.mkForce false;
            enableAllFirmware = lib.mkForce false;
            enableRedistributableFirmware = lib.mkForce false;
            firmware = lib.mkForce [ ];
            wirelessRegulatoryDatabase = lib.mkForce false;
            deviceTree.filter = "bcm2712-rpi-5-b.dtb";
            raspberry-pi = {
              usb-gadget-ethernet.enable = true;
              config.all = {
                options = {
                  camera_auto_detect.enable = lib.mkForce false;
                  display_auto_detect.enable = lib.mkForce false;
                  max_framebuffers.enable = lib.mkForce false;
                };
                base-dt-params.audio.enable = lib.mkForce false;
                dt-overlays = {
                  vc4-kms-v3d.enable = lib.mkForce false;
                  dwc2 = {
                    enable = true;
                    params.dr_mode = {
                      enable = true;
                      value = "peripheral";
                    };
                  };
                };
              };
            };
          };

          # The dedicated artifact constructor binds dm-verity to fixed SD
          # partition paths. The attached campaign NVMe remains unmounted.
          fileSystems = {
            "/" = {
              device = lib.mkForce "/dev/mapper/root";
              fsType = lib.mkForce "ext4";
            };
            # The generic SD-image module contributes a by-label, read-write
            # automount here. boot.img is already loaded into RAM, and leaving
            # this active would let an attached NVMe claim the label.
            "/boot/firmware".enable = lib.mkForce false;
          };

          image.baseName = lib.mkForce "kaiba-rpi5-stable-campaign-provisioner";
          sdImage = {
            compressImage = false;
            expandOnBoot = false;
            firmwareSize = lib.mkForce 96;
            populateRootCommands = lib.mkAfter ''
              # systemd cannot create these transfer targets after dm-verity
              # has made the real root read-only.
              mkdir -p \
                ./files/dev \
                ./files/etc \
                ./files/proc \
                ./files/root \
                ./files/run \
                ./files/sys \
                ./files/tmp \
                ./files/var
              chmod 0555 \
                ./files/dev \
                ./files/etc \
                ./files/proc \
                ./files/root \
                ./files/sys
              chmod 0755 ./files/run ./files/tmp ./files/var
            '';
            rootPartitionUUID = "4b414942-4152-4f4f-9488-888888888888";
            rootVolumeLabel = "KAIBA_ROOT";
          };

          system = {
            etc.overlay = {
              enable = true;
              mutable = false;
            };
            disableInstallerTools = true;
            stateVersion = "26.05";
            switch.enable = false;
          };

          systemd = {
            sysusers.enable = true;
            services = {
              register-nix-paths.enable = false;
              systemd-update-done.enable = false;
            };
          };
        }
      )
    ];
  };
in
{
  inherit
    developmentSSHAuthorizedKeyPath
    expectedCustomerKeyHash
    hostname
    nixosSystem
    sourceRevision
    ;
  inspectorPackage = stableCampaignGPTInspector;
  rootImage = nixosSystem.config.sdImage.rootFilesystemImage;
  system = nixosSystem.config.system.build.toplevel;
}
