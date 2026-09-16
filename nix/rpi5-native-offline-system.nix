{ nixosRaspberryPi, secureBootTargetModule }:
{ expectedCustomerKeyHash, sourceRevision }:

let
  hostname = "kaiba-rpi5-offline";
  nixosSystem = nixosRaspberryPi.lib.nixosSystem {
    trustCaches = false;
    modules = [
      nixosRaspberryPi.nixosModules.sd-image
      nixosRaspberryPi.nixosModules.raspberry-pi-5.base
      secureBootTargetModule
      ./modules/native-offline-evidence.nix
      (
        {
          config,
          lib,
          modulesPath,
          pkgs,
          ...
        }:
        {
          # Reuse only the image builder's ext4/firmware construction interface.
          # Normal boot is NVMe; the independent SD provisioner is unchanged.
          disabledModules = [
            (modulesPath + "/profiles/base.nix")
            (modulesPath + "/profiles/all-hardware.nix")
          ];
          assertions = [
            {
              assertion = builtins.match "[0-9a-f]{40}" sourceRevision != null;
              message = "the offline candidate requires a canonical source revision";
            }
            {
              assertion =
                config.nixpkgs.buildPlatform.system == "aarch64-linux"
                && config.nixpkgs.hostPlatform.system == "aarch64-linux";
              message = "offline Pi artifacts must be built natively on ARM64";
            }
            {
              assertion =
                !config.kaiba.secureBootTarget.developmentAccess.enable
                && !config.services.openssh.enable
                && !config.services.timesyncd.enable;
              message = "the offline candidate must not enable development access or network time";
            }
          ];
          kaiba.secureBootTarget = {
            enable = true;
            inherit expectedCustomerKeyHash sourceRevision;
            developmentAccess.enable = false;
          };
          nixpkgs.buildPlatform = "aarch64-linux";
          nixpkgs.overlays = lib.mkBefore [
            (
              final: prev:
              lib.optionalAttrs prev.stdenv.hostPlatform.isAarch64 (
                nixosRaspberryPi.overlays.jemalloc-page-size-16k final prev
              )
            )
          ];
          documentation.enable = false;
          environment.etc."machine-id" = {
            mode = "0444";
            text = "";
          };
          networking = {
            hostName = hostname;
            resolvconf.enable = false;
            useDHCP = lib.mkForce false;
            useNetworkd = lib.mkForce false;
            networkmanager.enable = lib.mkForce false;
            wireless.enable = lib.mkForce false;
          };
          services = {
            dbus.implementation = "dbus";
            timesyncd.enable = lib.mkForce false;
            chrony.enable = lib.mkForce false;
            ntp.enable = lib.mkForce false;
            openssh.enable = lib.mkForce false;
          };
          nix = {
            enable = false;
            package = pkgs.nix.nix-cli;
          };
          boot = {
            loader.raspberry-pi = {
              bootloader = "kernel";
              configurationLimit = 0;
              useGenerationDeviceTree = true;
            };
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
            raspberry-pi.config.all = {
              options = {
                camera_auto_detect.enable = lib.mkForce false;
                display_auto_detect.enable = lib.mkForce false;
                max_framebuffers.enable = lib.mkForce false;
              };
              base-dt-params.audio.enable = lib.mkForce false;
              dt-overlays.vc4-kms-v3d.enable = lib.mkForce false;
            };
          };
          fileSystems = {
            "/" = {
              device = lib.mkForce "/dev/mapper/root";
              fsType = lib.mkForce "ext4";
            };
            "/boot/firmware".enable = lib.mkForce false;
          };
          image.baseName = lib.mkForce "kaiba-rpi5-native-offline";
          sdImage = {
            compressImage = false;
            expandOnBoot = false;
            firmwareSize = lib.mkForce 96;
            populateRootCommands = lib.mkAfter ''
              mkdir -p ./files/{dev,etc,proc,root,run,sys,tmp,var}
              chmod 0555 ./files/{dev,etc,proc,root,sys}
              chmod 0755 ./files/{run,tmp,var}
              # A regular, non-sparse file with dedicated ext4 blocks. Startup
              # must not read it before the explicit late-read evidence step.
              cp ${config.system.build.kaibaOfflineProbe} ./files/kaiba-offline-read-probe
              chmod 0444 ./files/kaiba-offline-read-probe
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
            network.wait-online.enable = lib.mkForce false;
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
    hostname
    nixosSystem
    sourceRevision
    expectedCustomerKeyHash
    ;
  rootImage = nixosSystem.config.sdImage.rootFilesystemImage;
  system = nixosSystem.config.system.build.toplevel;
}
