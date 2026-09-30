{ raspberrypi, fleet }:
let
  rpi = raspberrypi;
  runtimes = import ./runtime.nix {
    inherit fleet;
    system = "aarch64-linux";
  };
  runtime = runtimes.pkgs;
  inherit (runtimes) python settings;
  targetSource = runtime.lib.fileset.toSource {
    root = ./.;
    fileset = runtime.lib.fileset.unions [
      ./target.py
      ./campaign.py
    ];
  };
  tools = runtime.writeShellApplication {
    name = "kaiba-qualify";
    runtimeInputs = [
      python
      runtime.coreutils
      runtime.util-linux
      runtime.systemd
      runtime.openssh
      runtime.iproute2
      runtime.nftables
      runtime.e2fsprogs
      runtime.gnutar
      runtime.openssl
    ];
    text = ''exec ${python}/bin/python3 -I -B ${targetSource}/target.py --settings ${settings} "$@"'';
  };
  target = rpi.lib.nixosSystem {
    trustCaches = false;
    modules = [
      rpi.nixosModules.sd-image
      rpi.nixosModules.raspberry-pi-5.base
      rpi.nixosModules.raspberry-pi-5.page-size-16k
      rpi.nixosModules.raspberry-pi-5.display-vc4
      (fleet + "/nix/spiffe/pilot.nix")
      (
        {
          config,
          lib,
          pkgs,
          modulesPath,
          ...
        }:
        {
          disabledModules = [ (modulesPath + "/profiles/all-hardware.nix") ];
          nixpkgs.buildPlatform = "aarch64-linux";
          system.stateVersion = "26.05";
          networking.hostName = "kaiba-nvme-test";
          networking.useDHCP = true;
          networking.wireless.enable = false;
          networking.networkmanager.enable = false;
          networking.firewall.allowedTCPPorts = [ 22 ];
          boot.blacklistedKernelModules = [
            "brcmfmac"
            "bluetooth"
            "btusb"
          ];
          boot.loader.raspberry-pi = {
            bootloader = "kernel";
            configurationLimit = 0;
          };
          boot.initrd.systemd.enable = false;
          boot.supportedFilesystems = lib.mkForce [
            "ext4"
            "vfat"
            "overlay"
          ];
          boot.initrd.availableKernelModules = [
            "nvme"
            "overlay"
          ];
          boot.initrd.postMountCommands = lib.mkAfter ''
            # The lower filesystem is never writable in the test installation.
            mkdir -p /mnt-lower /mnt-overlay
            mount --move /mnt-root /mnt-lower
            mount -t tmpfs -o mode=0755 tmpfs /mnt-overlay
            mkdir /mnt-overlay/upper /mnt-overlay/work
            mount -t overlay overlay -o lowerdir=/mnt-lower,upperdir=/mnt-overlay/upper,workdir=/mnt-overlay/work /mnt-root
            # Stage 1 moves /run into the new root after this hook.
            mkdir -p /run/qualification-lower /run/qualification-overlay
            mount --move /mnt-lower /run/qualification-lower
            mount --move /mnt-overlay /run/qualification-overlay
          '';
          hardware.raspberry-pi.config.all.base-dt-params.pciex1 = {
            enable = true;
            value = "on";
          };
          fileSystems."/" = {
            device = lib.mkForce "/dev/disk/by-label/KAIBA_Q_ROOT";
            fsType = "ext4";
            options = lib.mkForce [ "ro" ];
          };
          fileSystems."/boot/firmware".options = lib.mkForce [
            "ro"
            "noauto"
          ];
          fileSystems."/srv/qualification" = {
            device = "/dev/disk/by-label/KAIBA_Q_DATA";
            fsType = "ext4";
            options = [
              "nodev"
              "nosuid"
              "nofail"
              "x-systemd.device-timeout=15s"
            ];
            autoResize = false;
          };
          fileSystems."/var/lib/kaiba" = {
            device = "/srv/qualification/identity";
            fsType = "none";
            options = [
              "bind"
              "nofail"
              "x-systemd.requires=srv-qualification.mount"
            ];
          };
          swapDevices = [ ];
          environment.systemPackages = [
            tools
            python
            runtime.postgresql_18
            pkgs.jq
            pkgs.sqlite
            pkgs.age
            pkgs.e2fsprogs
            pkgs.util-linux
          ];
          environment.etc."kaiba-qualification-image".text = "kaiba.nvme-qualification/v1\n";
          environment.etc."tmpfiles.d/sys-kernel-debug.conf".text = "d! /sys/kernel/debug 0700 root root -\n";
          environment.etc."qualification-runtime.json".source = settings;
          services.openssh = {
            enable = true;
            settings = {
              PasswordAuthentication = false;
              KbdInteractiveAuthentication = false;
              PermitRootLogin = "prohibit-password";
            };
            hostKeys = [
              {
                path = "/srv/qualification/ssh/ssh_host_ed25519_key";
                type = "ed25519";
              }
            ];
          };
          # Physical-console root access is intentional on this disposable image.
          services.getty.autologinUser = "root";
          users.users.root.openssh.authorizedKeys.keys = [
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG/QadjZNM/w3a69dh8kwRuG+FIODgrkFEqqhltfyGP3 codex-remote@malak"
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJMjtOqSWLDq79t/9XljmBrfBVm8deQJdOQmTV7c45Ni adam@malak"
          ];
          users.groups.qualification = { };
          users.users.qualification = {
            isSystemUser = true;
            group = "qualification";
          };
          services.kaiba.identity = {
            trustDomain = "nvme-qualification.kaiba.test";
            role = "standalone";
            serverPackage = runtime.spire.server;
            agentPackage = runtime.spire.agent;
            pilot = {
              enable = true;
              logicalDeviceID = "ace-test";
              instanceID = "disposable-nvme";
              probePackage = fleet.packages.aarch64-linux.spiffe-probe;
              pythonPackage = python;
              requireSynchronizedClock = true;
              workloadTTLSeconds = 60;
            };
          };
          systemd.services =
            lib.genAttrs
              [
                "spire-server"
                "spire-agent"
                "kaiba-identity-pilot-initialize"
                "kaiba-identity-pilot-bundle"
                "kaiba-identity-pilot-probe"
              ]
              (_: {
                requires = [ "var-lib-kaiba.mount" ];
                after = [ "var-lib-kaiba.mount" ];
              })
            // {
              # fstab describes the read-only lower root; do not remount the
              # writable RAM overlay with those lower-filesystem options.
              systemd-remount-fs.enable = false;
              sshd = {
                requires = [ "srv-qualification.mount" ];
                after = [ "srv-qualification.mount" ];
              };
              sshd-keygen = {
                requires = [ "srv-qualification.mount" ];
                after = [ "srv-qualification.mount" ];
              };
              qualification-offline = {
                description = "Persistently selected software network isolation for this test image";
                wantedBy = [ "network-pre.target" ];
                before = [
                  "network-pre.target"
                  "network.target"
                ];
                after = [ "srv-qualification.mount" ];
                unitConfig.DefaultDependencies = false;
                unitConfig.ConditionPathExists = "/srv/qualification/offline";
                serviceConfig = {
                  Type = "oneshot";
                  RemainAfterExit = true;
                };
                path = [
                  pkgs.iproute2
                  pkgs.nftables
                ];
                script = ''
                  nft add table inet qualification_offline
                  nft 'add chain inet qualification_offline input { type filter hook input priority -300; policy drop; }'
                  nft 'add chain inet qualification_offline output { type filter hook output priority -300; policy drop; }'
                  nft add rule inet qualification_offline input iifname lo accept
                  nft add rule inet qualification_offline output oifname lo accept
                '';
              };
            };
          # Avoid automatically initializing authority state. Existing guarded
          # SPIRE units may resume only a previously explicit initialization.
          systemd.timers.kaiba-identity-pilot-probe.wantedBy = lib.mkForce [ ];
          documentation.enable = false;
          nix.enable = false;
          system.disableInstallerTools = true;
          image.baseName = lib.mkForce "kaiba-ace-nvme-qualification";
          sdImage = {
            compressImage = false;
            expandOnBoot = false;
            firmwareSize = lib.mkForce 256;
            firmwarePartitionID = lib.mkForce "0x51424f54";
            rootVolumeLabel = "KAIBA_Q_ROOT";
            rootPartitionUUID = "fa0aabf4-5a16-4e9d-a7db-903064ca1a00";
          };
        }
      )
    ];
  };
  pkgs = target.pkgs;
  image =
    pkgs.runCommand "kaiba-ace-nvme-qualification-image"
      {
        nativeBuildInputs = [
          pkgs.util-linux
          pkgs.e2fsprogs
          pkgs.coreutils
          pkgs.python3
        ];
      }
      ''
        mkdir -p "$out" data/{identity,ssh,cases,backups,evidence}
        chmod 0700 data/ssh data/backups data/evidence
        echo 'kaiba.nvme-qualification/v1' > data/image-marker
        truncate -s 4G data.ext4
        mkfs.ext4 -q -F -L KAIBA_Q_DATA -U fa0aabf4-5a16-4e9d-a7db-903064ca1a03 -d data data.ext4
        cp --sparse=always ${target.config.system.build.sdImage}/sd-image/*.img "$out/qualification.img"
        chmod u+w "$out/qualification.img"
        python3 ${./assemble.py} "$out/qualification.img" data.ext4
        cp ${./host.py} "$out/host.py"
        cp ${./README.md} "$out/README.md"
        python3 - "$out" ${target.config.system.build.toplevel} <<'PY'
        import hashlib,json,pathlib,sys
        out=pathlib.Path(sys.argv[1]); image=out/'qualification.img'
        with image.open('rb') as f: digest=hashlib.file_digest(f,'sha256').hexdigest()
        manifest={'schema':'kaiba.nvme-qualification-image/v1','image':'qualification.img','bytes':image.stat().st_size,'sha256':digest,'system':sys.argv[2],'synthetic':True,'hardware_qualified':False,'root_label':'KAIBA_Q_ROOT','data_label':'KAIBA_Q_DATA','fleet_revision':'0bd55c576536c29825aada2f7ce6fa052a877402'}
        (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
        PY
      '';
in
{
  inherit image tools;
  system = target.config.system.build.toplevel;
}
