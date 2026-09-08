{
  config,
  lib,
  pkgs,
  utils,
  ...
}:

let
  cfg = config.kaiba.stableVerifierSpike;
  verifierExecutable = "${cfg.package}/bin/kaiba-rpi5-stable-verifier";
  verifierPackageContract = cfg.package.kaibaRpi5StableVerifier or { };
  verifierPackageContractValid =
    (verifierPackageContract.runtimeBoundary or null) == "initramfs_only"
    && (verifierPackageContract.staticallyLinked or false)
    && (verifierPackageContract.kexecCapable or false)
    && (verifierPackageContract.nonProductionOnly or false)
    && !(verifierPackageContract.productionReady or true)
    && !(verifierPackageContract.hardwareObserved or true)
    && !(verifierPackageContract.privateKeyMaterialEmbedded or true)
    && !(verifierPackageContract.authoritySigningCapable or true)
    && !(verifierPackageContract.signingAuthorityConfigured or true);
  releaseMountUnit = "${utils.escapeSystemdPath cfg.releaseDirectory}.mount";
  publicInputs =
    pkgs.runCommand "kaiba-rpi5-stable-verifier-public-inputs"
      {
        policyInput = cfg.policy;
        rootPublicKeyInput = cfg.rootPublicKey;
        authorityCACertificateInput = cfg.authorityCACertificate;
        nativeBuildInputs = [
          pkgs.coreutils
          pkgs.gnugrep
          pkgs.jq
          pkgs.openssl
        ];
      }
      ''
        set -euo pipefail
        umask 022

        for public_input in "$policyInput" "$rootPublicKeyInput" "$authorityCACertificateInput"; do
          test -f "$public_input"
          test ! -L "$public_input"
          test -s "$public_input"
          test "$(stat --format=%s "$public_input")" -le 1048576
          if grep -aEq -- \
            '-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----|-----BEGIN OPENSSH PRIVATE KEY-----' \
            "$public_input"
          then
            echo "private key material is forbidden in stable-verifier public inputs" >&2
            exit 1
          fi
        done
        jq -e 'type == "object"' "$policyInput" > /dev/null
        test "$(openssl pkey -pubin -in "$rootPublicKeyInput" -text -noout | sed -n '1p')" = \
          'Public-Key: (2048 bit)'
        openssl pkey -pubin -in "$rootPublicKeyInput" -text -noout \
          | grep -Fx 'Exponent: 65537 (0x10001)' > /dev/null
        openssl x509 -in "$authorityCACertificateInput" -noout

        mkdir -p "$out"
        install -m 0444 "$policyInput" "$out/policy.json"
        install -m 0444 "$rootPublicKeyInput" "$out/root-public.pem"
        install -m 0444 "$authorityCACertificateInput" "$out/authority-ca.pem"
      '';
  verifierCommand = utils.escapeSystemdExecArgs (
    [
      verifierExecutable
      "--policy"
      "${publicInputs}/policy.json"
      "--root-public-key"
      "${publicInputs}/root-public.pem"
      "--release-dir"
      cfg.releaseDirectory
      "--verifier-version"
      (toString cfg.verifierVersion)
      "--cohort-id"
      cfg.cohortID
      "--slot-id"
      cfg.slotID
      "--minimum-security-epoch"
      (toString cfg.minimumSecurityEpoch)
      "--authority-url"
      cfg.authorityURL
      "--authority-ca"
      "${publicInputs}/authority-ca.pem"
      "--authority-key-id"
      cfg.authorityKeyID
      "--audience"
      cfg.audience
      "--logical-identity"
      cfg.logicalIdentity
      "--kexec"
      "${cfg.kexecPackage}/bin/kexec"
    ]
    ++ cfg.extraArguments
  );
  cleanAbsolute =
    value:
    builtins.isString value
    && lib.hasPrefix "/" value
    && value != "/"
    && !(lib.hasInfix "//" value)
    && !(lib.hasInfix "/./" value)
    && !(lib.hasInfix "/../" value)
    && !(lib.hasSuffix "/." value)
    && !(lib.hasSuffix "/.." value);
  reservedArgument =
    value:
    builtins.match "--?(policy|root-public-key|release-dir|verifier-version|cohort-id|slot-id|minimum-security-epoch|authority-url|authority-ca|authority-key-id|audience|logical-identity|kexec|bootstrap-registration-timeout|authority-client-timeout)(=.*)?" value
    != null;
in
{
  options.kaiba.stableVerifierSpike = {
    enable = lib.mkEnableOption "the development-only Raspberry Pi 5 initramfs stable-verifier spike";

    package = lib.mkOption {
      type = lib.types.package;
      description = ''
        Package containing the statically linked stable verifier. This module
        never adds signing credentials to the package or initramfs.
      '';
    };

    policy = lib.mkOption {
      type = lib.types.path;
      description = ''
        Root-signed stable-verifier policy. Its root_signature is inline; the
        policy is public input material and must not contain a private key.
      '';
    };

    rootPublicKey = lib.mkOption {
      type = lib.types.path;
      description = "RSA-2048 public key used to authenticate the stable policy.";
    };

    verifierVersion = lib.mkOption {
      type = lib.types.ints.positive;
      description = "Version asserted by the stable verifier in authorization requests.";
    };

    cohortID = lib.mkOption {
      type = lib.types.strMatching "[a-z0-9][a-z0-9._:-]{0,127}";
      description = "Delegated-release cohort this verifier instance will admit.";
    };

    slotID = lib.mkOption {
      type = lib.types.strMatching "[a-z0-9][a-z0-9._:-]{0,127}";
      description = "Expected delegated-release slot identifier.";
    };

    minimumSecurityEpoch = lib.mkOption {
      type = lib.types.ints.unsigned;
      description = "Minimum delegated-release security epoch admitted by this spike.";
    };

    authorityURL = lib.mkOption {
      type = lib.types.str;
      description = "HTTPS URL of the isolated non-production boot-authorization authority.";
    };

    authorityCACertificate = lib.mkOption {
      type = lib.types.path;
      description = ''
        Explicit public CA certificate used only for the non-production
        authorization endpoint. Ambient system trust roots are not used.
      '';
    };

    authorityKeyID = lib.mkOption {
      type = lib.types.strMatching "[a-z0-9][a-z0-9._:-]{0,127}";
      description = "One authorization signing-key identifier selected from the stable policy.";
    };

    audience = lib.mkOption {
      type = lib.types.strMatching "[a-z0-9][a-z0-9._:-]{0,127}";
      description = "Expected audience bound into boot-authorization responses.";
    };

    logicalIdentity = lib.mkOption {
      type = lib.types.strMatching "[a-z0-9][a-z0-9._:-]{0,127}";
      description = "Explicit non-production logical identity used by this spike.";
    };

    releaseDevice = lib.mkOption {
      type = lib.types.str;
      default = "/dev/disk/by-partlabel/KAIBA_RELEASE";
      description = "NVMe partition containing the delegated release bundle.";
    };

    releaseDirectory = lib.mkOption {
      type = lib.types.str;
      default = "/run/kaiba-release";
      description = "Read-only initramfs mount point passed to the verifier.";
    };

    releaseFileSystem = lib.mkOption {
      type = lib.types.enum [
        "ext4"
        "vfat"
      ];
      default = "ext4";
      description = "Filesystem used by the delegated-release NVMe partition.";
    };

    networkInterface = lib.mkOption {
      type = lib.types.strMatching "[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}";
      default = "end0";
      description = "RP1-backed interface on which initramfs networkd obtains DHCPv4.";
    };

    initrdKernelModules = lib.mkOption {
      type = lib.types.listOf (lib.types.strMatching "[A-Za-z0-9][A-Za-z0-9_-]{0,127}");
      default = [ "nvme" ];
      description = ''
        Storage and network modules copied into the initramfs. The caller's
        pinned Pi kernel module should extend this for its exact RP1 driver set.
      '';
    };

    kexecPackage = lib.mkOption {
      type = lib.types.package;
      default = pkgs.kexec-tools;
      defaultText = lib.literalExpression "pkgs.kexec-tools";
      description = "Pinned kexec implementation passed to the verifier.";
    };

    extraArguments = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = ''
        Additional argv entries for experimental verifier features. Core
        security arguments cannot be overridden through this escape hatch.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = verifierPackageContractValid;
        message = "kaiba.stableVerifierSpike.package must expose the static, initramfs-only, non-production verifier contract";
      }
      {
        assertion = cleanAbsolute cfg.releaseDevice && lib.hasPrefix "/dev/" cfg.releaseDevice;
        message = "kaiba.stableVerifierSpike.releaseDevice must be one clean absolute /dev path";
      }
      {
        assertion = cleanAbsolute cfg.releaseDirectory && lib.hasPrefix "/run/" cfg.releaseDirectory;
        message = "kaiba.stableVerifierSpike.releaseDirectory must be one clean absolute path below /run";
      }
      {
        assertion = builtins.match "https://[^[:space:]]+" cfg.authorityURL != null;
        message = "kaiba.stableVerifierSpike.authorityURL must use an explicit HTTPS URL";
      }
      {
        assertion = !(builtins.any reservedArgument cfg.extraArguments);
        message = "kaiba.stableVerifierSpike.extraArguments cannot override a core verifier argument";
      }
    ];

    boot = {
      initrd = {
        availableKernelModules = cfg.initrdKernelModules;
        kernelModules = cfg.initrdKernelModules;
        network.enable = true;
        systemd = {
          enable = true;
          emergencyAccess = false;
          shell.enable = false;
          storePaths = [
            cfg.package
            publicInputs
            cfg.kexecPackage
          ];
          network = {
            enable = true;
            networks."10-kaiba-stable-verifier" = {
              matchConfig.Name = cfg.networkInterface;
              networkConfig = {
                DHCP = "ipv4";
                IPv6AcceptRA = false;
                LinkLocalAddressing = false;
              };
            };
          };
          mounts = [
            {
              description = "Read-only Kaiba delegated release on NVMe";
              what = cfg.releaseDevice;
              where = cfg.releaseDirectory;
              type = cfg.releaseFileSystem;
              options = "ro,nosuid,nodev,noexec";
              wantedBy = [ "initrd.target" ];
              before = [ "kaiba-stable-verifier.service" ];
              unitConfig.DefaultDependencies = false;
            }
          ];
          services.kaiba-stable-verifier = {
            description = "Authenticate and hand off the Kaiba delegated release";
            wantedBy = [ "initrd.target" ];
            requiredBy = [ "initrd-switch-root.target" ];
            wants = [ "network-online.target" ];
            requires = [ releaseMountUnit ];
            after = [
              releaseMountUnit
              "network-online.target"
            ];
            # Do not let the ordinary root filesystem mount hide initrd store
            # paths while network authorization is still in progress. More
            # importantly, no stage-2 root should be consumed before this
            # service has authenticated the delegated release and replaced
            # the boot with kexec.
            before = [
              "initrd-root-fs.target"
              "initrd-switch-root.target"
              "sysroot.mount"
            ];
            unitConfig = {
              DefaultDependencies = false;
              FailureAction = "poweroff-force";
              SuccessAction = "poweroff-force";
            };
            serviceConfig = {
              Type = "oneshot";
              ExecStart = verifierCommand;
              StandardOutput = "journal+console";
              StandardError = "journal+console";
              NoNewPrivileges = true;
              PrivateDevices = true;
              PrivateTmp = true;
              ProtectControlGroups = true;
              ProtectHome = true;
              ProtectKernelModules = true;
              ProtectKernelTunables = true;
              ProtectSystem = "strict";
              ReadOnlyPaths = [ cfg.releaseDirectory ];
              # arm64 kexec-tools reads /proc/iomem before kexec_load. Linux
              # masks that map without CAP_SYS_ADMIN. Keep the temporary broad
              # capability explicit and deny its mount-family syscall surface.
              CapabilityBoundingSet = [
                "CAP_SYS_ADMIN"
                "CAP_SYS_BOOT"
              ];
              AmbientCapabilities = [
                "CAP_SYS_ADMIN"
                "CAP_SYS_BOOT"
              ];
              LockPersonality = true;
              MemoryDenyWriteExecute = true;
              RestrictAddressFamilies = [
                "AF_UNIX"
                "AF_INET"
                "AF_INET6"
              ];
              RestrictNamespaces = true;
              RestrictSUIDSGID = true;
              SystemCallFilter = [ "~@mount" ];
              SystemCallArchitectures = "native";
              UMask = "0077";
            };
          };
        };
      };
      kernelParams = [ "console=serial0,115200" ];
    };

    services = {
      getty.autologinUser = lib.mkForce null;
      openssh.enable = lib.mkForce false;
    };
    systemd.enableEmergencyMode = false;
    system.build.kaibaStableVerifierPublicInputs = publicInputs;
    swapDevices = lib.mkForce [ ];
    zramSwap.enable = false;
  };
}
