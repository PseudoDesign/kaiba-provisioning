{
  description = "Kaiba device provisioning";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/70ce234312134a463ba7728e94da2486a1d237ac";
  inputs.nixos-raspberrypi.url = "github:nvmd/nixos-raspberrypi/7e39508bcf9c1da82cf11c1e22f74f9d9fd0fe10";

  outputs =
    {
      self,
      nixpkgs,
      nixos-raspberrypi,
    }:
    let
      lib = nixpkgs.lib;
      # Build the UI test tree in one pass from the flake's original path.
      # nix/packages.nix does the same for the shared application source.
      repositorySource = ./.;
      stationUITestRoot = lib.fileset.toSource {
        root = repositorySource;
        fileset = lib.fileset.unions [
          ./internal/provisioning/livestation/web
          ./internal/provisioning/stationui/web
          ./tests/station-ui
        ];
      };
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = lib.genAttrs systems;
      hardwareConfigurations = import ./config/hardware;
      assets = rec {
        development = {
          posturePath = ./policies/raspberry-pi-5-development-posture-v1alpha1.json;
          posture = builtins.fromJSON (builtins.readFile development.posturePath);
          sshAuthorizedKeyPath = ./keys/codex-rpi5-development-2026-09-05.pub;
          sshAuthorizedKey = lib.removeSuffix "\n" (builtins.readFile development.sshAuthorizedKeyPath);
        };

        configuration = {
          prototypeEEPROMBoot = ./config/rpi5-prototype-eeprom/boot.conf;
          prototypeReleasePlatformAdapter = ./config/rpi5-prototype-release/platform-adapter-v1alpha1.json;
        };

        profiles = {
          raspberryPi5ModelB = ./profiles/device-classes/raspberry-pi-5-model-b-v1alpha1.json;
        };

        schemas = {
          bootSigningPlanV1Alpha2 = ./schemas/rpi5-boot-signing-plan-v1alpha2.schema.json;
          bootAuthorizationV1Alpha1 = ./schemas/rpi5-boot-authorization-v1alpha1.schema.json;
          delegatedReleaseManifestV1Alpha1 = ./schemas/rpi5-delegated-release-manifest-v1alpha1.schema.json;
          eepromSigningPlanV1Alpha1 = ./schemas/rpi5-eeprom-signing-plan-v1alpha1.schema.json;
          hardwareQualificationV1Alpha1 = ./schemas/rpi5-hardware-qualification-v1alpha1.schema.json;
          manualLaneQualificationV1Alpha1 = ./schemas/rpi5-manual-lane-qualification-v1alpha1.schema.json;
          platformAdapterV1Alpha1 = ./schemas/rpi5-platform-adapter-v1alpha1.schema.json;
          releaseIntentV1Alpha1 = ./schemas/rpi5-release-intent-v1alpha1.schema.json;
          signerIndependentReviewV1Alpha1 = ./schemas/signer-independent-review-v1alpha1.schema.json;
          stableVerifierEventV1Alpha1 = ./schemas/rpi5-stable-verifier-event-v1alpha1.schema.json;
          stableVerifierPolicyV1Alpha1 = ./schemas/rpi5-stable-verifier-policy-v1alpha1.schema.json;
          stableVerifierSpikeEvidenceV1Alpha1 = ./schemas/rpi5-stable-verifier-spike-evidence-v1alpha1.schema.json;
          stableCampaignProvisionerArtifactSetV1Alpha1 = ./schemas/rpi5-stable-campaign-provisioner-artifact-set-v1alpha1.schema.json;
          stableCampaignProvisionerBootIntegrityV1Alpha1 = ./schemas/rpi5-stable-campaign-provisioner-boot-integrity-v1alpha1.schema.json;
          stableCampaignProvisionerSigningApprovalV1Alpha1 = ./schemas/rpi5-stable-campaign-provisioner-signing-approval-v1alpha1.schema.json;
          stableCampaignProvisionerSigningIntentV1Alpha1 = ./schemas/rpi5-stable-campaign-provisioner-signing-intent-v1alpha1.schema.json;
          stableCampaignProvisionerSignedBootFilesystemV1Alpha1 = ./schemas/rpi5-stable-campaign-provisioner-signed-boot-filesystem-v1alpha1.schema.json;
          unsignedArtifactSetV1Alpha1 = ./schemas/unsigned-artifact-set-v1alpha1.schema.json;
        };

        signers.developmentPrototype = {
          independentReviewPath = ./signers/development-prototype/independent-review-2026-08-27.json;
          independentReview = builtins.fromJSON (
            builtins.readFile signers.developmentPrototype.independentReviewPath
          );
          reviewedBootPublicKey = ./signers/development-prototype/reviewed-boot-public.pem;
        };

        releases.rpi5V016 = {
          source = builtins.path {
            name = "kaiba-rpi5-v016-public-signed-input-source";
            path = ./releases/rpi5-v0.1.6;
          };
          operationalPayloadManifest = builtins.fromJSON (
            builtins.readFile ./releases/rpi5-v0.1.6/operational-payload-manifest.json
          );
          signedInputs = {
            bootSignedOutput = builtins.path {
              name = "boot-signed";
              path = ./releases/rpi5-v0.1.6/signed-inputs/boot-signed;
            };
            eepromSignedOutput = builtins.path {
              name = "eeprom-signed";
              path = ./releases/rpi5-v0.1.6/signed-inputs/eeprom-signed;
            };
            ownedRecoverySignedOutput = builtins.path {
              name = "owned-recovery-signed";
              path = ./releases/rpi5-v0.1.6/signed-inputs/owned-recovery-signed;
            };
            signingGrantRegistry = builtins.path {
              name = "signing-grants.json";
              path = ./releases/rpi5-v0.1.6/signed-inputs/signing-grants.json;
            };
            signingReceiptExport = builtins.path {
              name = "signing-receipts.json";
              path = ./releases/rpi5-v0.1.6/signed-inputs/signing-receipts.json;
            };
          };
        };
      };
      stableCampaignSourceRevision =
        if self ? rev then self.rev else "0000000000000000000000000000000000000000";
      stableCampaignExpectedCustomerKeyHash = lib.removePrefix "sha256:" (
        assets.signers.developmentPrototype.independentReview.public_bindings.customer_key_hash
      );
      packagesFor =
        system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        import ./nix/packages.nix {
          inherit pkgs lib;
        };

      packagesBySystem = forAllSystems packagesFor;

      modules = {
        default = import ./nix/modules;
        provisioning-audit = import ./nix/modules/provisioning-audit.nix;
        provisioning-authority-bridge = import ./nix/modules/provisioning-authority-bridge.nix;
        provisioning-control = import ./nix/modules/provisioning-control.nix;
        provisioning-lane-guard = import ./nix/modules/provisioning-lane-guard.nix;
        provisioning-probe = import ./nix/modules/provisioning-probe.nix;
        provisioning-signing-gate = import ./nix/modules/provisioning-signing-gate.nix;
        provisioning-station-demo = import ./nix/modules/provisioning-station-demo.nix;
        secure-boot-target = import ./nix/modules/secure-boot-target.nix;
        stable-verifier-spike = import ./nix/modules/stable-verifier-spike.nix;
      };

      provisioningFor =
        system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        import ./tests/packages.nix {
          inherit hardwareConfigurations pkgs lib;
          built = packagesBySystem.${system};
          kaibaModules = modules;
        };

      provisioningBySystem = forAllSystems provisioningFor;

      mkDevelopmentSigningCeremony =
        {
          system,
          sourceRevision,
          sourceTreeClean,
        }:
        import ./nix/development-signing-ceremony.nix {
          pkgs = import nixpkgs { inherit system; };
          inherit sourceRevision sourceTreeClean;
        };

      mkUbuntuProvisioningAuthorityDeployment =
        {
          system,
          auditPackage ? packagesBySystem.${system}.audit,
          auditPort ? 8092,
          controlPackage ? packagesBySystem.${system}.control,
          controlPort ? 8091,
          listenAddress ? "192.168.8.249",
        }:
        import ./nix/ubuntu-provisioning-authority-deployment.nix {
          pkgs = import nixpkgs { inherit system; };
          inherit
            auditPackage
            auditPort
            controlPackage
            controlPort
            listenAddress
            ;
        };

      mkUbuntuSigningGateDeployment =
        { system }:
        import ./nix/ubuntu-signing-gate-deployment.nix {
          pkgs = import nixpkgs { inherit system; };
        };

      mkRpi5StableCampaignProvisionerSystem =
        {
          sourceRevision,
          buildPlatformSystem ? "x86_64-linux",
        }:
        assert lib.assertMsg (builtins.elem buildPlatformSystem systems)
          "the stable-campaign provisioner build platform must be one of the flake's supported systems";
        let
          targetPkgs =
            if buildPlatformSystem == "aarch64-linux" then
              import nixpkgs { system = "aarch64-linux"; }
            else
              import nixpkgs {
                localSystem = buildPlatformSystem;
                crossSystem = "aarch64-linux";
              };
        in
        import ./nix/rpi5-stable-campaign-provisioner-system.nix
          {
            inherit buildPlatformSystem;
            nixosRaspberryPi = nixos-raspberrypi;
            secureBootTargetModule = modules.secure-boot-target;
            stableCampaignGPTInspector =
              (import ./nix/packages.nix {
                inherit lib;
                pkgs = targetPkgs;
              }).stableCampaignGPTInspector;
          }
          {
            expectedCustomerKeyHash = stableCampaignExpectedCustomerKeyHash;
            inherit sourceRevision;
          };

      mkRpi5StableCampaignProvisioner =
        {
          sourceRevision,
          buildPlatformSystem ? "x86_64-linux",
        }:
        let
          provisionerSystem = mkRpi5StableCampaignProvisionerSystem {
            inherit buildPlatformSystem sourceRevision;
          };
        in
        import ./nix/rpi5-stable-campaign-provisioner-artifacts.nix {
          inherit lib provisionerSystem;
          buildPkgs = import nixpkgs { system = buildPlatformSystem; };
        };

      mkRpi5StableCampaignProvisionerSignedBootFilesystem =
        (import ./nix/rpi5-stable-campaign-provisioner-signed-boot-filesystem.nix {
          inherit lib;
          pkgs = import nixpkgs { system = "x86_64-linux"; };
        }).mkRpi5StableCampaignProvisionerSignedBootFilesystem;
    in
    {
      nixosModules = modules;

      lib = {
        inherit
          assets
          hardwareConfigurations
          mkDevelopmentSigningCeremony
          mkRpi5StableCampaignProvisionerSignedBootFilesystem
          mkUbuntuProvisioningAuthorityDeployment
          mkUbuntuSigningGateDeployment
          ;

        mkRpi5SecureBootArtifacts =
          { system, ... }@args:
          assert lib.assertMsg (!(args ? rootDeviceBinding))
            "rootDeviceBinding is internal; the public secure-boot artifact constructor cannot select the stable-campaign SD profile";
          let
            pkgs = import nixpkgs { inherit system; };
            builder = import ./nix/secure-boot-artifacts.nix { inherit pkgs lib; };
          in
          builder (builtins.removeAttrs args [ "system" ] // { rootDeviceBinding = "gpt-partuuid"; });

        mkRpi5StableVerifierUnsignedBoot =
          { system, ... }@args:
          packagesBySystem.${system}.mkRpi5StableVerifierUnsignedBoot (
            builtins.removeAttrs args [ "system" ]
          );

        mkRpi5StableVerifierTestSD =
          { system, ... }@args:
          packagesBySystem.${system}.mkRpi5StableVerifierTestSD (builtins.removeAttrs args [ "system" ]);

        mkRpi5StableVerifierCampaignMedia =
          { system, ... }@args:
          packagesBySystem.${system}.mkRpi5StableVerifierCampaignMedia (
            builtins.removeAttrs args [ "system" ]
          );

        mkRpi5StableVerifierCampaignRun =
          { system, ... }@args:
          packagesBySystem.${system}.mkRpi5StableVerifierCampaignRun (builtins.removeAttrs args [ "system" ]);

        mkRpi5DelegatedReleaseSpike =
          { system, ... }@args:
          packagesBySystem.${system}.mkRpi5DelegatedReleaseSpike (builtins.removeAttrs args [ "system" ]);

        mkRpi5StableVerifierSpikeRig =
          { system, ... }@args:
          packagesBySystem.${system}.mkRpi5StableVerifierSpikeRig (builtins.removeAttrs args [ "system" ]);

        mkRpi5ReleasePayloadQemuVirt =
          { system, ... }@args:
          packagesBySystem.${system}.mkRpi5ReleasePayloadQemuVirt (builtins.removeAttrs args [ "system" ]);

        mkRpi5KernelQemuVirtBeacon =
          { system, ... }@args:
          packagesBySystem.${system}.mkRpi5KernelQemuVirtBeacon (builtins.removeAttrs args [ "system" ]);

        mkRpi5StableVerifierHardwareSystem =
          args:
          import ./nix/stable-verifier-hardware.nix {
            nixosRaspberryPi = nixos-raspberrypi;
            stableVerifierModule = modules.stable-verifier-spike;
            stableVerifierPackage = packagesBySystem.aarch64-linux.stableVerifierTool;
          } args;

        mkRpi5StableVerifierFileLiveFDTHardwareSystem =
          args:
          let
            requestedKexecMode = args.kexecMode or "experimental-file-live-fdt";
          in
          if args ? extraModules then
            throw "mkRpi5StableVerifierFileLiveFDTHardwareSystem does not accept extraModules"
          else if requestedKexecMode != "experimental-file-live-fdt" then
            throw "mkRpi5StableVerifierFileLiveFDTHardwareSystem only accepts experimental-file-live-fdt"
          else
            import ./nix/stable-verifier-hardware.nix {
              nixosRaspberryPi = nixos-raspberrypi;
              stableVerifierModule = modules.stable-verifier-spike;
              stableVerifierPackage = packagesBySystem.aarch64-linux.stableVerifierTool;
            } (args // { kexecMode = "experimental-file-live-fdt"; });

        mkRpi5PhysicalLaneGuard =
          { system, ... }@args:
          packagesBySystem.${system}.mkRpi5PhysicalLaneGuard (builtins.removeAttrs args [ "system" ]);

        mkRpi5DevelopmentSecureBootRunner =
          { system, ... }@args:
          packagesBySystem.${system}.mkRpi5DevelopmentSecureBootRunner (
            builtins.removeAttrs args [ "system" ]
          );

        mkRpi5DevelopmentSecureBootOperationalPayload =
          { system, ... }@args:
          packagesBySystem.${system}.mkRpi5DevelopmentSecureBootOperationalPayload (
            builtins.removeAttrs args [ "system" ]
          );

        mkRpi5BootSigningPlan =
          { system, ... }@args:
          packagesBySystem.${system}.mkRpi5BootSigningPlan (builtins.removeAttrs args [ "system" ]);

        mkRpi5StableCampaignProvisionerSigningPlan =
          { system, ... }@args:
          packagesBySystem.${system}.mkRpi5StableCampaignProvisionerSigningPlan (
            builtins.removeAttrs args [ "system" ]
          );

        mkRpi5EEPROMRelease =
          { system, ... }@args:
          packagesBySystem.${system}.mkRpi5EEPROMRelease (builtins.removeAttrs args [ "system" ]);

        mkRpi5EEPROMReleaseSigningInputs =
          { system, ... }@args:
          packagesBySystem.${system}.mkRpi5EEPROMReleaseSigningInputs (
            builtins.removeAttrs args [ "system" ]
          );

        mkRpi5EEPROMSigningPlan =
          { system, ... }@args:
          packagesBySystem.${system}.mkRpi5EEPROMSigningPlan (builtins.removeAttrs args [ "system" ]);

        mkRpi5OwnedRecoverySigningPlan =
          { system, ... }@args:
          packagesBySystem.${system}.mkRpi5OwnedRecoverySigningPlan (builtins.removeAttrs args [ "system" ]);

        mkRpi5VerifiedRPIBootBundles =
          { system, ... }@args:
          packagesBySystem.${system}.mkRpi5VerifiedRPIBootBundles (builtins.removeAttrs args [ "system" ]);

        mkRpi5VerifiedSigningReceipts =
          { system, ... }@args:
          packagesBySystem.${system}.mkRpi5VerifiedSigningReceipts (builtins.removeAttrs args [ "system" ]);

        mkRpi5VerifiedStableCampaignProvisionerSigning =
          { system, ... }@args:
          packagesBySystem.${system}.mkRpi5VerifiedStableCampaignProvisionerSigning (
            builtins.removeAttrs args [ "system" ]
          );

        mkRpi5VerifiedSignedRelease =
          { system, ... }@args:
          packagesBySystem.${system}.mkRpi5VerifiedSignedRelease (builtins.removeAttrs args [ "system" ]);

        mkRpi5ReleaseIntent =
          { system, ... }@args:
          packagesBySystem.${system}.mkRpi5ReleaseIntent (builtins.removeAttrs args [ "system" ]);

        mkDevelopmentYubiKeySigning =
          { system, ... }@args:
          packagesBySystem.${system}.mkDevelopmentYubiKeySigning (builtins.removeAttrs args [ "system" ]);

        mkRpi5UnfusedVerifier =
          { system, ... }@args:
          packagesBySystem.${system}.mkRpi5UnfusedVerifier (builtins.removeAttrs args [ "system" ]);

        mkRpi5VerifiedSignedBoot =
          { system, ... }@args:
          packagesBySystem.${system}.mkRpi5VerifiedSignedBoot (builtins.removeAttrs args [ "system" ]);

        mkRpi5VerifiedSignedEEPROM =
          { system, ... }@args:
          packagesBySystem.${system}.mkRpi5VerifiedSignedEEPROM (builtins.removeAttrs args [ "system" ]);

        mkRpi5VerifiedOwnedRecovery =
          { system, ... }@args:
          packagesBySystem.${system}.mkRpi5VerifiedOwnedRecovery (builtins.removeAttrs args [ "system" ]);

        mkRpi5VerifiedUnfusedCapsule =
          { system, ... }@args:
          packagesBySystem.${system}.mkRpi5VerifiedUnfusedCapsule (builtins.removeAttrs args [ "system" ]);

        mkRpi5MediaStagingFixture =
          { system, ... }@args:
          packagesBySystem.${system}.mkRpi5MediaStagingFixture (builtins.removeAttrs args [ "system" ]);

        mkRpi5ProductionMedia =
          { system, ... }@args:
          packagesBySystem.${system}.mkRpi5ProductionMedia (builtins.removeAttrs args [ "system" ]);
      };

      packages = forAllSystems (
        system:
        let
          built = packagesBySystem.${system};
          provisioning = provisioningBySystem.${system};
        in
        {
          default = built.provision;
          kaiba-provision-audit = built.audit;
          kaiba-provision-authority-bridge = built.authorityBridge;
          kaiba-provision-control = built.control;
          kaiba-provision-integrated-rehearsal = built.integratedRehearsal;
          kaiba-provision-lane-guard = built.laneGuard;
          kaiba-provision-lane-operator = built.laneOperator;
          kaiba-provision-lane-workflow = built.laneWorkflow;
          kaiba-provision-media-contract = built.mediaContractTool;
          kaiba-provision = built.provision;
          kaiba-provision-rehearsal = built.rehearsal;
          kaiba-provision-signer-foundation = built.signerFoundation;
          kaiba-provision-signing-client-foundation = built.signingClientFoundation;
          kaiba-provision-signing-gate-foundation = built.signingGateFoundation;
          kaiba-provision-signing-approval = built.signingApprovalTool;
          kaiba-provision-signing-receipts = built.signingReceiptsTool;
          kaiba-provision-sign-boot = built.signedBootTool;
          kaiba-provision-sign-eeprom = built.eepromSigningTool;
          kaiba-provision-rpiboot-bundles = built.rpibootBundleTool;
          kaiba-provision-finalize-release = built.signedReleaseTool;
          kaiba-provision-station = built.liveStation;
          kaiba-provision-station-demo = built.stationDemo;
          kaiba-provision-station-pages = built.stationPages;
          kaiba-provision-unfused-compat = built.unfusedCompat;
          kaiba-provision-unfused-evidence = built.unfusedEvidence;
          kaiba-provision-unfused-runtime-record = built.unfusedRuntimeRecordTool;
          kaiba-rpi5-kexec-input-validate = built.rpi5KexecInputValidator;
          kaiba-rpi5-one-boot-prove = built.oneBootProveTool;
          kaiba-rpi5-stable-campaign-gpt-inspect = built.stableCampaignGPTInspector;
          kaiba-rpi5-stable-campaign-plan = built.stableCampaignPlanTool;
          kaiba-rpi5-stable-campaign-signing = built.stableCampaignSigningTool;
          kaiba-rpi5-stable-verifier = built.stableVerifierTool;
          kaiba-rpi5-verifier-test-authority = built.verifierTestAuthority;
          provisioning-suite = built.suite;
          provisioning-services = built.serviceSuite;
          provisioning-test-result = provisioning.provisioningTestResult;
          rpi5-physical-lane-guard-fixture = provisioning.physicalLaneGuardFixture;
          rpi5-probe-bundle = built.rpi5ProbeBundle;
          rpi5-eeprom-release = built.rpi5EEPROMRelease;
          kaiba-provision-yubikey-wrapper-foundation = built.yubiKeyWrapperFoundation;
          ubuntu-provisioning-authority-deployment = mkUbuntuProvisioningAuthorityDeployment {
            inherit system;
          };
          ubuntu-signing-gate-deployment = mkUbuntuSigningGateDeployment { inherit system; };
        }
        // lib.optionalAttrs (system == "x86_64-linux") {
          kaiba-provision-signing-ceremony = mkDevelopmentSigningCeremony {
            inherit system;
            sourceRevision = "0000000000000000000000000000000000000000";
            sourceTreeClean = false;
          };
        }
        // lib.optionalAttrs (system == "aarch64-linux") {
          kaiba-rpi5-self-kexec-diagnostic = built.rpi5SelfKexecDiagnostic;
        }
        // lib.optionalAttrs (self ? rev && system == "x86_64-linux") {
          kaiba-rpi5-stable-campaign-development-signing = built.mkDevelopmentYubiKeySigning {
            name = "kaiba-rpi5-stable-campaign-development-signing";
            cohortID = "cohort:prototype";
            expectedCustomerKeyHash = stableCampaignExpectedCustomerKeyHash;
            publicKeyFingerprint =
              assets.signers.developmentPrototype.independentReview.public_bindings.public_key_fingerprint;
            publicKeyPEM = assets.signers.developmentPrototype.reviewedBootPublicKey;
            signerID = "signer:prototype";
            signerPolicyDigest =
              assets.signers.developmentPrototype.independentReview.public_bindings.signer_policy_digest;
            stableCampaignOnly = true;
            tokenSerial = assets.signers.developmentPrototype.independentReview.token.serial;
          };
          kaiba-rpi5-stable-campaign-provisioner-unsigned =
            (mkRpi5StableCampaignProvisioner {
              sourceRevision = stableCampaignSourceRevision;
            }).unsignedArtifacts;
          kaiba-rpi5-stable-campaign-provisioner-signing-plan =
            built.mkRpi5StableCampaignProvisionerSigningPlan
              {
                sourceDateEpoch = self.lastModified;
                sourceRevision = stableCampaignSourceRevision;
                unsignedArtifacts =
                  (mkRpi5StableCampaignProvisioner {
                    sourceRevision = stableCampaignSourceRevision;
                  }).unsignedArtifacts;
              };
        }
      );

      checks = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          built = packagesBySystem.${system};
          provisioning = provisioningBySystem.${system};
          stableVerifierVMFixture = import ./tests/stable-verifier-vm-fixture.nix {
            inherit pkgs;
            source = repositorySource;
          };
          stableVerifierInitramfsVM = import ./tests/stable-verifier-initramfs-vm.nix {
            inherit pkgs built;
            signedFixture = stableVerifierVMFixture;
          };
          stableVerifierCampaignMediaCheck = import ./tests/stable-verifier-campaign-media.nix {
            inherit lib pkgs;
          };
          stableVerifierCampaignRunCheck = import ./tests/stable-verifier-campaign-run.nix {
            inherit lib pkgs;
            baselineMedia = stableVerifierCampaignMediaCheck.fixtureBaselineMedia;
          };
          bootImageHashDecoderCheck = import ./tests/boot-image-hash-decoder.nix { inherit pkgs; };
          stableCampaignProvisioner = mkRpi5StableCampaignProvisioner {
            buildPlatformSystem = system;
            sourceRevision = stableCampaignSourceRevision;
          };
          stableCampaignProvisionerArtifactCheck =
            import ./tests/rpi5-stable-campaign-provisioner-artifacts.nix
              {
                artifacts = stableCampaignProvisioner.unsignedArtifacts;
                artifactSchema = assets.schemas.stableCampaignProvisionerArtifactSetV1Alpha1;
                bootIntegritySchema = assets.schemas.stableCampaignProvisionerBootIntegrityV1Alpha1;
                inherit lib pkgs;
                sourceRevision = stableCampaignSourceRevision;
              };
          stableCampaignProvisionerSignedBootFilesystemCheck =
            import ./tests/rpi5-stable-campaign-provisioner-signed-boot-filesystem.nix
              {
                inherit lib pkgs;
              };
          stableCampaignSigningCheck = import ./tests/rpi5-stable-campaign-signing.nix {
            inherit built lib pkgs;
          };
          aarch64GuestPkgs =
            if system == "aarch64-linux" then pkgs else import nixpkgs { system = "aarch64-linux"; };
          aarch64GuestBuilt =
            if system == "aarch64-linux" then
              built
            else
              import ./nix/packages.nix {
                pkgs = aarch64GuestPkgs;
                inherit lib;
              };
          stableVerifierAarch64KexecVM = import ./tests/stable-verifier-aarch64-kexec-vm.nix {
            inherit pkgs;
            guestPkgs = aarch64GuestPkgs;
            built = aarch64GuestBuilt;
          };
          stableHandoffAarch64KexecFileVM = import ./tests/stable-handoff-aarch64-kexec-file-vm.nix {
            inherit pkgs;
            guestPkgs = aarch64GuestPkgs;
            requireInPlacePatch = ./nix/patches/arm64-kexec-file-require-in-place.patch;
            source = repositorySource;
          };
          stableVerifierHardwareConstructor = import ./nix/stable-verifier-hardware.nix {
            nixosRaspberryPi = nixos-raspberrypi;
            stableVerifierModule = modules.stable-verifier-spike;
            stableVerifierPackage = packagesBySystem.aarch64-linux.stableVerifierTool;
          };
          stableVerifierHardwareArguments = {
            policy = builtins.toFile "kaiba-stable-verifier-hardware-check-policy.json" "{}";
            rootPublicKey = ./tests/fixtures/development-boot-public.pem;
            authorityCACertificate = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
            verifierVersion = 1;
            cohortID = "development";
            slotID = "a";
            minimumSecurityEpoch = 1;
            authorityURL = "https://192.0.2.1:8443";
            authorityKeyID = "development-authority";
            audience = "stable-verifier";
            logicalIdentity = "development-pi";
          };
          # No kexecMode is supplied here: this fixture protects the generic
          # constructor's compatibility default.
          stableVerifierHardwareSystem = stableVerifierHardwareConstructor stableVerifierHardwareArguments;
          # Exercise the exported closed constructor rather than rebuilding its
          # implementation locally in the check.
          stableVerifierFileLiveFDTHardwareSystem = self.lib.mkRpi5StableVerifierFileLiveFDTHardwareSystem stableVerifierHardwareArguments;
          hardwareKexecModeRejected =
            kexecMode:
            !(builtins.tryEval (
              (stableVerifierHardwareConstructor (stableVerifierHardwareArguments // { inherit kexecMode; }))
              .kexecMode
            )).success;
          fileLiveFDTHardwareArgumentsRejected =
            extraArguments:
            !(builtins.tryEval (
              (self.lib.mkRpi5StableVerifierFileLiveFDTHardwareSystem (
                stableVerifierHardwareArguments // extraArguments
              )).kexecMode
            )).success;
        in
        {
          asset-api = import ./tests/assets.nix { inherit assets pkgs; };
          boot-image-hash-decoder = bootImageHashDecoderCheck;
          unit = built.suite;
          development-yubikey-signing = provisioning.developmentYubiKeySigningContract;
          device-profile-schema = provisioning.deviceProfileSchema;
          rpi5-development-posture = provisioning.developmentPostureContract;
          module-eval = provisioning.moduleEval;
          provisioning-test-result = provisioning.provisioningTestResult;
          rpi5-probe-bundle = provisioning.probeBundleIntegrity;
          rpi5-self-kexec-diagnostic = built.rpi5SelfKexecDiagnosticCheck;
          rpi5-eeprom-release = provisioning.eepromReleaseContract;
          rpi5-eeprom-signing = provisioning.eepromSigningContract;
          rpi5-rpiboot-bundles = provisioning.rpibootBundleContract;
          rpi5-signed-release = provisioning.signedReleaseFinalizationContract;
          rpiboot-metadata-stdout = provisioning.rpibootMetadataStdoutCompatibility;
          secure-boot-artifacts = provisioning.secureBootArtifactContract;
          stable-verifier-spike = built.mkRpi5StableVerifierSpikeContractCheck {
            verifierPackage = built.stableVerifierTool;
          };
          stable-verifier-campaign-media = stableVerifierCampaignMediaCheck;
          stable-verifier-campaign-run = stableVerifierCampaignRunCheck;
        }
        // lib.optionalAttrs (system == "x86_64-linux") {
          # This evaluates the provisioner's deliberately fixed x86_64 build
          # graph. Do not export it to the native ARM64 check set: its store
          # references include x86_64 build-time helpers by contract.
          stable-campaign-provisioner-rpi5-hardware-eval =
            pkgs.runCommand "kaiba-stable-campaign-provisioner-rpi5-hardware-eval" { }
              ''
                test ${lib.escapeShellArg stableCampaignProvisioner.hostname} = kaiba-rpi5-provisioner
                test ${lib.escapeShellArg stableCampaignProvisioner.nixosSystem.config.networking.hostName} = kaiba-rpi5-provisioner
                test ${
                  lib.escapeShellArg stableCampaignProvisioner.nixosSystem.config.fileSystems."/".device
                } = /dev/mapper/root
                test ${
                  if !(stableCampaignProvisioner.nixosSystem.config.fileSystems ? "/boot/firmware") then
                    "true"
                  else
                    "false"
                } = true
                test ${lib.escapeShellArg stableCampaignProvisioner.rootDataPartitionGUID} = bdd5be20-f7ea-56e7-ae90-4465ae950596
                test ${lib.escapeShellArg stableCampaignProvisioner.rootHashPartitionGUID} = 62616022-71fb-5036-8cc4-b7949cc6e52c
                test ${lib.escapeShellArg stableCampaignProvisioner.expectedCustomerKeyHash} = \
                  ${lib.escapeShellArg stableCampaignExpectedCustomerKeyHash}
                test ${lib.escapeShellArg stableCampaignProvisioner.unsignedArtifacts.kaibaUnsignedArtifacts.rootDeviceBinding} = \
                  rpi5-sd-card
                test ${lib.escapeShellArg stableCampaignProvisioner.unsignedArtifacts.kaibaUnsignedArtifacts.dataDevice} = \
                  /dev/mmcblk0p2
                test ${lib.escapeShellArg stableCampaignProvisioner.unsignedArtifacts.kaibaUnsignedArtifacts.hashDevice} = \
                  /dev/mmcblk0p3
                test ${lib.escapeShellArg stableCampaignProvisioner.unsignedArtifacts.kaibaUnsignedArtifacts.diskGUID} = \
                  5625eee2-0c8a-402f-8c2f-5a1347652bb2
                test ${lib.escapeShellArg stableCampaignProvisioner.unsignedArtifacts.kaibaUnsignedArtifacts.bootPartitionGUID} = \
                  59d06b61-bf85-4d77-89c3-9e5395934ff8
                test ${toString stableCampaignProvisioner.unsignedArtifacts.kaibaUnsignedArtifacts.bootPartitionSizeBytes} = \
                  134217728
                test ${lib.escapeShellArg stableCampaignProvisioner.nixosSystem.pkgs.stdenv.buildPlatform.system} = x86_64-linux
                test ${lib.escapeShellArg stableCampaignProvisioner.nixosSystem.pkgs.stdenv.hostPlatform.system} = aarch64-linux
                test ${lib.escapeShellArg stableCampaignProvisioner.inspectorPackage.stdenv.buildPlatform.system} = x86_64-linux
                test ${lib.escapeShellArg stableCampaignProvisioner.inspectorPackage.stdenv.hostPlatform.system} = aarch64-linux
                test ${lib.escapeShellArg stableCampaignProvisioner.rootImage.system} = x86_64-linux
                test ${lib.escapeShellArg stableCampaignProvisioner.firmwareTree.system} = x86_64-linux
                test ${lib.escapeShellArg stableCampaignProvisioner.unsignedArtifacts.system} = x86_64-linux
                test ${
                  if
                    builtins.elem stableCampaignProvisioner.inspectorPackage stableCampaignProvisioner.nixosSystem.config.environment.systemPackages
                  then
                    "true"
                  else
                    "false"
                } = true
                test ${
                  if
                    builtins.all (
                      assertion: assertion.assertion
                    ) stableCampaignProvisioner.nixosSystem.config.assertions
                  then
                    "true"
                  else
                    "false"
                } = true
                test ${
                  if stableCampaignProvisioner.nixosSystem.config.swapDevices == [ ] then "true" else "false"
                } = true
                test ${
                  if stableCampaignProvisioner.nixosSystem.config.zramSwap.enable then "false" else "true"
                } = true
                test ${
                  if
                    !stableCampaignProvisioner.nixosSystem.config.hardware.enableAllFirmware
                    && !stableCampaignProvisioner.nixosSystem.config.hardware.enableRedistributableFirmware
                    && !stableCampaignProvisioner.nixosSystem.config.hardware.wirelessRegulatoryDatabase
                  then
                    "true"
                  else
                    "false"
                } = true
                test ${
                  if
                    builtins.elem "systemd.gpt_auto=no" stableCampaignProvisioner.nixosSystem.config.boot.kernelParams
                  then
                    "true"
                  else
                    "false"
                } = true
                test ${
                  if
                    lib.removeSuffix "\n" (builtins.readFile stableCampaignProvisioner.developmentSSHAuthorizedKeyPath)
                    == assets.development.sshAuthorizedKey
                  then
                    "true"
                  else
                    "false"
                } = true
                test ${lib.escapeShellArg stableCampaignProvisioner.unsignedArtifacts.kaibaUnsignedArtifacts.signingStatus} = unsigned
                test ${builtins.toJSON stableCampaignProvisioner.unsignedArtifacts.kaibaUnsignedArtifacts.mutationCapable} = false
                grep -aF '/bin/kaiba-rpi5-boot-image-hash-decode' \
                  ${lib.escapeShellArg stableCampaignProvisioner.nixosSystem.config.systemd.services.kaiba-secure-boot-evidence.serviceConfig.ExecStart} \
                  > /dev/null
                test ${
                  if
                    builtins.elem "kaiba-secure-boot-evidence.service" stableCampaignProvisioner.nixosSystem.config.systemd.services.sshd.requires
                  then
                    "true"
                  else
                    "false"
                } = true
                test ${
                  if
                    builtins.elem "kaiba-secure-boot-evidence.service" stableCampaignProvisioner.nixosSystem.config.systemd.services.sshd.after
                  then
                    "true"
                  else
                    "false"
                } = true
                test ${
                  if
                    !(self.lib ? mkRpi5StableCampaignProvisioner) && !(self.lib ? mkRpi5StableCampaignProvisionerSystem)
                  then
                    "true"
                  else
                    "false"
                } = true
                test ${
                  if
                    !(builtins.tryEval (
                      (self.lib.mkRpi5SecureBootArtifacts {
                        system = "x86_64-linux";
                        rootDeviceBinding = "rpi5-sd-card";
                      }).drvPath
                    )).success
                  then
                    "true"
                  else
                    "false"
                } = true
                test ${
                  if
                    self ? rev
                    &&
                      stableCampaignProvisioner.unsignedArtifacts.drvPath
                      == self.packages.x86_64-linux.kaiba-rpi5-stable-campaign-provisioner-unsigned.drvPath
                  then
                    "true"
                  else if !(self ? rev) then
                    "true"
                  else
                    "false"
                } = true
                mkdir "$out"
              '';
        }
        // {
          stable-verifier-rpi5-hardware-eval =
            pkgs.runCommand "kaiba-stable-verifier-rpi5-hardware-eval"
              (
                {
                  nativeBuildInputs = [
                    pkgs.findutils
                    pkgs.gnugrep
                  ];
                }
                // lib.optionalAttrs (system == "aarch64-linux") {
                  firmwareTree = stableVerifierHardwareSystem.firmwareTree;
                }
              )
              ''
                test ${lib.escapeShellArg stableVerifierHardwareSystem.platformRevision} = \
                  7e39508bcf9c1da82cf11c1e22f74f9d9fd0fe10
                test ${lib.escapeShellArg stableVerifierHardwareSystem.platformNarHash} = \
                  sha256-KT/OleUMpSKsWgi0eTuqS/0GD4ucPQcvLgmvlw8ZuCM=
                test ${lib.escapeShellArg stableVerifierHardwareSystem.kernelVersion} = \
                  6.18.34-unstable_20260604
                test ${lib.escapeShellArg stableVerifierHardwareSystem.firmwarePackage.version} = \
                  1.20260521
                test ${lib.escapeShellArg stableVerifierHardwareSystem.firmwareRevision} = \
                  09267f5354d40519d82fbd2193b9e211ec304055
                test ${lib.escapeShellArg stableVerifierHardwareSystem.kexecMode} = \
                  legacy-explicit-dtb
                test ${lib.escapeShellArg stableVerifierHardwareSystem.nixosSystem.config.kaiba.stableVerifierSpike.kexecMode} = legacy-explicit-dtb
                test ${
                  if
                    builtins.all (
                      assertion: assertion.assertion
                    ) stableVerifierHardwareSystem.nixosSystem.config.assertions
                  then
                    "true"
                  else
                    "false"
                } = true
                test ${lib.escapeShellArg stableVerifierHardwareSystem.nixosSystem.config.boot.loader.raspberry-pi.bootloader} = \
                  kernelboot-legacy-unsupported
                test ${lib.escapeShellArg stableVerifierHardwareSystem.nixosSystem.config.kaiba.stableVerifierSpike.releaseDevice} = \
                  /dev/disk/by-partlabel/KAIBA_RELEASE
                test ${lib.escapeShellArg stableVerifierHardwareSystem.nixosSystem.config.kaiba.stableVerifierSpike.networkInterface} = \
                  end0
                test ${
                  if
                    (stableVerifierHardwareSystem.nixosSystem.config.hardware.raspberry-pi.config.all.dt-overlays.dwc2.enable
                      or false
                    )
                  then
                    "true"
                  else
                    "false"
                } = false
                test ${
                  toString (
                    lib.count (
                      parameter: parameter == "cma=128M"
                    ) stableVerifierHardwareSystem.nixosSystem.config.boot.kernelParams
                  )
                } = 1
                test ${
                  if
                    lib.any (
                      parameter: lib.hasPrefix "cma=" parameter && parameter != "cma=128M"
                    ) stableVerifierHardwareSystem.nixosSystem.config.boot.kernelParams
                  then
                    "false"
                  else
                    "true"
                } = true
                test ${
                  if
                    lib.any (
                      patch:
                      patch.name == "kaiba-rpi5-stable-verifier-kexec-load"
                      && patch.structuredExtraConfig ? SUSPEND
                      && patch.structuredExtraConfig ? KEXEC
                    ) stableVerifierHardwareSystem.nixosSystem.config.boot.kernelPatches
                  then
                    "true"
                  else
                    "false"
                } = true
                test ${
                  if
                    lib.any (
                      patch:
                      patch.name == "kaiba-rpi5-stable-verifier-kexec-file-require-in-place"
                      && patch.patch != null
                      && patch.structuredExtraConfig ? ARM64_KEXEC_FILE_REQUIRE_IN_PLACE
                    ) stableVerifierHardwareSystem.nixosSystem.config.boot.kernelPatches
                  then
                    "true"
                  else
                    "false"
                } = true
                test ${lib.escapeShellArg (builtins.toJSON stableVerifierHardwareSystem.nixosSystem.config.boot.initrd.systemd.services.kaiba-stable-verifier.serviceConfig.CapabilityBoundingSet)} = '["CAP_SYS_ADMIN","CAP_SYS_BOOT"]'
                test ${
                  if
                    lib.hasInfix ''"--kexec-mode" "legacy-explicit-dtb"'' stableVerifierHardwareSystem.nixosSystem.config.boot.initrd.systemd.services.kaiba-stable-verifier.serviceConfig.ExecStart
                  then
                    "true"
                  else
                    "false"
                } = true
                test ${if hardwareKexecModeRejected null then "true" else "false"} = true
                test ${if hardwareKexecModeRejected "file-live-fdt" then "true" else "false"} = true
                ${lib.optionalString (system == "aarch64-linux") ''
                  grep -Fx 'CONFIG_SUSPEND=y' \
                    ${stableVerifierHardwareSystem.kernel.configfile} > /dev/null
                  grep -Fx 'CONFIG_PM_SLEEP_SMP=y' \
                    ${stableVerifierHardwareSystem.kernel.configfile} > /dev/null
                  grep -Fx 'CONFIG_ARCH_SUPPORTS_KEXEC=y' \
                    ${stableVerifierHardwareSystem.kernel.configfile} > /dev/null
                  grep -Fx 'CONFIG_KEXEC=y' \
                    ${stableVerifierHardwareSystem.kernel.configfile} > /dev/null
                  grep -Fx 'CONFIG_CMA=y' \
                    ${stableVerifierHardwareSystem.kernel.configfile} > /dev/null
                  grep -Fx 'CONFIG_ARM64_KEXEC_FILE_REQUIRE_IN_PLACE=y' \
                    ${stableVerifierHardwareSystem.kernel.configfile} > /dev/null
                  find "$firmwareTree" -type f -printf '%P\n' | sort > "$TMPDIR/actual-files"
                  printf '%s\n' \
                    bcm2712-rpi-5-b.dtb \
                    cmdline.txt \
                    config.txt \
                    initrd \
                    kernel.img \
                    overlays/README \
                    overlays/bcm2712d0.dtbo \
                    overlays/overlay_map.dtb \
                    > "$TMPDIR/expected-files"
                  cmp "$TMPDIR/expected-files" "$TMPDIR/actual-files"
                  test -z "$(find "$firmwareTree" -type l -print -quit)"
                  test -z "$(find "$firmwareTree" ! -type d ! -type f -print -quit)"
                  test -s "$firmwareTree/initrd"
                  test -s "$firmwareTree/kernel.img"
                  test "$(tr ' ' '\n' < "$firmwareTree/cmdline.txt" | grep -Fxc 'cma=128M')" = 1
                  ! tr ' ' '\n' < "$firmwareTree/cmdline.txt" \
                    | grep -E '^cma=' \
                    | grep -Fvx 'cma=128M' > /dev/null
                  ! grep -Eq '(^|[[:space:]])init=' "$firmwareTree/cmdline.txt"
                  ! grep -Eq '^dtoverlay=vc4-kms-v3d(,.*)?$' "$firmwareTree/config.txt"
                  ! grep -Eq '^dtoverlay=dwc2(,.*)?$' "$firmwareTree/config.txt"
                ''}
                mkdir -p "$out"
                printf '%s\n' 'stable-verifier Raspberry Pi 5 hardware evaluation: pass' > "$out/result.txt"
              '';
          stable-verifier-rpi5-file-live-fdt-hardware-eval =
            pkgs.runCommand "kaiba-stable-verifier-rpi5-file-live-fdt-hardware-eval"
              (
                {
                  nativeBuildInputs = [
                    pkgs.findutils
                    pkgs.gnugrep
                  ];
                }
                // lib.optionalAttrs (system == "aarch64-linux") {
                  firmwareTree = stableVerifierFileLiveFDTHardwareSystem.firmwareTree;
                }
              )
              ''
                test ${lib.escapeShellArg stableVerifierFileLiveFDTHardwareSystem.platformRevision} = \
                  7e39508bcf9c1da82cf11c1e22f74f9d9fd0fe10
                test ${lib.escapeShellArg stableVerifierFileLiveFDTHardwareSystem.platformNarHash} = \
                  sha256-KT/OleUMpSKsWgi0eTuqS/0GD4ucPQcvLgmvlw8ZuCM=
                test ${lib.escapeShellArg stableVerifierFileLiveFDTHardwareSystem.kernelVersion} = \
                  6.18.34-unstable_20260604
                test ${lib.escapeShellArg stableVerifierFileLiveFDTHardwareSystem.firmwarePackage.version} = \
                  1.20260521
                test ${lib.escapeShellArg stableVerifierFileLiveFDTHardwareSystem.firmwareRevision} = \
                  09267f5354d40519d82fbd2193b9e211ec304055
                test ${lib.escapeShellArg stableVerifierFileLiveFDTHardwareSystem.kexecMode} = \
                  experimental-file-live-fdt
                test ${lib.escapeShellArg stableVerifierFileLiveFDTHardwareSystem.nixosSystem.config.kaiba.stableVerifierSpike.kexecMode} = experimental-file-live-fdt
                test ${lib.escapeShellArg stableVerifierFileLiveFDTHardwareSystem.nixosSystem.config.kaiba.stableVerifierSpike.networkInterface} = end0
                test ${
                  if fileLiveFDTHardwareArgumentsRejected { extraModules = [ ]; } then "true" else "false"
                } = true
                test ${
                  if
                    fileLiveFDTHardwareArgumentsRejected {
                      kexecMode = "legacy-explicit-dtb";
                    }
                  then
                    "true"
                  else
                    "false"
                } = true
                test ${
                  if
                    builtins.all (
                      assertion: assertion.assertion
                    ) stableVerifierFileLiveFDTHardwareSystem.nixosSystem.config.assertions
                  then
                    "true"
                  else
                    "false"
                } = true
                test ${
                  if
                    lib.any (
                      assertion:
                      assertion.assertion
                      && lib.hasInfix "experimental-file-live-fdt mode requires exactly one reviewed" assertion.message
                    ) stableVerifierFileLiveFDTHardwareSystem.nixosSystem.config.assertions
                  then
                    "true"
                  else
                    "false"
                } = true
                test ${lib.escapeShellArg stableVerifierFileLiveFDTHardwareSystem.nixosSystem.config.boot.loader.raspberry-pi.bootloader} = kernelboot-legacy-unsupported
                test ${
                  if
                    stableVerifierFileLiveFDTHardwareSystem.nixosSystem.config.hardware.raspberry-pi.config.all.dt-overlays.dwc2.enable
                    && stableVerifierFileLiveFDTHardwareSystem.nixosSystem.config.hardware.raspberry-pi.config.all.dt-overlays.dwc2.params.dr_mode.enable
                    &&
                      stableVerifierFileLiveFDTHardwareSystem.nixosSystem.config.hardware.raspberry-pi.config.all.dt-overlays.dwc2.params.dr_mode.value
                      == "peripheral"
                  then
                    "true"
                  else
                    "false"
                } = true
                test ${
                  toString (
                    lib.count (
                      parameter: parameter == "cma=128M"
                    ) stableVerifierFileLiveFDTHardwareSystem.nixosSystem.config.boot.kernelParams
                  )
                } = 1
                test ${
                  if
                    lib.any (
                      parameter: parameter != "cma=128M" && lib.hasPrefix "cma=" parameter
                    ) stableVerifierFileLiveFDTHardwareSystem.nixosSystem.config.boot.kernelParams
                  then
                    "false"
                  else
                    "true"
                } = true
                test ${
                  toString (
                    lib.count (
                      patch:
                      patch.name == "kaiba-rpi5-stable-verifier-kexec-file-require-in-place"
                      && patch.patch != null
                      && toString patch.patch == toString ./nix/patches/arm64-kexec-file-require-in-place.patch
                      && (patch.structuredExtraConfig.ARM64_KEXEC_FILE_REQUIRE_IN_PLACE or null) == lib.kernel.yes
                    ) stableVerifierFileLiveFDTHardwareSystem.nixosSystem.config.boot.kernelPatches
                  )
                } = 1
                test ${
                  if
                    lib.any (
                      patch: patch.name == "kaiba-rpi5-stable-verifier-kexec-load"
                    ) stableVerifierFileLiveFDTHardwareSystem.nixosSystem.config.boot.kernelPatches
                  then
                    "false"
                  else
                    "true"
                } = true
                test ${lib.escapeShellArg (builtins.toJSON stableVerifierFileLiveFDTHardwareSystem.nixosSystem.config.boot.initrd.systemd.services.kaiba-stable-verifier.serviceConfig.CapabilityBoundingSet)} = '["CAP_SYS_BOOT"]'
                test ${lib.escapeShellArg (builtins.toJSON stableVerifierFileLiveFDTHardwareSystem.nixosSystem.config.boot.initrd.systemd.services.kaiba-stable-verifier.serviceConfig.AmbientCapabilities)} = '["CAP_SYS_BOOT"]'
                test ${
                  if
                    lib.hasInfix ''"--kexec-mode" "experimental-file-live-fdt"'' stableVerifierFileLiveFDTHardwareSystem.nixosSystem.config.boot.initrd.systemd.services.kaiba-stable-verifier.serviceConfig.ExecStart
                  then
                    "true"
                  else
                    "false"
                } = true
                test ${
                  if
                    lib.hasInfix "--dtb" stableVerifierFileLiveFDTHardwareSystem.nixosSystem.config.boot.initrd.systemd.services.kaiba-stable-verifier.serviceConfig.ExecStart
                    || lib.hasInfix "--device-tree" stableVerifierFileLiveFDTHardwareSystem.nixosSystem.config.boot.initrd.systemd.services.kaiba-stable-verifier.serviceConfig.ExecStart
                  then
                    "false"
                  else
                    "true"
                } = true
                test ${lib.escapeShellArg stableVerifierFileLiveFDTHardwareSystem.firmwareTree.kaibaRpi5StableVerifierPlatform.kexecMode} = experimental-file-live-fdt
                test ${
                  if
                    stableVerifierFileLiveFDTHardwareSystem.firmwareTree.kaibaRpi5StableVerifierPlatform.liveFirmwareDeviceTreeHandoff
                  then
                    "true"
                  else
                    "false"
                } = true
                test ${
                  if
                    stableVerifierFileLiveFDTHardwareSystem.firmwareTree.kaibaRpi5StableVerifierPlatform.userspaceDeviceTreeHandoff
                  then
                    "true"
                  else
                    "false"
                } = false
                ${lib.optionalString (system == "aarch64-linux") ''
                  grep -Fx 'CONFIG_KEXEC_FILE=y' \
                    ${stableVerifierFileLiveFDTHardwareSystem.kernel.configfile} > /dev/null
                  ! grep -Fx 'CONFIG_KEXEC=y' \
                    ${stableVerifierFileLiveFDTHardwareSystem.kernel.configfile} > /dev/null
                  grep -Fx '# CONFIG_KEXEC_SIG is not set' \
                    ${stableVerifierFileLiveFDTHardwareSystem.kernel.configfile} > /dev/null
                  grep -Fx 'CONFIG_CMA=y' \
                    ${stableVerifierFileLiveFDTHardwareSystem.kernel.configfile} > /dev/null
                  grep -Fx 'CONFIG_ARM64_KEXEC_FILE_REQUIRE_IN_PLACE=y' \
                    ${stableVerifierFileLiveFDTHardwareSystem.kernel.configfile} > /dev/null
                  find "$firmwareTree" -type f -printf '%P\n' | sort > "$TMPDIR/actual-files"
                  printf '%s\n' \
                    bcm2712-rpi-5-b.dtb \
                    cmdline.txt \
                    config.txt \
                    initrd \
                    kernel.img \
                    overlays/README \
                    overlays/bcm2712d0.dtbo \
                    overlays/dwc2.dtbo \
                    overlays/overlay_map.dtb \
                    > "$TMPDIR/expected-files"
                  cmp "$TMPDIR/expected-files" "$TMPDIR/actual-files"
                  test -z "$(find "$firmwareTree" -type l -print -quit)"
                  test -z "$(find "$firmwareTree" ! -type d ! -type f -print -quit)"
                  test -s "$firmwareTree/initrd"
                  test -s "$firmwareTree/kernel.img"
                  test "$(tr ' ' '\n' < "$firmwareTree/cmdline.txt" | grep -Fxc 'cma=128M')" = 1
                  ! tr ' ' '\n' < "$firmwareTree/cmdline.txt" \
                    | grep -E '^cma=' \
                    | grep -Fvx 'cma=128M' > /dev/null
                  ! grep -Eq '(^|[[:space:]])init=' "$firmwareTree/cmdline.txt"
                  ! grep -Eq '^dtoverlay=vc4-kms-v3d(,.*)?$' "$firmwareTree/config.txt"
                  test "$(grep -Ec '^dtoverlay=dwc2(,.*)?$' "$firmwareTree/config.txt")" = 1
                  test "$(grep -Fxc 'dtparam=dr_mode=peripheral' "$firmwareTree/config.txt")" = 1
                  test "$(grep -Fxc 'dtoverlay=' "$firmwareTree/config.txt")" = 1
                  printf '%s\n' \
                    'dtoverlay=dwc2' \
                    'dtparam=dr_mode=peripheral' \
                    'dtoverlay=' \
                    > "$TMPDIR/expected-dwc2-block"
                  grep -Fx -A 2 'dtoverlay=dwc2' "$firmwareTree/config.txt" \
                    > "$TMPDIR/actual-dwc2-block"
                  cmp "$TMPDIR/expected-dwc2-block" "$TMPDIR/actual-dwc2-block"
                ''}
                mkdir -p "$out"
                printf '%s\n' \
                  'stable-verifier Raspberry Pi 5 file/live-FDT hardware evaluation: pass' \
                  > "$out/result.txt"
              '';
          media-staging-fixture = provisioning.mediaStagingFixtureContract;
          production-media-staging = provisioning.productionMediaStagingContract;
          signed-release-manifest = provisioning.signedReleaseManifestContract;
          signed-boot-plan = provisioning.signedBootPlanContract;
          signing-approval = built.signingApprovalTool;
          signing-receipts = built.signingReceiptsTool;
          signing-receipts-integration = provisioning.signingReceiptVerificationContract;
          unfused-capsule = provisioning.unfusedCapsuleContract;
          ubuntu-provisioning-authority-deployment = import ./tests/ubuntu-provisioning-authority.nix {
            deployment = mkUbuntuProvisioningAuthorityDeployment { inherit system; };
            runtimeDeployment = mkUbuntuProvisioningAuthorityDeployment {
              inherit system;
              listenAddress = "127.0.0.1";
              controlPort = 38091;
              auditPort = 38092;
            };
            inherit pkgs;
          };
          ubuntu-signing-gate-deployment = mkUbuntuSigningGateDeployment { inherit system; };
          station-ui =
            pkgs.runCommand "kaiba-provisioning-station-ui-check"
              {
                nativeBuildInputs = [
                  pkgs.nodejs
                  pkgs.python3
                ];
              }
              ''
                set -eu
                export PYTHONDONTWRITEBYTECODE=1
                cd ${stationUITestRoot}
                node --check internal/provisioning/stationui/web/app.js
                node --check internal/provisioning/stationui/web/transport.js
                node --check internal/provisioning/livestation/web/app.js
                node internal/provisioning/livestation/web/app.test.cjs
                export KAIBA_STATION_PAGES=${built.stationPages}
                node --test tests/station-ui/transport.test.mjs
                python3 -m unittest discover -s tests/station-ui -p 'test_*.py' -v
                for asset in index.html styles.css transport.js app.js; do
                  cmp "internal/provisioning/stationui/web/$asset" "${built.stationPages}/$asset"
                done
                test "$(find ${built.stationPages} -maxdepth 1 -type f | wc -l)" -eq 6
                mkdir -p "$out"
                printf '%s\n' 'provisioning station UI: pass' > "$out/results.txt"
              '';
        }
        // lib.optionalAttrs (system == "x86_64-linux") {
          stable-campaign-provisioner-signed-boot-filesystem =
            stableCampaignProvisionerSignedBootFilesystemCheck;
          stable-campaign-signing = stableCampaignSigningCheck;
          stable-verifier-initramfs-vm = pkgs.linkFarm "kaiba-stable-verifier-initramfs-vm" [
            {
              name = "fail-closed";
              path = stableVerifierInitramfsVM.failure;
            }
            {
              name = "signed-handoff";
              path = stableVerifierInitramfsVM.signedHandoff;
            }
          ];
          signing-ceremony = import ./tests/signing-ceremony.nix {
            ceremony = mkDevelopmentSigningCeremony {
              inherit system;
              sourceRevision = "0000000000000000000000000000000000000000";
              sourceTreeClean = false;
            };
            inherit pkgs;
          };
        }
        // lib.optionalAttrs (system == "aarch64-linux") {
          # Build the full provisioner artifact contract natively. The
          # production package remains an x86_64 cross-build, while CI avoids
          # rebuilding the AArch64 userspace through the cross toolchain.
          stable-campaign-provisioner-unsigned-artifacts = stableCampaignProvisionerArtifactCheck;
          # This check builds and boots a native AArch64 NixOS closure. Keep it
          # on the native ARM64 CI runner; exporting it under x86_64-linux makes
          # the x86 job require an otherwise unconfigured ARM builder.
          stable-verifier-aarch64-kexec-vm = stableVerifierAarch64KexecVM;
          stable-handoff-aarch64-kexec-file-vm = stableHandoffAarch64KexecFileVM;
          operator-packages = pkgs.linkFarm "kaiba-operator-packages-check" [
            {
              name = "kaiba-provision";
              path = built.provision;
            }
            {
              name = "kaiba-provision-station";
              path = built.liveStation;
            }
            {
              name = "kaiba-provision-station-demo";
              path = built.stationDemo;
            }
            {
              name = "kaiba-provision-station-pages";
              path = built.stationPages;
            }
            {
              name = "provisioning-test-result";
              path = provisioning.provisioningTestResult;
            }
          ];
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          reportPython = pkgs.python3.withPackages (pythonPackages: [ pythonPackages.jsonschema ]);
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              check-jsonschema
              go
              gopls
              gotools
              jq
              nodejs
              reportPython
              nixfmt-tree
            ];
          };
        }
      );

      formatter = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        pkgs.nixfmt-tree
      );
    };
}
