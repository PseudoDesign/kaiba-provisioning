{
  lib,
  pkgs,
  mkHardware,
  mkUnsignedBoot,
  mkSigningPlan,
}:

{
  publicInputs,
  sourceRevision,
  sourceDateEpoch,
}:

let
  names = [
    "authority-ca.pem"
    "candidate.json"
    "policy.json"
    "root-public.pem"
  ];
  directory = builtins.readDir publicInputs;
  configBytes = builtins.readFile (publicInputs + "/candidate.json");
  config = builtins.fromJSON configBytes;
  configKeys = [
    "audience"
    "authority_key_id"
    "authority_url"
    "cohort_id"
    "logical_identity"
    "minimum_security_epoch"
    "schema_version"
    "slot_id"
    "verifier_version"
  ];
  identifier =
    value: builtins.isString value && builtins.match "[a-z0-9][a-z0-9._:-]{0,127}" value != null;
  positiveInt = value: builtins.isInt value && value > 0 && value <= 2147483647;
  # Copy only the closed public input set, never an operator evidence directory.
  inputs = builtins.path {
    path = publicInputs;
    name = "kaiba-stable-verifier-candidate-public-inputs";
  };
  validatedInputs =
    pkgs.runCommand "kaiba-stable-verifier-candidate-validated-inputs"
      {
        inputsPath = inputs;
        expectedConfig = builtins.toJSON config;
        nativeBuildInputs = [
          pkgs.python3
          pkgs.openssl
        ];
      }
      ''
        python3 ${./stable-verifier-candidate-inputs.py}
        openssl pkey -pubin -in "$out/root-public.pem" -noout
        openssl x509 -in "$out/authority-ca.pem" -noout
      '';
  hardware = mkHardware {
    policy = "${validatedInputs}/policy.json";
    rootPublicKey = "${validatedInputs}/root-public.pem";
    authorityCACertificate = "${validatedInputs}/authority-ca.pem";
    verifierVersion = config.verifier_version;
    cohortID = config.cohort_id;
    slotID = config.slot_id;
    minimumSecurityEpoch = config.minimum_security_epoch;
    authorityURL = config.authority_url;
    authorityKeyID = config.authority_key_id;
    audience = config.audience;
    logicalIdentity = config.logical_identity;
  };
  unsignedBoot = mkUnsignedBoot {
    inherit sourceRevision;
    firmwareTree = hardware.firmwareTree;
    firmwareAllowlist = [
      "bcm2712-rpi-5-b.dtb"
      "cmdline.txt"
      "config.txt"
      "initrd"
      "kernel.img"
      "overlays/README"
      "overlays/bcm2712d0.dtbo"
      "overlays/dwc2.dtbo"
      "overlays/overlay_map.dtb"
    ];
    verifierPackage = hardware.nixosSystem.config.kaiba.stableVerifierSpike.package;
    stableVerifierPolicy = "${validatedInputs}/policy.json";
    rootPublicKey = "${validatedInputs}/root-public.pem";
    authorityCACertificate = "${validatedInputs}/authority-ca.pem";
    piPlatformSourceRevision = hardware.platformRevision;
    piPlatformSourceNarHash = hardware.platformNarHash;
    bootImageSizeMiB = 96;
  };
  signingPlan = mkSigningPlan {
    inherit sourceRevision sourceDateEpoch;
    stableVerifierUnsignedBoot = unsignedBoot;
  };
in
assert lib.assertMsg (
  pkgs.stdenv.buildPlatform.system == "aarch64-linux"
  && pkgs.stdenv.hostPlatform.system == "aarch64-linux"
) "stable verifier candidates require native aarch64-linux construction";
assert lib.assertMsg (
  builtins.attrNames directory == names && lib.all (name: directory.${name} == "regular") names
) "publicInputs must contain exactly four regular public input files";
assert lib.assertMsg (
  builtins.isAttrs config && builtins.attrNames config == configKeys
) "candidate.json must use the closed stable-verifier candidate schema";
assert lib.assertMsg (
  builtins.stringLength configBytes <= 16384
  && config.schema_version == "kaiba.provisioning.rpi5-stable-verifier-candidate/v1alpha1"
  && positiveInt config.verifier_version
  && positiveInt config.minimum_security_epoch
  && lib.all identifier [
    config.cohort_id
    config.slot_id
    config.authority_key_id
    config.audience
    config.logical_identity
  ]
  && builtins.isString config.authority_url
  && builtins.stringLength config.authority_url <= 2048
  && builtins.match "https://[^[:space:]]+" config.authority_url != null
) "candidate.json contains invalid configuration fields";
assert lib.assertMsg (
  builtins.isString sourceRevision
  && builtins.match "[0-9a-f]{40}" sourceRevision != null
  && builtins.isInt sourceDateEpoch
  && sourceDateEpoch > 0
  && sourceDateEpoch <= 253402300799
) "candidate source revision and epoch must be explicit canonical values";
assert lib.assertMsg (
  hardware.kexecMode == "experimental-file-live-fdt"
  && hardware.nixosSystem.pkgs.stdenv.buildPlatform.system == "aarch64-linux"
  && hardware.nixosSystem.pkgs.stdenv.hostPlatform.system == "aarch64-linux"
) "candidate hardware must retain the native file/live-FDT contract";
{
  inherit
    unsignedBoot
    signingPlan
    hardware
    validatedInputs
    ;
  source = { inherit sourceRevision sourceDateEpoch; };
  signingPerformed = false;
  hardwareObserved = false;
  productionReady = false;
}
