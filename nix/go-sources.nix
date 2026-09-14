{
  lib,
  root ? ../.,
}:

let
  # Filter once, directly from the original repository. Copying a broad source
  # inside a derivation still puts the whole tree in that derivation's key, and
  # filtering an already filtered store subpath can break lazy-tree evaluation.
  source = fileset: lib.fileset.toSource { inherit root fileset; };
  runtimeFiles =
    paths:
    lib.fileset.unions (
      map (
        path:
        lib.fileset.fileFilter (file: file.hasExt "go" && !(lib.hasSuffix "_test.go" file.name)) (
          root + "/${path}"
        )
      ) paths
    );
  runtimeSource =
    paths:
    source (
      lib.fileset.unions [
        (root + "/go.mod")
        (runtimeFiles paths)
      ]
    );
  # These are the runtime import closures, shared where the entry points use
  # the same verifier libraries. Tests retain the complete application source.
  # Add any future go:embed assets explicitly alongside their runtime package.
  verifierLibraries = [
    "internal/provisioning/bundle"
    "internal/provisioning/eepromsigning"
    "internal/provisioning/rpi5kexecinput"
    "internal/provisioning/stableverifier"
  ];
in
{
  application = source (
    lib.fileset.unions (
      map (path: root + "/${path}") [
        "cmd"
        "config/rpi5-prototype-release/platform-adapter-v1alpha1.json"
        "go.mod"
        "internal"
        "policies/raspberry-pi-5-development-posture-v1alpha1.json"
        "profiles/device-classes/raspberry-pi-5-model-b-v1alpha1.json"
        "schemas"
        "signers/development-prototype/independent-review-2026-08-27.json"
      ]
    )
  );
  stableVerifier = runtimeSource (
    verifierLibraries
    ++ [
      "cmd/kaiba-rpi5-stable-verifier"
      "internal/provisioning/releaseauthorization"
      "internal/provisioning/stablehandoff"
      "internal/provisioning/verifierevents"
    ]
  );
  stableCampaignGPTInspector = runtimeSource (
    verifierLibraries
    ++ [
      "cmd/kaiba-rpi5-stable-campaign-gpt-inspect"
      "internal/provisioning/campaignmedia"
      "internal/provisioning/mediacontract"
      "internal/provisioning/mediadevice"
      "internal/provisioning/mediainventory"
      "internal/provisioning/stablecampaign"
      "internal/provisioning/verifierevents"
    ]
  );
  kexecInputValidator = runtimeSource [
    "cmd/kaiba-rpi5-kexec-input-validate"
    "internal/provisioning/rpi5kexecinput"
  ];
  verifierTestAuthority = runtimeSource [
    "cmd/kaiba-rpi5-verifier-test-authority"
    "internal/provisioning/mtls"
    "internal/provisioning/releaseauthorization"
  ];
  oneBootProve = runtimeSource [
    "cmd/kaiba-rpi5-one-boot-prove"
    "internal/provisioning/releaseauthorization"
  ];
  verifierVM = runtimeSource verifierLibraries;
  stableHandoffVM = runtimeSource [ "internal/provisioning/stablehandoff" ];
  verifierFixture = source (
    lib.fileset.unions [
      (root + "/go.mod")
      (root + "/tests/deterministic-rsa-fixture.py")
      (runtimeFiles (
        verifierLibraries
        ++ [
          "internal/provisioning/releaseauthorization"
          "tests/stable-verifier-vm-fixture"
        ]
      ))
    ]
  );
}
