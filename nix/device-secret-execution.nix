{
  pkgs,
  lib,
  built,
  platformRevision,
  platformNarHash,
  lockFile,
}:
let
  native = import ./native-offline-handoff.nix { inherit pkgs lib built; };
  source = ../scripts/device-secret;
  storeBacked =
    x:
    lib.hasPrefix "${builtins.storeDir}/" (toString x)
    && builtins.match "[A-Za-z0-9+._/-]+" (toString x) != null
    && !(lib.hasInfix "/../" (toString x));
  mkSigningPlan =
    {
      candidate,
      sourceDateEpoch,
      publicKey ? ../signers/development-prototype/reviewed-boot-public.pem,
      signerReview ? ../signers/development-prototype/independent-review-2026-08-27.json,
    }:
    assert candidate ? deviceSecretExperiment;
    let
      baselineReview = import ./rpi5-native-offline-review.nix {
        inherit
          pkgs
          candidate
          platformRevision
          platformNarHash
          lockFile
          ;
      };
      experiment = candidate.nixosSystem.config.system.build.kaibaDeviceSecretExperimentConfig;
      review =
        pkgs.runCommand "kaiba-device-secret-signing-review" { nativeBuildInputs = [ pkgs.jq ]; }
          ''
            mkdir "$out"
            cp ${baselineReview}/* "$out/"
            chmod u+w "$out/review.json"
            cp ${experiment}/experiment.json "$out/experiment.json"
            jq --arg digest "sha256:$(sha256sum "$out/experiment.json" | cut -d ' ' -f 1)" \
              '. + {device_secret_experiment_digest: $digest, device_secret_execution: "pending-separate-authority"}' \
              ${baselineReview}/review.json > "$out/review.json"
          '';
    in
    native.mkSigningPlan {
      inherit
        candidate
        review
        sourceDateEpoch
        publicKey
        signerReview
        ;
      sourceRevision = candidate.sourceRevision;
    };
  mkPacket =
    {
      verifiedSigning,
      targetSizeBytes,
      host,
      captureSettings,
      slotReview,
      imageReview,
      recoveryReview,
    }:
    assert verifiedSigning.kaibaNativeOffline.candidate ? deviceSecretExperiment;
    assert lib.all storeBacked [
      slotReview
      imageReview
      recoveryReview
    ];
    let
      media = native.mkMedia { inherit verifiedSigning targetSizeBytes; };
      experiment = "${verifiedSigning.kaibaNativeOffline.review}/experiment.json";
      hostFile = pkgs.writeText "device-secret-host.json" (builtins.toJSON host);
      captureFile = pkgs.writeText "device-secret-capture.json" (builtins.toJSON captureSettings);
    in
    pkgs.runCommand "kaiba-device-secret-execution-packet"
      {
        nativeBuildInputs = [
          pkgs.python3
          pkgs.gptfdisk
        ];
        passthru.kaibaDeviceSecretPacket = true;
      }
      ''
        python3 -I ${source}/packet.py ${media} ${experiment} ${hostFile} ${captureFile} \
          ${slotReview} ${imageReview} ${recoveryReview} "$out" compose-files-only
      '';
  mkExecutor =
    { packet }:
    assert packet.kaibaDeviceSecretPacket or false;
    pkgs.writeShellApplication {
      name = "kaiba-device-secret-media";
      runtimeInputs = [
        pkgs.systemd
        pkgs.util-linux
      ];
      text = ''
        if [ "$#" -ne 1 ]; then
          echo 'Choose exactly one: describe, status, backup, stage, verify, restore' >&2
          exit 2
        fi
        test ! -e ${source}/__pycache__
        exec ${pkgs.python3}/bin/python3 -I -B ${source}/executor.py ${packet} "$1"
      '';
      derivationArgs.passthru = { inherit packet; };
    };
  mkReport =
    { packet }:
    assert packet.kaibaDeviceSecretPacket or false;
    pkgs.writeShellApplication {
      name = "kaiba-device-secret-report";
      text = ''
        if [ "$#" -ne 2 ]; then
          echo 'Usage: kaiba-device-secret-report /private/capture-state /new/private-draft.json' >&2
          exit 2
        fi
        exec ${pkgs.python3}/bin/python3 -I ${source}/report.py ${packet} "$1" "$2"
      '';
    };
in
{
  inherit
    mkSigningPlan
    mkPacket
    mkExecutor
    mkReport
    ;
}
