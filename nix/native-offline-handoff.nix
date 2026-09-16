{
  pkgs,
  lib,
  built,
}:
let
  tool = built.nativeOfflineSigningTool;
  storeBacked =
    value:
    let
      path = toString value;
    in
    lib.hasPrefix "${builtins.storeDir}/" path
    && builtins.match "[A-Za-z0-9+._/-]+" path != null
    && !(lib.hasInfix "/../" path)
    && !(lib.hasInfix "/./" path)
    && !(lib.hasInfix "//" path)
    && !(lib.hasSuffix "/.." path);
  mkSigningPlan =
    {
      candidate,
      review,
      sourceRevision,
      sourceDateEpoch,
      signerReview ? ../signers/development-prototype/independent-review-2026-08-27.json,
      publicKey ? ../signers/development-prototype/reviewed-boot-public.pem,
    }:
    assert builtins.match "[0-9a-f]{40}" sourceRevision != null;
    assert builtins.isInt sourceDateEpoch && sourceDateEpoch > 0;
    assert lib.all storeBacked [
      candidate.unsignedArtifacts
      review
      signerReview
      publicKey
    ];
    pkgs.runCommand "kaiba-rpi5-native-offline-signing-plan"
      {
        outputs = [
          "out"
          "input"
        ];
        nativeBuildInputs = [
          (pkgs.python3.withPackages (p: [ p.pycryptodomex ]))
          pkgs.openssl
          pkgs.cryptsetup
          pkgs.mtools
          tool
        ];
        passthru.kaibaNativeOffline = { inherit candidate review sourceRevision; };
      }
      ''
        python3 ${../scripts/native-offline/prepare-signing.py} \
          ${candidate.unsignedArtifacts} ${review} ${publicKey} ${signerReview} \
          "$out" "$input" ${lib.escapeShellArg sourceRevision} ${toString sourceDateEpoch} \
          ${pkgs.raspberrypi-eeprom.src}/tools/rpi-bootloader-key-convert
        kaiba-rpi5-native-offline-signing validate-plan --plan "$out"
        kaiba-rpi5-native-offline-signing validate-unsigned --plan "$out" --manifest "$input/manifest.json"
      '';
  mkVerified =
    {
      signingPlan,
      authorization,
      signedOutput,
      receiptExport,
    }:
    assert signingPlan ? kaibaNativeOffline;
    assert lib.all storeBacked [
      signingPlan
      authorization
      signedOutput
      receiptExport
    ];
    pkgs.runCommand "kaiba-rpi5-native-offline-verified-signing"
      {
        nativeBuildInputs = [ tool ];
        passthru.kaibaNativeOffline = signingPlan.kaibaNativeOffline // {
          inherit signingPlan;
        };
      }
      ''
        kaiba-rpi5-native-offline-signing validate-unsigned \
          --plan ${signingPlan} --manifest ${signingPlan.input}/manifest.json
        kaiba-rpi5-native-offline-signing finalize \
          --plan ${signingPlan} --signed ${signedOutput} \
          --approval ${authorization}/approval.json \
          --registry ${authorization}/signing-grants.json \
          --receipt-export ${receiptExport} --output "$out"
      '';
  mkMedia =
    { verifiedSigning, targetSizeBytes }:
    assert verifiedSigning ? kaibaNativeOffline;
    assert storeBacked verifiedSigning;
    assert builtins.isInt targetSizeBytes && targetSizeBytes > 0 && lib.mod targetSizeBytes 512 == 0;
    let
      contract = verifiedSigning.kaibaNativeOffline;
      hardware = pkgs.writeText "native-offline-hardware.json" (
        builtins.toJSON (
          import ../config/hardware/raspberry-pi-5-sacrificial-development-pi-local-nvme-v1alpha2.nix
        )
      );
    in
    pkgs.runCommand "kaiba-rpi5-native-offline-media-handoff"
      {
        nativeBuildInputs = [
          pkgs.python3
          pkgs.dosfstools
          pkgs.mtools
          pkgs.gptfdisk
          pkgs.cryptsetup
          pkgs.e2fsprogs
        ];
      }
      ''
        python3 ${../scripts/native-offline/prepare-media.py} \
          ${verifiedSigning} ${contract.candidate.unsignedArtifacts} \
          ${contract.signingPlan.input}/manifest.json ${contract.review} \
          ${hardware} \
          ${toString targetSizeBytes} "$out" ${../scripts/native-offline/root-probe-plan.py}
      '';
in
{
  inherit mkSigningPlan mkVerified mkMedia;
}
