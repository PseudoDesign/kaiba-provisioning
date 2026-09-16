# Evaluate only after a reviewed signing operation has produced public results.
# All four path arguments contain public material, never key/PIN/secret files.
{
  revision,
  authorization,
  signedOutput,
  receiptExport,
  targetSizeBytes,
  system ? builtins.currentSystem,
}:
assert builtins.match "[0-9a-f]{40}" revision != null;
let
  source = builtins.getFlake "git+https://github.com/PseudoDesign/kaiba-provisioning?rev=${revision}";
  publicPath = value: builtins.path { path = /. + value; };
  verifiedSigning = source.lib.mkRpi5VerifiedNativeOfflineSigning {
    inherit system;
    signingPlan = source.packages.aarch64-linux.kaiba-rpi5-native-offline-signing-plan;
    authorization = publicPath authorization;
    signedOutput = publicPath signedOutput;
    receiptExport = publicPath receiptExport;
  };
in
source.lib.mkRpi5NativeOfflineMediaHandoff { inherit system verifiedSigning targetSizeBytes; }
