# File-only construction. Select an attribute to build; none executes hardware.
# JSON and review inputs are public bindings, never raw evidence or secret data.
{
  revision,
  experimentFile,
  expectedCustomerKeyHash,
  hostFile,
  captureSettingsFile,
  slotReview,
  imageReview,
  recoveryReview,
  targetSizeBytes,
  authorization ? null,
  signedOutput ? null,
  receiptExport ? null,
  system ? builtins.currentSystem,
}:
assert builtins.match "[0-9a-f]{40}" revision != null;
let
  source = builtins.getFlake "git+https://github.com/PseudoDesign/kaiba-provisioning?rev=${revision}";
  publicPath = value: builtins.path { path = /. + value; };
  readJSON = value: builtins.fromJSON (builtins.readFile (publicPath value));
  candidate = source.lib.mkRpi5DeviceSecretExperiment {
    experiment = readJSON experimentFile;
    sourceRevision = revision;
    inherit expectedCustomerKeyHash;
  };
  signingPlan = source.lib.mkRpi5DeviceSecretSigningPlan {
    system = "aarch64-linux";
    inherit candidate;
    sourceDateEpoch = source.lastModified;
  };
  verifiedSigning = source.lib.mkRpi5VerifiedNativeOfflineSigning {
    inherit system signingPlan;
    authorization = publicPath authorization;
    signedOutput = publicPath signedOutput;
    receiptExport = publicPath receiptExport;
  };
  packet = source.lib.mkRpi5DeviceSecretExecutionPacket {
    inherit system verifiedSigning targetSizeBytes;
    host = readJSON hostFile;
    captureSettings = readJSON captureSettingsFile;
    slotReview = publicPath slotReview;
    imageReview = publicPath imageReview;
    recoveryReview = publicPath recoveryReview;
  };
in
{
  inherit candidate signingPlan packet;
  executor = source.lib.mkRpi5DeviceSecretMediaExecutor { inherit system packet; };
  report = source.lib.mkRpi5DeviceSecretReport { inherit system packet; };
}
