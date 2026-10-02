# File-only package construction. No device or physical-approval interface.
{
  kaiba ? builtins.getFlake "github:PseudoDesign/kaiba-provisioning/c4b9dcf9b0460cca889e4555c75a1f9a20f70754",
  nativeComponent,
  nativeSourceRevision,
}:
assert kaiba.rev == "c4b9dcf9b0460cca889e4555c75a1f9a20f70754";
kaiba.lib.mkRpi5StableCampaignStagingAssembly {
  system = "x86_64-linux";
  descriptor = ./descriptor.json;
  inherit nativeComponent;
  sourceRevision = nativeSourceRevision;
  stagingPlan = builtins.storePath /nix/store/wfd8y6sydc8gi6qrbk2aknmn3q7fbxxa-kaiba-task1-proposed-current-nvme-staging-plan.json;
  payloads.release-filesystem = builtins.storePath /nix/store/8ql5xf1hg94b592jr8n56j5h5mhjb2hj-kaiba-task1-retained-release-filesystem.img;
}
