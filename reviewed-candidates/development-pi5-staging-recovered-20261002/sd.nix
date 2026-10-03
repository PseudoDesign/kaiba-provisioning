# File-only package construction. No device or physical-approval interface.
{
  kaiba ? builtins.getFlake "github:PseudoDesign/kaiba-provisioning/c4b9dcf9b0460cca889e4555c75a1f9a20f70754",
}:
assert kaiba.rev == "c4b9dcf9b0460cca889e4555c75a1f9a20f70754";
kaiba.lib.mkRpi5StableCampaignStaging {
  system = "x86_64-linux";
  leg = "malak-sd";
  stagingPlan = builtins.storePath /nix/store/wfd8y6sydc8gi6qrbk2aknmn3q7fbxxa-kaiba-task1-proposed-current-nvme-staging-plan.json;
  payloads = {
    boot-filesystem = builtins.storePath /nix/store/nkkf7zgfhs8ar5vzn9cksac6ksyd46mp-kaiba-task1-retained-boot-filesystem.img;
    root-data = builtins.storePath /nix/store/3wrh182ninz2j896aa2h7lhdyhfq0mjp-kaiba-task1-retained-root-data.img;
    root-hash = builtins.storePath /nix/store/l5dlk0hpp90ikmmgglq0zs1x6xcp1580-kaiba-task1-retained-root-hash.img;
  };
}
