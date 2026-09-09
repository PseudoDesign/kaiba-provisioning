{
  pkgs,
  source ? ../.,
  kernel ? pkgs.writeText "stable-verifier-vm-kernel" "fixture kernel",
  initramfs ? pkgs.writeText "stable-verifier-vm-initramfs" "fixture initramfs",
  deviceTree ? pkgs.writeText "stable-verifier-vm-device-tree" "fixture device tree",
  commandLine ? pkgs.writeText "stable-verifier-vm-command-line" ''
    console=ttyS0 kaiba.vm=1
  '',
  rootImage ? pkgs.writeText "stable-verifier-vm-root-image" "fixture root image",
  dmVerity ? pkgs.writeText "stable-verifier-vm-dm-verity" ''
    {"root_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
  '',
  slot ? pkgs.writeText "stable-verifier-vm-slot" ''
    spike
  '',
}:

let
  fixtureBuilder = pkgs.buildGoModule {
    pname = "kaiba-stable-verifier-vm-fixture-builder";
    version = "0.1.0";
    inherit source;
    src = source;
    subPackages = [ "tests/stable-verifier-vm-fixture" ];
    vendorHash = null;
    env.CGO_ENABLED = 0;
    doCheck = false;
  };
  rawFixture =
    pkgs.runCommand "kaiba-stable-verifier-vm-fixture"
      {
        nativeBuildInputs = [
          pkgs.jq
          pkgs.python3
        ];
      }
      ''
        set -euo pipefail
        umask 077

        python3 ${source}/tests/deterministic-rsa-fixture.py \
          --private "$TMPDIR/root-rsa-private.pem"
        python3 ${source}/tests/deterministic-rsa-fixture.py \
          --label stable-verifier-vm-delegated \
          --private "$TMPDIR/delegated-rsa-private.pem"
        ${fixtureBuilder}/bin/stable-verifier-vm-fixture \
          --output "$out" \
          --root-rsa-private-key "$TMPDIR/root-rsa-private.pem" \
          --delegated-rsa-private-key "$TMPDIR/delegated-rsa-private.pem" \
          --kernel ${kernel} \
          --initramfs ${initramfs} \
          --device-tree ${deviceTree} \
          --command-line ${commandLine} \
          --root-image ${rootImage} \
          --dm-verity ${dmVerity} \
          --slot ${slot}

        test ! -e "$out/root-rsa-private.pem"
        test ! -e "$out/delegated-rsa-private.pem"
        test -f "$out/policy.json"
        test -f "$out/root-public.pem"
        test -f "$out/authority-ca.pem"
        test -f "$out/release/release-manifest.json"
        test "$(find "$out/release" -type f | wc -l)" -eq 8
        jq --exit-status --raw-output --join-output \
          '.delegated_keys[0].public_key_pem' "$out/policy.json" \
          > "$TMPDIR/delegated-public.pem"
        ! cmp "$out/root-public.pem" "$TMPDIR/delegated-public.pem"
      '';
in
rawFixture.overrideAttrs (previous: {
  passthru = (previous.passthru or { }) // {
    kaibaStableVerifierVM = {
      authorityKeyID = "authorization-vm";
      logicalIdentity = "rpi5-spike:vm";
      audience = "verifier:vm";
      verifierVersion = 1;
      cohortID = "spike-cohort";
      slotID = "spike";
      securityEpoch = 2;
      policy = "${rawFixture}/policy.json";
      rootPublicKey = "${rawFixture}/root-public.pem";
      authorityCACertificate = "${rawFixture}/authority-ca.pem";
      release = "${rawFixture}/release";
      authority = "${rawFixture}/authority";
      metadata = "${rawFixture}/fixture.json";
      privateKeysAreTestOnly = true;
      rootAndDelegatedKeysAreDistinct = true;
      productionReady = false;
      hardwareObserved = false;
    };
  };
})
