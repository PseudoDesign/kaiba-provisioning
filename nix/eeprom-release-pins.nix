{ lib, releaseVersion }:

let
  historical = {
    schemaVersion = "kaiba.provisioning.rpi5-eeprom-release/v1alpha1";
    deviceClass = "raspberry-pi-5-model-b-v1alpha1";

    source = {
      repository = "https://github.com/raspberrypi/rpi-eeprom";
      tag = "v2026.05.17-2711-0138c0";
      revision = "05d94be4554ce44a057bfce8d0dd37d951703dab";
      nixHash = "sha256-duzftioXXrLizQVLwAS285n6ve4Y3rCt/ERjcGQG+Dc=";
      packageVersion = "2026.05.17-2711-0138c0";
    };

    firmware = {
      release = "2026-05-26";
      buildEpoch = 1779807685;
      revision = "086b83e3";
      manufacturingVersion = 1;
      image = {
        path = "firmware/pieeprom.original.bin";
        upstreamChannel = "default";
        upstreamPath = "firmware-2712/default/pieeprom-2026-05-26.bin";
        sizeBytes = 2097152;
        sha256 = "sha256:fee8bee6a738a1a61004f0770f15534de7a48a2a199dc4c7af7ed73ab04f18dd";
      };
      recovery = {
        path = "firmware/recovery.original.bin";
        upstreamChannel = "latest";
        upstreamPath = "firmware-2712/latest/recovery.bin";
        sizeBytes = 105396;
        sha256 = "sha256:73dab9a01c139b7d995ac9a4055ee0d15551d7f8dbf1c2605bae584ef7126e0c";
      };
      bootcode = {
        path = "firmware/components/bootcode.bin";
        sizeBytes = 25984;
        sha256 = "sha256:78c1035aae86a25f4e92ed43e4b82bab01ecfa9e4e9a9b81d59b99a62ba9b26e";
      };
      bootsys = {
        path = "firmware/components/bootsys";
        sizeBytes = 78332;
        sha256 = "sha256:cb72681190fb140eaddc3f42327217121eeff088626a5e7026d49f804420ed72";
      };
    };

    capability = {
      id = "boot_img_sha256";
      deviceTreePath = "/proc/device-tree/chosen/bootloader/boot_img_sha256";
      enabledWhen = "signed_boot";
      introducedRelease = "2025-01-22";
      introducedRevision = "7918c84b4b9d7695c3b734e628139dd78b14a6b3";
      introducedBuildEpoch = 1737505011;
    };

    updateWorkflow = {
      repository = "https://github.com/raspberrypi/usbboot";
      revision = "42ca50932f67f4571951a11da3c3161561cb49c2";
      abSigningRevision = "08d4060ecfd85d402d2134572fe1e11d8b1b2dc8";
      eepromSubmoduleRevision = "25f837ab8009a643ed85b9aad94d911baddaf0c4";
      sha256 = "sha256:1b23da89519d73b07decf26e8fb8f7978800d407d2beb21f66c1ceef901e4da5";
      sizeBytes = 8971;
    };

    tools = {
      rpiEEPROMConfig = {
        id = "rpi-eeprom-config";
        path = "toolchain/rpi-eeprom-config";
        sizeBytes = 26205;
        sha256 = "sha256:39895792eb724afe5a4ed39e5798db844292efcca4317228aa790c580ddbb70f";
      };
      rpiEEPROMDigest = {
        id = "rpi-eeprom-digest";
        path = "toolchain/rpi-eeprom-digest";
        sizeBytes = 5245;
        sha256 = "sha256:ec84c22d54793bc68b273d1f26380280fe0453995d85660fdb5e041f4a756bbb";
      };
      rpiSignBootcode = {
        id = "rpi-sign-bootcode";
        path = "toolchain/rpi-sign-bootcode";
        sizeBytes = 11118;
        sha256 = "sha256:a1995a12340dd3a76b9f085726509eee7ebc0407bd0c71c60473bf443c9549f6";
      };
      rpiBootloaderKeyConvert = {
        id = "rpi-bootloader-key-convert";
        path = "toolchain/rpi-bootloader-key-convert";
        sizeBytes = 1398;
        sha256 = "sha256:26502957010893e74c0036c7b86b1db209ddbed716d8f52751fb0f0ee39bf16d";
      };
    };

    provenance = {
      releaseNotes = {
        id = "firmware-2712-release-notes";
        path = "provenance/firmware-2712-release-notes.md";
        sizeBytes = 48758;
        sha256 = "sha256:5c4edbadca75281a9fddca478c4fd69373e89fe232f46ab3e1578b1242559fdd";
      };
      versions = {
        id = "firmware-2712-versions";
        path = "provenance/firmware-2712-versions.txt";
        sizeBytes = 4400;
        sha256 = "sha256:dc14d345eb16bf21f88236dfd490a62949fd28edef0d15598b8ab0b1cb3cf3cd";
      };
    };
  };
  current = lib.recursiveUpdate historical {
    schemaVersion = "kaiba.provisioning.rpi5-eeprom-release/v1alpha2";
    source = {
      tag = null;
      revision = "2fee426f27b6c54d3f5b6f36efd9a2fe1286a45d";
      nixHash = "sha256-EB4hvvPNSs0ykZ86VJLvCq5hBYwAZX/BmZ2leZyEBaM=";
      packageVersion = "2026-09-12";
    };
    firmware = {
      release = "2026-09-12";
      buildEpoch = 1789171628;
      revision = "a8698392";
      # Upstream promoted the files without regenerating versions.txt.
      versionsIndexChannel = "latest";
      image = {
        upstreamPath = "firmware-2712/default/pieeprom-2026-09-12.bin";
        sha256 = "sha256:b49adc90c380f3b9bec9e1ab21111571d7cfdbfe8f2dc5974f294bdb3eb7c39a";
      };
      recovery = {
        sizeBytes = 105420;
        sha256 = "sha256:f0cda4652fede0838e5b61c50979cf1f3c537ff0d652a77c9078495054d0e7b3";
      };
      bootcode.sha256 = "sha256:9563d201f467d83bfc3c6ad0a9904002a4802cac183544aaaa0439c0443aa167";
      bootsys = {
        sizeBytes = 78356;
        sha256 = "sha256:1d93abd789d8978054cfa48577956299fcc9faa3b4a343201cf4afc4f45cc9f5";
      };
    };
    cryptoLocks = {
      introducedRelease = "2026-06-17";
      introducedBuildEpoch = 1781654813;
    };
    tools = {
      rpiEEPROMConfig = {
        sizeBytes = 26657;
        sha256 = "sha256:dfa8e2a819e0922fc7fd948ef4fa55f44066fa04ccf5da210d880f0b35ad9d1b";
      };
      rpiEEPROMDigest = {
        sizeBytes = 5518;
        sha256 = "sha256:2885e3603f9d89995cf5b033f2a616bd1e932547c1d3cffff1ad98e427996a03";
      };
      rpiSignBootcode = {
        sizeBytes = 14792;
        sha256 = "sha256:120d9626f8ce31f8c3cbfa45f4a46df322cba1f9e525c851b74bebaa6390fd82";
      };
    };
    provenance = {
      releaseNotes = {
        sizeBytes = 56406;
        sha256 = "sha256:61431896bd8d3889302a91dad298153be1b336cd6534fa37a80f548e499f739b";
      };
      versions = {
        sizeBytes = 4694;
        sha256 = "sha256:3f6353efc38e30d0258926b1cceb4fffa30b79caca5fb0c473c326858a09ea08";
      };
    };
  };
in
assert lib.assertMsg (builtins.elem releaseVersion [
  "2026-05-26"
  "2026-09-12"
]) "unsupported EEPROM release: select one of the reviewed fixed pins";
if releaseVersion == "2026-05-26" then historical else current
