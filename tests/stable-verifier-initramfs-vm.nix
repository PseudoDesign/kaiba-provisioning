{
  pkgs,
  lib ? pkgs.lib,
  built ? import ../nix/packages.nix { inherit lib pkgs; },
  stableVerifierTool ? built.stableVerifierTool,
  verifierTestAuthority ? built.verifierTestAuthority,
  signedFixture ? null,
  stableVerifierModule ? ../nix/modules/stable-verifier-spike.nix,
}:

assert lib.assertMsg (
  pkgs.stdenv.hostPlatform.system == "x86_64-linux"
) "the stable-verifier initramfs VM checks must be evaluated with x86_64-linux packages";
assert lib.assertMsg (
  (stableVerifierTool.kaibaRpi5StableVerifier.runtimeBoundary or null) == "initramfs_only"
  && (stableVerifierTool.kaibaRpi5StableVerifier.staticallyLinked or false)
  && (stableVerifierTool.kaibaRpi5StableVerifier.kexecCapable or false)
) "stableVerifierTool must be the static, initramfs-only, kexec-capable verifier";

let
  eventSchema = "kaiba.provisioning.rpi5-stable-verifier-event/v1alpha1";
  releaseDirectory = "/run/kaiba-release";
  releaseMountUnit = "run-kaiba\\x2drelease.mount";
  authorityAdminDirectory = "/run/kaiba-verifier-authority";
  authorityAdminSocket = "${authorityAdminDirectory}/authority.sock";

  # These evaluation-time bindings are deliberately fixed on both sides of
  # the test. Only the authenticated policy and manifest digests are read from
  # fixture.json at runtime by the isolated authority VM.
  binding = {
    authorityKeyID = "authorization-vm";
    logicalIdentity = "rpi5-spike:vm";
    audience = "verifier:vm";
    verifierVersion = 1;
    cohortID = "spike-cohort";
    slotID = "spike";
    securityEpoch = 2;
  };

  defaultRootPublicKey = ./fixtures/signed-boot-finalizer-public.pem;

  # Public certificate only. The negative check fails during root-policy
  # authentication and never attempts to contact an authority.
  defaultAuthorityCACertificate = pkgs.writeText "kaiba-initramfs-vm-public-ca.pem" ''
    -----BEGIN CERTIFICATE-----
    MIIDSzCCAjOgAwIBAgIIIwtYp+WlBbswDQYJKoZIhvcNAQELBQAwIDEeMBwGA1UE
    AxMVbWluaWNhIHJvb3QgY2EgMjMwYjU4MCAXDTIyMTEyMTE3MTcxMFoYDzIxMjIx
    MTIxMTcxNzEwWjAgMR4wHAYDVQQDExVtaW5pY2Egcm9vdCBjYSAyMzBiNTgwggEi
    MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCvqAoAyV8igrmBnU6T1nQDfkkQ
    HjQp+ANCthNCi4kGPOoTxrYrUMWa6d/aSIv5hKO2A+r2GdTeM1RvSo6GUr3GmsJc
    WUMbIsJ0SJSLQEyvmFPpzfV3NdfIt6vZRiqJbLt7yuDiZil33GdQEKYywJxIsCb2
    CSd55V1cZSiLItWEIURAhHhSxHabMRmIF/xZWxKFEDeagzXOxUBPAvIwzzqQroBv
    3vZhfgcAjCyS0crJ/E2Wa6GLKfFvaXGEj/KlXftwpbvFtnNBtmtJcNy9a8LJoOcA
    E+ZjD21hidnCc+Yag7LaR3ZtAVkpeRJ9rRNBkVP4rv2mq2skIkgDfY/F8smPAgMB
    AAGjgYYwgYMwDgYDVR0PAQH/BAQDAgKEMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggr
    BgEFBQcDAjASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBS9MITcuP8/o5aS
    Y4a2yNxNwgPOQDAfBgNVHSMEGDAWgBS9MITcuP8/o5aSY4a2yNxNwgPOQDANBgkq
    hkiG9w0BAQsFAAOCAQEADCcgaxrI/pqjkYb0c3QHwfKCNz4khSWs/9tBpBfdxdUX
    uvG7rZzVW7pkzML+m4tSo2wm9sHRAgG+dIpzbSoRTouMntWlvYEnrr1SCw4NyBo1
    cwmNUz4JL+E3dnpI4FSOpyFyO87qL9ep0dxQEADWSppyCA762wfFpY+FvT6b/he8
    eDEc/Umjfm+X0tqNWx3aVoeyIJT46AeElry2IRLAk7z/vEPGFFzgd2Jh6Qsdeagk
    YkU0tFl9q9BotPYGlCMtVjmzbJtxh4uM9YCgiz1THzFjrUvfaTM8VjuBxbpoCZkS
    85mNhFZvNq8/cgYc0kYZOg8+jRdy87xmTRp64LBd6w==
    -----END CERTIFICATE-----
  '';

  # This policy is structurally canonical and binds the configured public
  # root, but its all-zero RSA signature is intentionally invalid. That makes
  # the failure deterministic while exercising more than JSON parsing.
  invalidPolicy =
    pkgs.runCommand "kaiba-initramfs-vm-invalid-policy.json"
      {
        rootPublicKeyInput = defaultRootPublicKey;
        nativeBuildInputs = [
          pkgs.coreutils
          pkgs.jq
          pkgs.openssl
        ];
      }
      ''
        set -euo pipefail
        root_fingerprint="sha256:$(
          openssl pkey -pubin -in "$rootPublicKeyInput" -outform DER \
            | sha256sum | cut -d ' ' -f 1
        )"
        invalid_signature="$(head --bytes=256 /dev/zero | base64 --wrap=0)"
        jq --null-input --compact-output \
          --arg root_fingerprint "$root_fingerprint" \
          --rawfile delegated_public_key "$rootPublicKeyInput" \
          --arg invalid_signature "$invalid_signature" \
          '{
            schema_version: "kaiba.provisioning.rpi5-stable-verifier-policy/v1alpha1",
            policy_id: "policy:initramfs-vm-invalid",
            device_class: "raspberry-pi-5-model-b-v1alpha1",
            cohort_id: "spike-cohort",
            security_epoch: 2,
            minimum_verifier_version: 1,
            release_signature_threshold: 1,
            allowed_slot_ids: ["spike"],
            root_key_id: "root-vm",
            root_key_fingerprint: $root_fingerprint,
            delegated_keys: [{
              key_id: "release-vm",
              algorithm: "rsa-2048-sha256-pkcs1v15",
              public_key_pem: $delegated_public_key,
              public_key_fingerprint: $root_fingerprint,
              status: "active"
            }],
            authorization_authorities: [{
              key_id: "authorization-vm",
              algorithm: "ed25519",
              public_key: "ed25519:0000000000000000000000000000000000000000000000000000000000000000"
            }],
            root_signature: {
              key_id: "root-vm",
              algorithm: "rsa-2048-sha256-pkcs1v15",
              value: $invalid_signature
            }
          }' > "$out"
      '';

  invalidReleaseTree = pkgs.runCommand "kaiba-initramfs-vm-invalid-release" { } ''
    mkdir -p "$out/overlays"
    printf '%s' '{}' > "$out/release-manifest.json"
    printf '%s\n' fixture-kernel > "$out/kernel"
    printf '%s\n' fixture-initramfs > "$out/initramfs"
    printf '%s\n' fixture-device-tree > "$out/device-tree.dtb"
    printf '%s\n' 'console=ttyS0,115200' > "$out/cmdline.txt"
    printf '%s\n' fixture-root > "$out/root.img"
    printf '%s\n' '{"root_hash":"fixture"}' > "$out/dm-verity.json"
    printf '%s\n' spike > "$out/slot.txt"
  '';

  mkReleaseDisk =
    name: releaseTree:
    pkgs.runCommand name
      {
        releaseTreeInput = releaseTree;
        nativeBuildInputs = [
          pkgs.coreutils
          pkgs.e2fsprogs
        ];
      }
      ''
        set -euo pipefail
        export E2FSPROGS_FAKE_TIME=315532800
        export LC_ALL=C
        export SOURCE_DATE_EPOCH=315532800
        export TZ=UTC

        release_bytes="$(du --summarize --bytes --apparent-size "$releaseTreeInput" | cut -f 1)"
        disk_mib="$(( (release_bytes + 1048575) / 1048576 + 32 ))"
        test "$disk_mib" -le 768
        truncate --size="$disk_mib"M "$out"
        mkfs.ext4 \
          -F \
          -L KAIBA_RELEASE \
          -U 4b414942-4152-454c-9400-000000000001 \
          -E lazy_itable_init=0,lazy_journal_init=0 \
          -d "$releaseTreeInput" \
          "$out" \
          > /dev/null
        debugfs -w -R 'rmdir /lost+found' "$out" > /dev/null
        e2fsck -fn "$out" > /dev/null
      '';

  invalidReleaseDisk = mkReleaseDisk "kaiba-initramfs-vm-invalid-release.img" invalidReleaseTree;

  # The positive VM must never make a real kexec syscall. Returning success
  # from both expected invocations lets the verifier demonstrate that it
  # reached load and execute; its fail-closed `kexec returned` handling then
  # produces the terminal failure event and powers the VM off.
  fakeKexecRejectionPath = "/run/kaiba-fake-kexec/rejected";
  fakeKexecExecutionAcceptedPath = "/run/kaiba-fake-kexec/execution-accepted";
  fakeKexec = pkgs.writeTextFile {
    name = "kaiba-initramfs-vm-fake-kexec";
    destination = "/bin/kexec";
    executable = true;
    # makeInitrdNG follows ELF dependencies but does not resolve an arbitrary
    # script's Nix-store shebang. Use the static BusyBox that the test copies
    # explicitly instead of relying on writeShellScriptBin's Bash interpreter.
    text = ''
      #!${pkgs.pkgsStatic.busybox}/bin/busybox sh
      set -eu
      fail() {
        printf 'KAIBA_FAKE_KEXEC_REJECTED:%s\n' "$1" > ${fakeKexecRejectionPath}
        exit 64
      }
      case "''${1-}" in
        --kexec-syscall)
          test "$#" -eq 6 || fail argument-count
          test "$2" = --load || fail load-argument
          test "$3" = /proc/self/fd/3 || fail kernel-argument
          test -r /proc/self/fd/3 || fail kernel-descriptor
          test -r /proc/self/fd/4 || fail initramfs-descriptor
          test -r /proc/self/fd/5 || fail device-tree-descriptor
          test "$4" = --initrd=/proc/self/fd/4 || fail initramfs-argument
          test "$5" = --dtb=/proc/self/fd/5 || fail device-tree-argument
          case "$6" in
            --command-line=?*) ;;
            *) fail command-line-argument ;;
          esac
          ;;
        --exec)
          test "$#" -eq 1 || fail execute-argument-count
          printf 'KAIBA_FAKE_KEXEC_EXEC_ACCEPTED\n' >> ${fakeKexecExecutionAcceptedPath}
          ;;
        *)
          fail operation
          ;;
      esac
    '';
  };
  fakeKexecReporter = pkgs.writeText "kaiba-report-fake-kexec-result" ''
    if test -f ${fakeKexecRejectionPath}; then
      ${pkgs.pkgsStatic.busybox}/bin/busybox cat ${fakeKexecRejectionPath}
    fi
    if test -f ${fakeKexecExecutionAcceptedPath}; then
      ${pkgs.pkgsStatic.busybox}/bin/busybox cat ${fakeKexecExecutionAcceptedPath}
    fi
  '';

  releaseProbe = pkgs.writeShellScriptBin "kaiba-initramfs-release-probe" ''
    set -eu
    release_directory="$1"
    options="$(${pkgs.pkgsStatic.busybox}/bin/busybox awk -v target="$release_directory" '
      $2 == target { print $4; found = 1 }
      END { if (!found) exit 1 }
    ' /proc/mounts)"
    for required in ro nosuid nodev noexec; do
      case ",$options," in
        *,"$required",*) ;;
        *) exit 1 ;;
      esac
    done
    test -r "$release_directory/release-manifest.json"
    printf '%s\n' KAIBA_INITRAMFS_RELEASE_MOUNT_OK
  '';

  mkDutNode =
    {
      authorityCACertificate,
      policy,
      releaseDisk,
      rootPublicKey,
    }:
    { lib, ... }:
    {
      imports = [ stableVerifierModule ];

      system.stateVersion = "26.05";
      virtualisation = {
        graphics = false;
        memorySize = 1024;
        qemu.drives = lib.mkAfter [
          {
            name = "kaiba-release";
            file = "${releaseDisk}";
            driveExtraOpts = {
              format = "raw";
              readonly = "on";
            };
            deviceExtraOpts.serial = "kaiba-release";
          }
        ];
      };

      kaiba.stableVerifierSpike = {
        enable = true;
        package = stableVerifierTool;
        inherit
          authorityCACertificate
          policy
          rootPublicKey
          ;
        inherit (binding)
          audience
          authorityKeyID
          cohortID
          logicalIdentity
          slotID
          verifierVersion
          ;
        minimumSecurityEpoch = binding.securityEpoch;
        authorityURL = "https://192.168.1.1:8443";
        initrdKernelModules = [
          "ext4"
          "virtio_blk"
          "virtio_net"
          "virtio_pci"
        ];
        kexecPackage = fakeKexec;
        networkInterface = "eth1";
        releaseDevice = "/dev/vdb";
        inherit releaseDirectory;
      };

      # The test VLAN has no DHCP server. Give the real initramfs networkd
      # instance its deterministic test address so network-online.target is a
      # meaningful gate in both checks.
      boot.initrd.systemd.network.networks."10-kaiba-stable-verifier" = {
        linkConfig.RequiredForOnline = "routable";
        networkConfig = lib.mkForce {
          Address = "192.168.1.2/24";
          DHCP = "no";
          IPv6AcceptRA = false;
          LinkLocalAddressing = false;
        };
      };

      # An observation-only initramfs service proves that the attached image
      # was mounted with all four required restrictions before the verifier is
      # allowed to run.
      boot.initrd.systemd.storePaths = [
        fakeKexecReporter
        releaseProbe
        pkgs.pkgsStatic.busybox
      ];
      boot.initrd.systemd.services.kaiba-initramfs-release-probe = {
        description = "Observe the read-only Kaiba release mount";
        wantedBy = [ "initrd.target" ];
        requires = [ releaseMountUnit ];
        after = [ releaseMountUnit ];
        before = [ "kaiba-stable-verifier.service" ];
        unitConfig.DefaultDependencies = false;
        serviceConfig = {
          Type = "oneshot";
          # Invoke through the static BusyBox already copied into the initrd.
          # A writeShellScriptBin shebang points at dynamic Bash, which is not
          # part of this deliberately small pre-switch-root environment.
          ExecStart = "${pkgs.pkgsStatic.busybox}/bin/busybox sh ${releaseProbe}/bin/kaiba-initramfs-release-probe ${releaseDirectory}";
          StandardOutput = "journal+console";
          StandardError = "journal+console";
        };
      };
      boot.initrd.systemd.services.kaiba-stable-verifier = {
        requires = [ "kaiba-initramfs-release-probe.service" ];
        after = [ "kaiba-initramfs-release-probe.service" ];
        serviceConfig = {
          ExecStopPost = "${pkgs.pkgsStatic.busybox}/bin/busybox sh ${fakeKexecReporter}";
          # Give the test-only kexec result sentinels an explicit writable
          # location inside the otherwise read-only verifier service sandbox.
          RuntimeDirectory = "kaiba-fake-kexec";
          RuntimeDirectoryMode = "0700";
        };
      };

      # Keep the x86 test console last even though the Pi module also carries
      # its serial0 argument. The direct-boot test driver appends ttyS0 too.
      boot.kernelParams = lib.mkAfter [
        "console=ttyS0,115200n8"
        "rd.systemd.show_status=true"
      ];
    };

  waitForEvent = sequence: event: ''
    dut.wait_for_console_text(
        r'"schema_version":"${eventSchema}".*"sequence":${toString sequence}.*"source":"verifier-uart".*"event":"${event}"',
        timeout=120,
    )
  '';

  assertEventTrace = expectedEvents: failureCode: ''
    console_log = dut.get_console_log()
    expected_events = ${builtins.toJSON expectedEvents}
    all_progress_events = [
        "verifier-started",
        "release-verified",
        "bootstrap-key-ready",
        "authorization-granted",
        "handoff-loaded",
        "handoff-executing",
    ]
    positions = []
    for event in expected_events:
        marker = f'"event":"{event}"'
        assert console_log.count(marker) == 1, f"expected exactly one {event} event"
        positions.append(console_log.index(marker))
    assert positions == sorted(positions), "verifier progress events were out of order"
    for event in all_progress_events:
        if event not in expected_events:
            assert f'"event":"{event}"' not in console_log, f"unexpected {event} event"
    failure_marker = '"event":"verifier-failed"'
    assert console_log.count(failure_marker) == 1, "expected exactly one terminal failure event"
    assert '"failure_code":"${failureCode}"' in console_log
    assert "KAIBA_FAKE_KEXEC_REJECTED:" not in console_log, "fake kexec rejected its invocation"
    assert "Stage 2" not in console_log, "the original system switched to stage 2"
  '';

  failureEvents = [ "verifier-started" ];
  failureEventWaits = lib.concatStrings (
    lib.imap0 (index: event: waitForEvent (index + 1) event) failureEvents
  );
  failureTest = pkgs.testers.runNixOSTest {
    name = "kaiba-stable-verifier-initramfs-fail-closed";
    globalTimeout = 240;
    passthru.kaibaStableVerifierInitramfsVM = {
      architecture = "x86_64-linux";
      expectedFailureCode = "release-verification-failed";
      forcedPoweroffObserved = true;
      generatedInitramfsBooted = true;
      realKexecSyscalls = false;
      signedReleaseVerified = false;
      productionReady = false;
      raspberryPiHardwareObserved = false;
    };
    nodes.dut = mkDutNode {
      authorityCACertificate = defaultAuthorityCACertificate;
      policy = invalidPolicy;
      releaseDisk = invalidReleaseDisk;
      rootPublicKey = defaultRootPublicKey;
    };
    testScript = ''
      dut.start()
      dut.wait_for_console_text("KAIBA_INITRAMFS_RELEASE_MOUNT_OK", timeout=120)
      ${failureEventWaits}
      ${waitForEvent 2 "verifier-failed"}
      dut.wait_for_console_text(r"(?:reboot: Power down|Power down\.)", timeout=60)
      dut.wait_for_shutdown()
      ${assertEventTrace failureEvents "release-verification-failed"}
    '';
  };

  signedFixtureContract =
    if signedFixture == null then { } else signedFixture.kaibaStableVerifierVM or { };
  signedFixtureContractValid =
    (signedFixtureContract.authorityKeyID or null) == binding.authorityKeyID
    && (signedFixtureContract.logicalIdentity or null) == binding.logicalIdentity
    && (signedFixtureContract.audience or null) == binding.audience
    && (signedFixtureContract.verifierVersion or null) == binding.verifierVersion
    && (signedFixtureContract.cohortID or null) == binding.cohortID
    && (signedFixtureContract.slotID or null) == binding.slotID
    && (signedFixtureContract.securityEpoch or null) == binding.securityEpoch
    && (signedFixtureContract.rootAndDelegatedKeysAreDistinct or false)
    && !(signedFixtureContract.productionReady or true);

  signedReleaseDisk = mkReleaseDisk "kaiba-initramfs-vm-signed-release.img" "${signedFixture}/release";

  authorityRunner = pkgs.writeShellApplication {
    name = "kaiba-run-initramfs-vm-authority";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.jq
      verifierTestAuthority
    ];
    text = ''
      set -euo pipefail
      state=${authorityAdminDirectory}
      install -m 0600 ${signedFixture}/authority/tls-key.pem "$state/tls-key.pem"
      install -m 0600 ${signedFixture}/authority/authority-key.pem "$state/authority-key.pem"
      install -m 0444 ${signedFixture}/authority/tls-cert.pem "$state/tls-cert.pem"

      policy_digest="$(jq -er '.policy_digest // .binding.policy_digest' ${signedFixture}/fixture.json)"
      manifest_digest="$(jq -er '.manifest_digest // .binding.manifest_digest' ${signedFixture}/fixture.json)"

      exec kaiba-rpi5-verifier-test-authority \
        --listen 192.168.1.1:8443 \
        --admin-socket "$state/authority.sock" \
        --tls-cert "$state/tls-cert.pem" \
        --tls-key "$state/tls-key.pem" \
        --authority-key "$state/authority-key.pem" \
        --authority-key-id ${binding.authorityKeyID} \
        --logical-identity ${binding.logicalIdentity} \
        --audience ${binding.audience} \
        --verifier-version ${toString binding.verifierVersion} \
        --policy-digest "$policy_digest" \
        --manifest-digest "$manifest_digest" \
        --security-epoch ${toString binding.securityEpoch} \
        --challenge-max-age 60s \
      --authorization-max-age 60s
    '';
  };

  authorityReadiness = pkgs.writeShellApplication {
    name = "kaiba-wait-for-initramfs-vm-authority";
    runtimeInputs = [ pkgs.coreutils ];
    text = ''
      set -euo pipefail
      for _ in $(seq 1 6000); do
        if test -S ${authorityAdminSocket}; then
          printf '%s\n' KAIBA_INITRAMFS_VM_AUTHORITY_READY
          exit 0
        fi
        sleep 0.1
      done
      printf '%s\n' KAIBA_INITRAMFS_VM_AUTHORITY_NOT_READY >&2
      exit 1
    '';
  };

  authorityNetworkReadiness = pkgs.writeShellApplication {
    name = "kaiba-wait-for-initramfs-vm-authority-network";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.gnugrep
      pkgs.iproute2
    ];
    text = ''
      set -euo pipefail
      for _ in $(seq 1 6000); do
        if ip -4 -o address show \
          | grep -Eq ' inet 192[.]168[.]1[.]1/24([[:space:]]|$)'; then
          printf '%s\n' KAIBA_INITRAMFS_VM_AUTHORITY_NETWORK_READY
          exit 0
        fi
        sleep 0.1
      done
      printf '%s\n' KAIBA_INITRAMFS_VM_AUTHORITY_NETWORK_NOT_READY >&2
      exit 1
    '';
  };

  signedEvents = [
    "verifier-started"
    "release-verified"
    "bootstrap-key-ready"
    "authorization-granted"
    "handoff-loaded"
    "handoff-executing"
  ];
  signedEventWaitsBeforeRegistration = lib.concatStrings (
    lib.imap0 (index: event: waitForEvent (index + 1) event) (lib.take 3 signedEvents)
  );
  signedEventWaitsAfterRegistration = lib.concatStrings (
    lib.imap0 (index: event: waitForEvent (index + 4) event) (lib.drop 3 signedEvents)
  );

  signedHandoffTest = pkgs.testers.runNixOSTest {
    name = "kaiba-stable-verifier-initramfs-signed-handoff";
    # This test boots an authority VM before the verifier VM. Builders without
    # KVM legitimately need several minutes for the first TCG boot alone.
    globalTimeout = 900;
    passthru.kaibaStableVerifierInitramfsVM = {
      architecture = "x86_64-linux";
      expectedFailureCode = "kexec-execute-failed";
      forcedPoweroffObserved = true;
      generatedInitramfsBooted = true;
      handoffExecutingObserved = true;
      realKexecSyscalls = false;
      signedReleaseVerified = true;
      testAuthorityObserved = true;
      testAuthorityNetworkReadinessObserved = true;
      productionReady = false;
      raspberryPiHardwareObserved = false;
    };

    nodes = {
      authority =
        { ... }:
        {
          system.stateVersion = "26.05";
          environment.systemPackages = [ pkgs.curl ];
          networking.firewall.allowedTCPPorts = [ 8443 ];
          systemd.services.kaiba-verifier-test-authority = {
            description = "Isolated Kaiba non-production verifier authority";
            wantedBy = [ "multi-user.target" ];
            wants = [ "network-online.target" ];
            after = [ "network-online.target" ];
            serviceConfig = {
              Type = "simple";
              ExecStartPre = "${authorityNetworkReadiness}/bin/kaiba-wait-for-initramfs-vm-authority-network";
              ExecStart = "${authorityRunner}/bin/kaiba-run-initramfs-vm-authority";
              ExecStartPost = "${authorityReadiness}/bin/kaiba-wait-for-initramfs-vm-authority";
              RuntimeDirectory = "kaiba-verifier-authority";
              RuntimeDirectoryMode = "0700";
              StandardOutput = "journal+console";
              StandardError = "journal+console";
              TimeoutStartSec = 660;
              UMask = "0077";
            };
          };
        };

      dut = mkDutNode {
        authorityCACertificate = "${signedFixture}/authority-ca.pem";
        policy = "${signedFixture}/policy.json";
        releaseDisk = signedReleaseDisk;
        rootPublicKey = "${signedFixture}/root-public.pem";
      };
    };

    testScript = ''
      import json
      import re
      import shlex

      authority.start()
      authority.wait_for_console_text("KAIBA_INITRAMFS_VM_AUTHORITY_NETWORK_READY", timeout=600)
      authority.wait_for_console_text("KAIBA_INITRAMFS_VM_AUTHORITY_READY", timeout=600)
      authority.wait_for_unit("kaiba-verifier-test-authority.service")
      authority.wait_until_succeeds("test -S ${authorityAdminSocket}")

      dut.start()
      dut.wait_for_console_text("KAIBA_INITRAMFS_RELEASE_MOUNT_OK", timeout=120)
      ${signedEventWaitsBeforeRegistration}

      bootstrap_matches = re.findall(
          r'"bootstrap_public_key":"(ed25519:[0-9a-f]{64})"',
          dut.get_console_log(),
      )
      assert len(bootstrap_matches) == 1, "expected one bootstrap public key"
      registration = json.dumps(
          {
              "schema_version": "kaiba.provisioning.rpi5-non-production-bootstrap-registration/v1alpha1",
              "logical_identity": "${binding.logicalIdentity}",
              "bootstrap_public_key": bootstrap_matches[0],
          },
          separators=(",", ":"),
      )
      authority.succeed(
          "curl --fail --silent --show-error "
          "--unix-socket ${authorityAdminSocket} "
          "--header 'Content-Type: application/json' "
          "--data-binary " + shlex.quote(registration) + " "
          "http://unix/non-production/v1alpha1/bootstrap-registrations"
      )

      ${signedEventWaitsAfterRegistration}
      ${waitForEvent 7 "verifier-failed"}
      dut.wait_for_console_text(r"(?:reboot: Power down|Power down\.)", timeout=60)
      dut.wait_for_shutdown()
      ${assertEventTrace signedEvents "kexec-execute-failed"}
      assert console_log.count("KAIBA_FAKE_KEXEC_EXEC_ACCEPTED") == 1, (
          "fake kexec did not accept exactly one --exec invocation"
      )
    '';
  };

in
{
  failure = failureTest;

  signedHandoff =
    assert lib.assertMsg (
      signedFixture != null
    ) "signedHandoff requires the private-test-material signedFixture derivation";
    assert lib.assertMsg signedFixtureContractValid
      "signedFixture.kaibaStableVerifierVM does not match the fixed VM binding";
    signedHandoffTest;
}
