{
  pkgs,
  lib ? pkgs.lib,
  guestPkgs ? pkgs,
  built ? import ../nix/packages.nix {
    inherit lib;
    pkgs = guestPkgs;
  },
  verifierPackage ? built.stableVerifierTool,
  authorityPackage ? built.verifierTestAuthority,
  source ? built.goSource,
  fixtureGeneratorPackage ? null,
}:

assert lib.assertMsg (pkgs.stdenv.hostPlatform.isLinux
) "the stable-verifier real-kexec VM check requires a Linux VM host";
assert lib.assertMsg (
  guestPkgs.stdenv.hostPlatform.system == "aarch64-linux"
) "the stable-verifier real-kexec VM guest must use aarch64-linux packages";
assert lib.assertMsg (
  (verifierPackage.kaibaRpi5StableVerifier.runtimeBoundary or null) == "initramfs_only"
  && (verifierPackage.kaibaRpi5StableVerifier.staticallyLinked or false)
  && (verifierPackage.kaibaRpi5StableVerifier.kexecCapable or false)
) "verifierPackage must be the static, initramfs-only, kexec-capable stable verifier";

let
  # QEMU's virt machine synthesizes its DTB from the final machine arguments.
  # Consequently the signed release is assembled inside the disposable VM
  # after copying /sys/firmware/fdt. This helper holds test-only signing keys in
  # RAM-backed/disposable VM storage; no key becomes a Nix-store input.
  defaultFixtureGeneratorMain = guestPkgs.writeText "kaiba-kexec-vm-fixture.go" ''
    package main

    import (
      "crypto"
      "crypto/ed25519"
      "crypto/rand"
      "crypto/rsa"
      "crypto/sha256"
      "crypto/x509"
      "crypto/x509/pkix"
      "encoding/base64"
      "encoding/hex"
      "encoding/json"
      "encoding/pem"
      "flag"
      "fmt"
      "math/big"
      "net"
      "os"
      "path/filepath"
      "time"

      "github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
      "github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stableverifier"
    )

    const (
      authorityKeyID = "authorization-vm"
      cohortID = "qemu-aarch64"
      slotID = "vm"
    )

    func fatal(format string, arguments ...any) {
      fmt.Fprintf(os.Stderr, format+"\n", arguments...)
      os.Exit(1)
    }

    func must[T any](value T, err error) T {
      if err != nil {
        fatal("fixture generation: %v", err)
      }
      return value
    }

    func writeFile(path string, contents []byte, mode os.FileMode) {
      if err := os.WriteFile(path, contents, mode); err != nil {
        fatal("write %s: %v", path, err)
      }
      if err := os.Chmod(path, mode); err != nil {
        fatal("chmod %s: %v", path, err)
      }
    }

    func rsaPublic(key *rsa.PublicKey) ([]byte, bundle.Digest) {
      der := must(x509.MarshalPKIXPublicKey(key))
      encoded := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
      return encoded, bundle.Sum(der)
    }

    func rsaSignature(key *rsa.PrivateKey, preimage []byte) string {
      digest := sha256.Sum256(preimage)
      signature := must(rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:]))
      return base64.StdEncoding.EncodeToString(signature)
    }

    func privateKeyPEM(key any) []byte {
      encoded := must(x509.MarshalPKCS8PrivateKey(key))
      return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})
    }

    func ed25519KeyPair() (ed25519.PublicKey, ed25519.PrivateKey) {
      publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
      if err != nil {
        fatal("generate Ed25519 key: %v", err)
      }
      return publicKey, privateKey
    }

    func writeTLSFixture(output string) {
      now := time.Now().UTC()
      caPublic, caPrivate := ed25519KeyPair()
      caTemplate := &x509.Certificate{
        SerialNumber: big.NewInt(1),
        Subject: pkix.Name{CommonName: "Kaiba kexec VM test CA"},
        NotBefore: now.Add(-time.Hour),
        NotAfter: now.Add(24 * time.Hour),
        IsCA: true,
        BasicConstraintsValid: true,
        KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
      }
      caDER := must(x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate))

      serverPublic, serverPrivate := ed25519KeyPair()
      serverTemplate := &x509.Certificate{
        SerialNumber: big.NewInt(2),
        Subject: pkix.Name{CommonName: "127.0.0.1"},
        NotBefore: now.Add(-time.Hour),
        NotAfter: now.Add(24 * time.Hour),
        KeyUsage: x509.KeyUsageDigitalSignature,
        ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
        IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
      }
      serverDER := must(x509.CreateCertificate(
        rand.Reader, serverTemplate, caTemplate, serverPublic, caPrivate,
      ))
      writeFile(filepath.Join(output, "authority-ca.pem"), pem.EncodeToMemory(&pem.Block{
        Type: "CERTIFICATE", Bytes: caDER,
      }), 0o644)
      writeFile(filepath.Join(output, "tls-server.pem"), pem.EncodeToMemory(&pem.Block{
        Type: "CERTIFICATE", Bytes: serverDER,
      }), 0o644)
      writeFile(filepath.Join(output, "tls-server-key.pem"), privateKeyPEM(serverPrivate), 0o600)
    }

    func main() {
      output := flag.String("output", "", "empty owner-controlled fixture directory")
      kernelPath := flag.String("kernel", "", "AArch64 Linux Image")
      initramfsPath := flag.String("initramfs", "", "base second-stage initramfs")
      deviceTreePath := flag.String("device-tree", "", "QEMU runtime device tree")
      flag.Parse()
      if flag.NArg() != 0 || *output == "" || *kernelPath == "" || *initramfsPath == "" || *deviceTreePath == "" {
        fatal("--output, --kernel, --initramfs, and --device-tree are required")
      }
      if err := os.MkdirAll(filepath.Join(*output, "release", "overlays"), 0o700); err != nil {
        fatal("create fixture directories: %v", err)
      }
      if err := os.Chmod(*output, 0o700); err != nil {
        fatal("protect fixture directory: %v", err)
      }

      rootPrivate := must(rsa.GenerateKey(rand.Reader, 2048))
      delegatedPrivate := must(rsa.GenerateKey(rand.Reader, 2048))
      rootPublicPEM, rootFingerprint := rsaPublic(&rootPrivate.PublicKey)
      delegatedPublicPEM, delegatedFingerprint := rsaPublic(&delegatedPrivate.PublicKey)
      authorityPublic, authorityPrivate := ed25519KeyPair()
      authorityPublicText := "ed25519:" + hex.EncodeToString(authorityPublic)

      policy := stableverifier.Policy{
        SchemaVersion: stableverifier.PolicySchemaV1Alpha1,
        PolicyID: "policy:qemu-aarch64-kexec",
        DeviceClass: stableverifier.DeviceClass,
        CohortID: cohortID,
        SecurityEpoch: 1,
        MinimumVerifierVersion: 1,
        ReleaseSignatureThreshold: 1,
        AllowedSlotIDs: []string{slotID},
        RootKeyID: "root-vm",
        RootKeyFingerprint: rootFingerprint,
        DelegatedKeys: []stableverifier.DelegatedKey{{
          KeyID: "release-vm",
          Algorithm: stableverifier.RSA2048SHA256Algorithm,
          PublicKeyPEM: string(delegatedPublicPEM),
          PublicKeyFingerprint: delegatedFingerprint,
          Status: "active",
        }},
        AuthorizationAuthorities: []stableverifier.AuthorizationAuthority{{
          KeyID: authorityKeyID,
          Algorithm: stableverifier.Ed25519Algorithm,
          PublicKey: authorityPublicText,
        }},
      }
      policyPreimage := must(policy.SigningPreimage())
      policy.RootSignature = stableverifier.RSASignature{
        KeyID: policy.RootKeyID,
        Algorithm: stableverifier.RSA2048SHA256Algorithm,
        Value: rsaSignature(rootPrivate, policyPreimage),
      }
      policyJSON := must(policy.CanonicalJSON())
      policyDigest := must(policy.Digest())
      writeFile(filepath.Join(*output, "root-public.pem"), rootPublicPEM, 0o644)
      writeFile(filepath.Join(*output, "policy.json"), policyJSON, 0o644)
      writeFile(filepath.Join(*output, "authority-key.pem"), privateKeyPEM(authorityPrivate), 0o600)
      writeTLSFixture(*output)

      componentContents := map[stableverifier.ComponentRole][]byte{
        stableverifier.RoleKernel: must(os.ReadFile(*kernelPath)),
        stableverifier.RoleInitramfs: must(os.ReadFile(*initramfsPath)),
        stableverifier.RoleResolvedDeviceTree: must(os.ReadFile(*deviceTreePath)),
        stableverifier.RoleKernelCommandLine: []byte("console=ttyAMA0,115200 earlycon=pl011,0x09000000 rdinit=/init kaiba.second_stage=1\n"),
        stableverifier.RoleRootImage: []byte("qemu-observation-only-root-image\n"),
        stableverifier.RoleDMVerityMetadata: []byte("{\"mode\":\"metadata-handoff-observation\",\"root_hash\":\"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\"}\n"),
        stableverifier.RoleSlotMetadata: []byte(slotID + "\n"),
      }
      components := make([]stableverifier.Component, 0, len(stableverifier.ComponentRoles()))
      for _, role := range stableverifier.ComponentRoles() {
        contents := componentContents[role]
        relativePath, ok := stableverifier.ComponentPath(role)
        if !ok {
          fatal("unknown component role %q", role)
        }
        writeFile(filepath.Join(*output, "release", relativePath), contents, 0o600)
        components = append(components, stableverifier.Component{
          Role: role, Digest: bundle.Sum(contents), SizeBytes: uint64(len(contents)),
        })
      }
      manifest := stableverifier.Manifest{
        SchemaVersion: stableverifier.ManifestSchemaV1Alpha1,
        ReleaseID: "release:qemu-aarch64-kexec",
        DeviceClass: stableverifier.DeviceClass,
        CohortID: cohortID,
        PolicyDigest: policyDigest,
        SecurityEpoch: 1,
        SlotID: slotID,
        Components: components,
        Overlays: []stableverifier.Overlay{},
      }
      manifestPreimage := must(manifest.SigningPreimage())
      manifest.Signatures = []stableverifier.RSASignature{{
        KeyID: "release-vm",
        Algorithm: stableverifier.RSA2048SHA256Algorithm,
        Value: rsaSignature(delegatedPrivate, manifestPreimage),
      }}
      manifestJSON := must(manifest.CanonicalJSON())
      manifestDigest := must(manifest.Digest())
      writeFile(filepath.Join(*output, "release", "release-manifest.json"), manifestJSON, 0o600)

      binding := struct {
        PolicyDigest bundle.Digest `json:"policy_digest"`
        ManifestDigest bundle.Digest `json:"manifest_digest"`
        AuthorityPublicKey string `json:"authority_public_key"`
      }{policyDigest, manifestDigest, authorityPublicText}
      writeFile(filepath.Join(*output, "binding.json"), must(json.Marshal(binding)), 0o644)
    }
  '';

  defaultFixtureGeneratorSource = guestPkgs.runCommand "kaiba-kexec-vm-fixture-source" { } ''
    mkdir -p "$out/cmd/kaiba-kexec-vm-fixture"
    cp ${source}/go.mod "$out/go.mod"
    cp -R ${source}/internal "$out/internal"
    cp ${defaultFixtureGeneratorMain} "$out/cmd/kaiba-kexec-vm-fixture/main.go"
  '';

  defaultFixtureGenerator = guestPkgs.buildGoModule {
    pname = "kaiba-kexec-vm-fixture";
    version = "0.1.0";
    src = defaultFixtureGeneratorSource;
    subPackages = [ "cmd/kaiba-kexec-vm-fixture" ];
    vendorHash = null;
    env.CGO_ENABLED = 0;
    doCheck = false;
  };

  fixtureGenerator =
    if fixtureGeneratorPackage == null then defaultFixtureGenerator else fixtureGeneratorPackage;

  secondStageInit = guestPkgs.writeText "kaiba-kexec-vm-init" ''
    #!/bin/busybox sh
    /bin/busybox mount -t devtmpfs devtmpfs /dev
    exec >/dev/console 2>&1
    /bin/busybox mount -t proc proc /proc
    /bin/busybox mount -t sysfs sysfs /sys
    /bin/busybox echo KAIBA_KEXEC_SECOND_STAGE_BOOTED

    failed=0
    for path in \
      /run/kaiba/boot-authorization.json \
      /run/kaiba/one-boot-ed25519.pk8 \
      /run/kaiba/dm-verity.json \
      /run/kaiba/slot.txt
    do
      if ! /bin/busybox test -s "$path"; then
        /bin/busybox echo "KAIBA_KEXEC_MISSING_CREDENTIAL:$path"
        failed=1
      fi
    done
    if ! /bin/busybox grep -F '"decision":"authorized"' /run/kaiba/boot-authorization.json >/dev/null; then
      /bin/busybox echo KAIBA_KEXEC_AUTHORIZATION_INVALID
      failed=1
    fi
    if ! /bin/busybox test "$(/bin/busybox cat /run/kaiba/dm-verity.json)" = '{"mode":"metadata-handoff-observation","root_hash":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}'; then
      /bin/busybox echo KAIBA_KEXEC_DM_VERITY_METADATA_INVALID
      failed=1
    fi
    if ! /bin/busybox test "$(/bin/busybox cat /run/kaiba/slot.txt)" = vm; then
      /bin/busybox echo KAIBA_KEXEC_SLOT_INVALID
      failed=1
    fi
    if ! /bin/busybox test "$(/bin/busybox stat -c %a /run/kaiba/one-boot-ed25519.pk8)" = 400; then
      /bin/busybox echo KAIBA_KEXEC_ONE_BOOT_KEY_MODE_INVALID
      failed=1
    fi
    if ! /bin/busybox test "$(/bin/busybox stat -c %a /run/kaiba/boot-authorization.json)" = 400; then
      /bin/busybox echo KAIBA_KEXEC_AUTHORIZATION_MODE_INVALID
      failed=1
    fi
    if ! /bin/busybox test "$(/bin/busybox stat -c %a /run/kaiba/dm-verity.json)" = 444; then
      /bin/busybox echo KAIBA_KEXEC_DM_VERITY_MODE_INVALID
      failed=1
    fi
    if ! /bin/busybox test "$(/bin/busybox stat -c %a /run/kaiba/slot.txt)" = 444; then
      /bin/busybox echo KAIBA_KEXEC_SLOT_MODE_INVALID
      failed=1
    fi
    if ! /bin/busybox test "$(/bin/busybox cat /proc/cmdline)" = 'console=ttyAMA0,115200 earlycon=pl011,0x09000000 rdinit=/init kaiba.second_stage=1'; then
      /bin/busybox echo KAIBA_KEXEC_COMMAND_LINE_INVALID
      failed=1
    fi
    if ! /bin/busybox test "$(/bin/busybox cat /proc/device-tree/chosen/kaiba,kexec-vm-marker)" = signed-dtb; then
      /bin/busybox echo KAIBA_KEXEC_DEVICE_TREE_INVALID
      failed=1
    fi

    if /bin/busybox test "$failed" -eq 0; then
      /bin/busybox echo KAIBA_KEXEC_CREDENTIALS_OK
      /bin/busybox echo KAIBA_KEXEC_DM_VERITY_METADATA_OK
      /bin/busybox rm /run/kaiba/one-boot-ed25519.pk8
      if /bin/busybox test -e /run/kaiba/one-boot-ed25519.pk8; then
        /bin/busybox echo KAIBA_KEXEC_ONE_BOOT_KEY_REMOVE_FAILED
      else
        /bin/busybox echo KAIBA_KEXEC_ONE_BOOT_KEY_REMOVED
        /bin/busybox echo KAIBA_KEXEC_SECOND_STAGE_OK
      fi
    else
      /bin/busybox echo KAIBA_KEXEC_SECOND_STAGE_FAILED
    fi
    /bin/busybox sync
    /bin/busybox poweroff -f
  '';

  secondStageInitramfs =
    guestPkgs.runCommand "kaiba-kexec-vm-initramfs"
      {
        nativeBuildInputs = [
          guestPkgs.coreutils
          guestPkgs.cpio
          guestPkgs.findutils
        ];
      }
      ''
        root="$TMPDIR/root"
        mkdir -p "$root/bin" "$root/dev" "$root/proc" "$root/run" "$root/sys"
        install -m 0555 ${guestPkgs.pkgsStatic.busybox}/bin/busybox "$root/bin/busybox"
        install -m 0555 ${secondStageInit} "$root/init"
        find "$root" -exec touch -h --date=@1 '{}' +
        (
          cd "$root"
          find . -print0 | sort -z \
            | cpio --null --create --format=newc --owner=0:0 --reproducible --quiet
        ) > "$out"
      '';

  runVerifier = guestPkgs.writeShellApplication {
    name = "kaiba-run-aarch64-kexec-vm";
    runtimeInputs = [
      authorityPackage
      fixtureGenerator
      guestPkgs.coreutils
      guestPkgs.curl
      guestPkgs.dtc
      guestPkgs.gnugrep
      guestPkgs.jq
      guestPkgs.kexec-tools
      verifierPackage
    ];
    text = ''
      runtime=/run/kaiba-kexec-vm
      state="$runtime/state"
      admin="$runtime/admin"
      events="$runtime/events.ndjson"
      install -d -m 0700 "$state" "$admin"
      : > "$events"
      chmod 0600 "$events"

      cp /sys/firmware/fdt "$state/signed-device-tree.dtb"
      chmod 0600 "$state/signed-device-tree.dtb"
      fdtput -t s "$state/signed-device-tree.dtb" /chosen kaiba,kexec-vm-marker signed-dtb

      kaiba-kexec-vm-fixture \
        --output "$state" \
        --kernel /run/current-system/kernel \
        --initramfs ${secondStageInitramfs} \
        --device-tree "$state/signed-device-tree.dtb"

      policy_digest="$(jq -er .policy_digest "$state/binding.json")"
      manifest_digest="$(jq -er .manifest_digest "$state/binding.json")"

      kaiba-rpi5-verifier-test-authority \
        --listen 127.0.0.1:8443 \
        --admin-socket "$admin/authority.sock" \
        --tls-cert "$state/tls-server.pem" \
        --tls-key "$state/tls-server-key.pem" \
        --authority-key "$state/authority-key.pem" \
        --authority-key-id authorization-vm \
        --logical-identity rpi5-qemu-vm \
        --audience stable-verifier-vm \
        --verifier-version 1 \
        --policy-digest "$policy_digest" \
        --manifest-digest "$manifest_digest" \
        --security-epoch 1 \
        --challenge-max-age 60s \
        --authorization-max-age 60s \
        &
      authority_pid=$!
      trap 'kill "$authority_pid" 2>/dev/null || true' EXIT

      for _ in $(seq 1 200); do
        if test -S "$admin/authority.sock"; then
          break
        fi
        if ! kill -0 "$authority_pid" 2>/dev/null; then
          echo KAIBA_KEXEC_AUTHORITY_EXITED
          exit 1
        fi
        sleep 0.05
      done
      test -S "$admin/authority.sock"

      # The authority has synchronously loaded these keys before publishing
      # its socket. Remove the files so the verifier cannot casually consume
      # authority signing material from the shared test runtime directory.
      rm -f "$state/authority-key.pem" "$state/tls-server-key.pem"

      (
        while ! grep -m1 -F '"event":"bootstrap-key-ready"' "$events" >/dev/null; do
          sleep 0.05
        done
        bootstrap_key="$(grep -m1 -F '"event":"bootstrap-key-ready"' "$events" | jq -er .bootstrap_public_key)"
        jq -cjn \
          --arg bootstrap_public_key "$bootstrap_key" \
          '{schema_version:"kaiba.provisioning.rpi5-non-production-bootstrap-registration/v1alpha1",logical_identity:"rpi5-qemu-vm",bootstrap_public_key:$bootstrap_public_key}' \
          | curl --fail --silent --show-error \
              --unix-socket "$admin/authority.sock" \
              --header 'Content-Type: application/json' \
              --data-binary @- \
              http://unix/non-production/v1alpha1/bootstrap-registrations
        echo KAIBA_KEXEC_BOOTSTRAP_REGISTERED
      ) &

      set +e
      kaiba-rpi5-stable-verifier \
        --policy "$state/policy.json" \
        --root-public-key "$state/root-public.pem" \
        --release-dir "$state/release" \
        --verifier-version 1 \
        --cohort-id qemu-aarch64 \
        --slot-id vm \
        --minimum-security-epoch 1 \
        --authority-url https://127.0.0.1:8443 \
        --authority-ca "$state/authority-ca.pem" \
        --authority-key-id authorization-vm \
        --audience stable-verifier-vm \
        --logical-identity rpi5-qemu-vm \
        --kexec ${guestPkgs.kexec-tools}/bin/kexec \
        --bootstrap-registration-timeout 30s \
        --authority-client-timeout 30s \
        2>&1 | tee -a "$events"
      verifier_status="''${PIPESTATUS[0]}"
      set -e
      echo "KAIBA_KEXEC_VERIFIER_RETURNED:$verifier_status"
      exit "$verifier_status"
    '';
  };

  vmTestRequiringKVM = pkgs.testers.runNixOSTest {
    name = "kaiba-stable-verifier-aarch64-real-kexec";
    # Native ARM64 runners do not necessarily expose KVM. Keep the slow-path
    # serial boot and the real kexec exercise within an explicit bound.
    globalTimeout = 1200;
    # runNixOSTest defaults nodes to the host package set. Override that one
    # unique value so QEMU/the Python driver remain native while the VM closure
    # and verifier are built for AArch64.
    node.pkgs = lib.mkForce guestPkgs;

    passthru.kaibaStableVerifierAarch64KexecVM = {
      architecture = "aarch64-linux";
      emulatedMachine = "qemu-virt";
      emulatedInterruptController = "gicv2";
      realKexecSyscalls = true;
      legacyKexecSyscallForced = true;
      legacyKexecRequiresCAPSYSADMIN = true;
      secondKernelObserved = true;
      authenticatedCommandLineObserved = true;
      authenticatedDeviceTreeObserved = true;
      credentialArchiveObserved = true;
      dmVerityMetadataObserved = true;
      dmVerityMappingExercised = false;
      authorityIsolated = false;
      authorityPrivateKeyFilesRemovedBeforeVerification = true;
      raspberryPiFirmwareObserved = false;
      rp1Observed = false;
      nvmeObserved = false;
      productionReady = false;
    };

    nodes.machine =
      { lib, ... }:
      {
        boot.kernelParams = [
          "console=ttyAMA0,115200"
          "earlycon=pl011,0x09000000"
        ];
        boot.kernel.sysctl."kernel.kexec_load_disabled" = 0;
        system.stateVersion = "26.05";
        virtualisation.cores = 2;
        virtualisation.graphics = false;
        virtualisation.memorySize = 1536;
        # QEMU's GICv3 ITS/LPI state is not reset reliably across an in-guest
        # kexec under TCG. GICv2 avoids that emulator-only failure and is also
        # the interrupt-controller generation used by the Pi 5 platform.
        virtualisation.qemu.options = [ "-machine gic-version=2" ];

        systemd.services.kaiba-stable-verifier-kexec-vm = {
          description = "Kaiba stable-verifier real kexec VM exercise";
          serviceConfig = {
            Type = "oneshot";
            ExecStart = "${runVerifier}/bin/kaiba-run-aarch64-kexec-vm";
            TimeoutStartSec = 0;
            RuntimeDirectory = "kaiba-kexec-vm";
            RuntimeDirectoryMode = "0700";
            ReadWritePaths = [ "/run/kaiba-kexec-vm" ];
            StandardOutput = "journal+console";
            StandardError = "journal+console";
            NoNewPrivileges = true;
            PrivateDevices = true;
            PrivateTmp = true;
            ProtectControlGroups = true;
            ProtectHome = true;
            ProtectKernelModules = true;
            ProtectKernelTunables = true;
            ProtectSystem = "strict";
            CapabilityBoundingSet = [
              "CAP_SYS_ADMIN"
              "CAP_SYS_BOOT"
            ];
            AmbientCapabilities = [
              "CAP_SYS_ADMIN"
              "CAP_SYS_BOOT"
            ];
            LockPersonality = true;
            MemoryDenyWriteExecute = true;
            RestrictAddressFamilies = [
              "AF_UNIX"
              "AF_INET"
              "AF_INET6"
            ];
            RestrictNamespaces = true;
            RestrictSUIDSGID = true;
            SystemCallFilter = [ "~@mount" ];
            SystemCallArchitectures = "native";
            UMask = "0077";
          };
        };

        # The second kernel intentionally has no test-agent or SSH service.
        # The test driver follows the emulated PL011 console across kexec.
        services.openssh.enable = lib.mkForce false;
      };

    testScript = ''
      console_timeout = 600
      machine.start()
      # Do not spend the test driver's fixed 300-second guest-shell handshake
      # while a cold AArch64 TCG guest is still booting. The serial console is
      # available from reset; wait for the instrumentation's readiness marker.
      machine.wait_for_console_text(r"connecting to host\.\.\.", timeout=console_timeout)
      machine.wait_for_unit("multi-user.target")
      machine.succeed("test -r /sys/firmware/fdt")
      machine.succeed("systemctl start --no-block kaiba-stable-verifier-kexec-vm.service")
      machine.wait_for_console_text("KAIBA_KEXEC_BOOTSTRAP_REGISTERED", timeout=console_timeout)
      machine.wait_for_console_text('"event":"handoff-executing"', timeout=console_timeout)
      machine.wait_for_console_text("KAIBA_KEXEC_SECOND_STAGE_BOOTED", timeout=console_timeout)
      machine.wait_for_console_text("KAIBA_KEXEC_CREDENTIALS_OK", timeout=console_timeout)
      machine.wait_for_console_text("KAIBA_KEXEC_DM_VERITY_METADATA_OK", timeout=console_timeout)
      machine.wait_for_console_text("KAIBA_KEXEC_ONE_BOOT_KEY_REMOVED", timeout=console_timeout)
      machine.wait_for_console_text("KAIBA_KEXEC_SECOND_STAGE_OK", timeout=console_timeout)
      machine.wait_for_shutdown()
    '';
  };

  # GitHub's native ARM64 hosted runners do not expose /dev/kvm. The NixOS VM
  # launcher already falls back from KVM to TCG, so retain the NixOS-test
  # sandbox requirement while dropping the framework's unconditional KVM
  # scheduling marker.
  vmTest = vmTestRequiringKVM.overrideTestDerivation (_: {
    requiredSystemFeatures = [ "nixos-test" ];
  });
in
vmTest
