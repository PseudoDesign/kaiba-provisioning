{
  pkgs,
  source,
  lib ? pkgs.lib,
  guestPkgs ? pkgs,
  qemuPackage ? pkgs.qemu,
  requireInPlacePatch,
}:

assert lib.assertMsg pkgs.stdenv.hostPlatform.isLinux
  "the stable-handoff kexec_file VM check requires a Linux VM host";
assert lib.assertMsg (
  guestPkgs.stdenv.hostPlatform.system == "aarch64-linux"
) "the stable-handoff kexec_file VM guest must use aarch64-linux package set";
assert lib.assertMsg (builtins.pathExists "${source}/go.mod")
  "source must contain the repository Go module";
assert lib.assertMsg
  (builtins.pathExists "${source}/internal/provisioning/stablehandoff/kexec_linux.go")
  "source must contain the stablehandoff implementation";

let
  firstStageFdtProvenance = "kaiba-qemu-virt-first-stage-fdt-v1";
  secondStageCommandLine = lib.concatStringsSep " " [
    "console=ttyAMA0,115200"
    "earlycon=pl011,0x09000000"
    "rdinit=/init"
    "kaiba.kexec_file_live_fdt=1"
  ];
  credentialAuthorization = ''{"decision":"authorized","source":"stablehandoff-qemu-virt"}'';
  credentialDMVerity = ''{"mode":"metadata-handoff-observation","root_hash":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}'';
  credentialSlot = "qemu-file\n";

  # QEMU normally synthesizes this tree when it starts. Generate the same
  # generic virt tree explicitly so the test can add one immutable canary to
  # the first kernel's boot-time flattened FDT. arm64 kexec_file_load builds
  # the target FDT from initial_boot_params while replacing /chosen/bootargs
  # and initrd data. Whole-DTB equality would not be a sound assertion because
  # those fields and reservations are legitimately rewritten.
  firstStageDeviceTree =
    pkgs.runCommand "kaiba-kexec-file-qemu-virt-first-stage.dtb"
      {
        nativeBuildInputs = [
          pkgs.dtc
          qemuPackage
        ];
        preferLocalBuild = true;
      }
      ''
        set -euo pipefail
        export LC_ALL=C

        qemu-system-aarch64 \
          -machine virt,gic-version=2,dtb-randomness=off,dumpdtb="$out" \
          -cpu max \
          -smp 4 \
          -m 1536M \
          -display none

        test -s "$out"
        test "$(fdtget -t s "$out" / model)" = linux,dummy-virt
        test "$(fdtget -t s "$out" / compatible)" = linux,dummy-virt
        for cpu in 0 1 2 3; do
          fdtget "$out" "/cpus/cpu@$cpu" reg > /dev/null
        done

        fdtput -t s \
          "$out" \
          /chosen \
          kaiba,kexec-file-vm-provenance \
          ${lib.escapeShellArg firstStageFdtProvenance}
        test "$(
          fdtget -t s "$out" /chosen kaiba,kexec-file-vm-provenance
        )" = ${lib.escapeShellArg firstStageFdtProvenance}
      '';

  handoffDriverMain = guestPkgs.writeText "kaiba-stablehandoff-vm-main.go" ''
    package main

    import (
      "context"
      "crypto/ed25519"
      "crypto/rand"
      "errors"
      "flag"
      "fmt"
      "io"
      "os"
      "os/exec"
      "regexp"
      "strings"
      "syscall"

      "github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stablehandoff"
    )

    const (
      fcntlGetSeals = 1034
      requiredSeals = 0x0001 | 0x0002 | 0x0004 | 0x0008
    )

    var (
      authorization = []byte(${builtins.toJSON credentialAuthorization})
      dmVerity = []byte(${builtins.toJSON credentialDMVerity})
      slot = []byte(${builtins.toJSON credentialSlot})
      directFileLoad = regexp.MustCompile(
        `(?m)kexec_file_load: type:0, start:0x[0-9a-f]+ head:0x4 flags:0x8$`,
      )
      directArm64Head = regexp.MustCompile(`(?m)head:[[:space:]]+4$`)
      zeroRelocation = regexp.MustCompile(`(?m)kern_reloc:[[:space:]]+(0x)?0+$`)
    )

    func fatal(format string, arguments ...any) {
      fmt.Fprintf(os.Stderr, "stablehandoff VM driver: "+format+"\n", arguments...)
      os.Exit(1)
    }

    type diagnosticExecRunner struct {
      commandLine string
      loadSeen bool
      executeSeen bool
    }

    func (runner *diagnosticExecRunner) Run(
      ctx context.Context,
      path string,
      arguments []string,
      extraFiles []*os.File,
      output io.Writer,
    ) error {
      invocation := append([]string(nil), arguments...)
      switch {
      case len(arguments) == 5 && arguments[0] == "--kexec-file-syscall":
        expected := []string{
          "--kexec-file-syscall",
          "--load",
          "/proc/self/fd/3",
          "--initrd=/proc/self/fd/4",
          "--command-line=" + runner.commandLine,
        }
        for index := range expected {
          if arguments[index] != expected[index] {
            return fmt.Errorf("unexpected Plan.Load arguments: %q", arguments)
          }
        }
        if runner.loadSeen || runner.executeSeen || len(extraFiles) != 2 {
          return errors.New("invalid Plan.Load invocation state")
        }
        for index, retained := range extraFiles {
          identity, err := retained.Stat()
          if err != nil || !identity.Mode().IsRegular() {
            return fmt.Errorf("inherited descriptor %d is not a retained regular file", index+3)
          }
        }
        runner.loadSeen = true
        fmt.Fprintf(
          output,
          "KAIBA_STABLEHANDOFF_PLAN_LOAD_ARGS:%s\n",
          strings.Join(arguments, "|"),
        )
        // Plan still owns the exact file-mode argv and inherited descriptors.
        // This test runner adds only the observation flag that asks Linux 6.18
        // to emit the direct/CMA image layout before accepting the load.
        invocation = append([]string{"--debug"}, invocation...)
      case len(arguments) == 1 && arguments[0] == "--exec":
        if !runner.loadSeen || runner.executeSeen || len(extraFiles) != 0 {
          return errors.New("invalid Plan.Execute invocation state")
        }
        runner.executeSeen = true
        fmt.Fprintln(output, "KAIBA_STABLEHANDOFF_PLAN_EXECUTE")
      default:
        return fmt.Errorf("unexpected stablehandoff runner invocation: %q", arguments)
      }

      command := exec.CommandContext(ctx, path, invocation...)
      command.ExtraFiles = extraFiles
      command.Stdout = output
      command.Stderr = output
      return command.Run()
    }

    func openRegular(path, label string) *os.File {
      opened, err := os.Open(path)
      if err != nil {
        fatal("open %s: %v", label, err)
      }
      identity, err := opened.Stat()
      if err != nil || !identity.Mode().IsRegular() {
        opened.Close()
        fatal("%s is not a retained regular file", label)
      }
      return opened
    }

    func readKernelLog(ctx context.Context, dmesgPath string) []byte {
      command := exec.CommandContext(ctx, dmesgPath)
      output, err := command.CombinedOutput()
      if err != nil {
        fatal("read kernel log: %v: %s", err, output)
      }
      os.Stdout.Write(output)
      return output
    }

    func main() {
      kernelPath := flag.String("kernel", "", "retained target kernel")
      baseInitramfsPath := flag.String("base-initramfs", "", "retained base initramfs")
      kexecPath := flag.String("kexec", "", "pinned kexec executable")
      dmesgPath := flag.String("dmesg", "", "pinned dmesg executable")
      commandLine := flag.String("command-line", "", "second-stage command line")
      expectLoadFailure := flag.Bool(
        "expect-load-failure",
        false,
        "require the in-place policy to reject the load",
      )
      flag.Parse()
      if flag.NArg() != 0 || *kernelPath == "" || *baseInitramfsPath == "" ||
        *kexecPath == "" || *dmesgPath == "" || *commandLine == "" {
        fatal("kernel, base-initramfs, kexec, dmesg, and command-line are required")
      }

      kernel := openRegular(*kernelPath, "kernel")
      defer kernel.Close()
      baseInitramfs := openRegular(*baseInitramfsPath, "base initramfs")
      defer baseInitramfs.Close()

      _, privateKey, err := ed25519.GenerateKey(rand.Reader)
      if err != nil {
        fatal("generate one-boot key: %v", err)
      }
      preparedInitramfs, err := stablehandoff.PrepareInitramfs(
        baseInitramfs,
        stablehandoff.Credential{
          Authorization: authorization,
          OneBootPrivateKey: privateKey,
          DMVerityMetadata: dmVerity,
          SlotMetadata: slot,
        },
      )
      clear(privateKey)
      if err != nil {
        fatal("PrepareInitramfs: %v", err)
      }
      defer preparedInitramfs.Close()

      seals, _, errno := syscall.Syscall(
        syscall.SYS_FCNTL,
        preparedInitramfs.Fd(),
        fcntlGetSeals,
        0,
      )
      if errno != 0 || seals != requiredSeals {
        fatal("prepared initramfs seals = %#x, errno = %v", seals, errno)
      }
      if _, err := preparedInitramfs.WriteAt([]byte("mutation"), 0); err == nil {
        fatal("prepared initramfs accepted a write after sealing")
      }
      fmt.Println("KAIBA_STABLEHANDOFF_PREPARED_INITRAMFS_SEALED")

      ctx := context.Background()
      runner := &diagnosticExecRunner{commandLine: *commandLine}
      loaded, loadErr := (stablehandoff.Plan{
        Mode: stablehandoff.KexecModeExperimentalFileLiveDeviceTree,
        KexecPath: *kexecPath,
        Kernel: kernel,
        Initramfs: preparedInitramfs,
        DeviceTree: nil,
        CommandLine: *commandLine,
        Output: os.Stdout,
        Runner: runner,
      }).Load(ctx)

      if *expectLoadFailure {
        if loadErr == nil || loaded != nil {
          fatal("relocating Plan.Load unexpectedly succeeded")
        }
        kernelLog := readKernelLog(ctx, *dmesgPath)
        if !strings.Contains(
          string(kernelLog),
          "Refusing kexec_file image that requires relocation",
        ) {
          fatal("kernel log does not contain require-in-place refusal")
        }
        if runner.executeSeen {
          fatal("Plan.Execute ran after a rejected Plan.Load")
        }
        fmt.Printf("KAIBA_STABLEHANDOFF_PLAN_LOAD_REJECTED:%v\n", loadErr)
        fmt.Println("KAIBA_STABLEHANDOFF_RELOCATION_REJECTED_WITHOUT_EXECUTE")
        return
      }

      if loadErr != nil || loaded == nil || !runner.loadSeen {
        fatal("direct Plan.Load failed: %v", loadErr)
      }
      kernelLog := readKernelLog(ctx, *dmesgPath)
      if !directFileLoad.Match(kernelLog) {
        fatal("kernel log lacks direct file-load head evidence")
      }
      if !directArm64Head.Match(kernelLog) {
        fatal("kernel log lacks arm64 IND_DONE evidence")
      }
      if !zeroRelocation.Match(kernelLog) {
        fatal("kernel log reports a relocation stub")
      }
      if strings.Contains(
        string(kernelLog),
        "Refusing kexec_file image that requires relocation",
      ) {
        fatal("require-in-place policy rejected the direct load")
      }
      fmt.Println("KAIBA_STABLEHANDOFF_DIRECT_CMA_LOAD_ACCEPTED")

      if err := loaded.Execute(ctx); err != nil {
        fatal("Plan.Execute: %v", err)
      }
      fatal("Plan.Execute returned without an error")
    }
  '';

  handoffDriverSource =
    guestPkgs.runCommand "kaiba-stablehandoff-kexec-file-vm-source"
      {
        sourceInput = source;
        mainInput = handoffDriverMain;
      }
      ''
        set -euo pipefail
        mkdir -p \
          "$out/cmd/kaiba-stablehandoff-kexec-file-vm" \
          "$out/internal/provisioning/stablehandoff"
        install -m 0444 "$sourceInput/go.mod" "$out/go.mod"
        for file in \
          archive.go \
          kexec_linux.go \
          memfd_linux.go \
          syscall_linux_arm64.go
        do
          install -m 0444 \
            "$sourceInput/internal/provisioning/stablehandoff/$file" \
            "$out/internal/provisioning/stablehandoff/$file"
        done
        install -m 0444 \
          "$mainInput" \
          "$out/cmd/kaiba-stablehandoff-kexec-file-vm/main.go"
      '';

  handoffDriver = guestPkgs.buildGoModule {
    pname = "kaiba-stablehandoff-kexec-file-vm";
    version = "0.1.0";
    src = handoffDriverSource;
    subPackages = [ "cmd/kaiba-stablehandoff-kexec-file-vm" ];
    vendorHash = null;
    env.CGO_ENABLED = 0;
    ldflags = [
      "-s"
      "-w"
    ];
    doCheck = false;
    passthru.kaibaStableHandoffVMDriver = {
      architecture = "aarch64-linux";
      repositoryStableHandoffIntegrated = true;
      prepareInitramfs = true;
      experimentalFileLiveDeviceTreePlan = true;
      staticallyLinked = true;
      productionReady = false;
    };
  };

  secondStageInit = guestPkgs.writeText "kaiba-kexec-file-vm-init" ''
    #!/bin/busybox sh
    set -eu
    bb=/bin/busybox

    "$bb" mkdir -p /dev /proc /sys
    "$bb" mount -t devtmpfs devtmpfs /dev
    "$bb" test -c /dev/console
    exec </dev/console >/dev/console 2>&1
    "$bb" mount -t proc proc /proc
    "$bb" mount -t sysfs sysfs /sys

    fail() {
      "$bb" echo "KAIBA_KEXEC_FILE_SECOND_STAGE_FAILED:$1"
      "$bb" sync
      "$bb" poweroff -f
      while "$bb" true; do
        "$bb" sleep 10
      done
    }

    read_text() {
      "$bb" tr -d '\000\n' <"$1"
    }

    for path in \
      /run/kaiba/boot-authorization.json \
      /run/kaiba/one-boot-ed25519.pk8 \
      /run/kaiba/dm-verity.json \
      /run/kaiba/slot.txt
    do
      "$bb" test -s "$path" || fail "missing-credential:$path"
    done
    "$bb" test "$("$bb" stat -c %a /run/kaiba)" = 700 \
      || fail credential-directory-mode
    "$bb" test "$("$bb" stat -c %a /run/kaiba/boot-authorization.json)" = 400 \
      || fail authorization-mode
    "$bb" test "$("$bb" stat -c %a /run/kaiba/one-boot-ed25519.pk8)" = 400 \
      || fail one-boot-key-mode
    "$bb" test "$("$bb" stat -c %a /run/kaiba/dm-verity.json)" = 444 \
      || fail dm-verity-mode
    "$bb" test "$("$bb" stat -c %a /run/kaiba/slot.txt)" = 444 \
      || fail slot-mode
    "$bb" test "$(read_text /run/kaiba/boot-authorization.json)" = \
      ${lib.escapeShellArg credentialAuthorization} \
      || fail authorization-contents
    "$bb" test "$(read_text /run/kaiba/dm-verity.json)" = \
      ${lib.escapeShellArg credentialDMVerity} \
      || fail dm-verity-contents
    "$bb" test "$(read_text /run/kaiba/slot.txt)" = qemu-file \
      || fail slot-contents
    key_size="$(
      "$bb" wc -c </run/kaiba/one-boot-ed25519.pk8 \
        | "$bb" tr -d ' '
    )"
    key_prefix="$(
      "$bb" od -An -tx1 -N16 /run/kaiba/one-boot-ed25519.pk8 \
        | "$bb" tr -d ' \n'
    )"
    "$bb" test "$key_size" = 48 || fail one-boot-key-size
    "$bb" test "$key_prefix" = 302e020100300506032b657004220420 \
      || fail one-boot-key-pkcs8-ed25519
    "$bb" echo KAIBA_STABLEHANDOFF_CREDENTIAL_ARCHIVE_OK

    command_line="$(read_text /proc/cmdline)"
    possible="$(read_text /sys/devices/system/cpu/possible)"
    present="$(read_text /sys/devices/system/cpu/present)"
    online="$(read_text /sys/devices/system/cpu/online)"
    model="$(read_text /proc/device-tree/model)"
    compatible="$(read_text /proc/device-tree/compatible)"
    provenance="$(
      read_text /proc/device-tree/chosen/kaiba,kexec-file-vm-provenance
    )"

    "$bb" echo "KAIBA_KEXEC_FILE_SECOND_STAGE_CMDLINE:$command_line"
    "$bb" echo "KAIBA_KEXEC_FILE_SECOND_STAGE_CPU_POSSIBLE:$possible"
    "$bb" echo "KAIBA_KEXEC_FILE_SECOND_STAGE_CPU_PRESENT:$present"
    "$bb" echo "KAIBA_KEXEC_FILE_SECOND_STAGE_CPU_ONLINE:$online"
    "$bb" echo "KAIBA_KEXEC_FILE_SECOND_STAGE_MODEL:$model"
    "$bb" echo "KAIBA_KEXEC_FILE_SECOND_STAGE_FDT_PROVENANCE:$provenance"

    "$bb" test "$command_line" = ${lib.escapeShellArg secondStageCommandLine} \
      || fail command-line
    "$bb" test "$possible" = 0-3 || fail cpu-possible
    "$bb" test "$present" = 0-3 || fail cpu-present
    "$bb" test "$online" = 0-3 || fail cpu-online
    "$bb" test "$model" = linux,dummy-virt || fail qemu-model
    "$bb" test "$compatible" = linux,dummy-virt || fail qemu-compatible
    "$bb" test "$provenance" = ${lib.escapeShellArg firstStageFdtProvenance} \
      || fail boot-fdt-provenance

    "$bb" rm /run/kaiba/one-boot-ed25519.pk8
    "$bb" test ! -e /run/kaiba/one-boot-ed25519.pk8 \
      || fail one-boot-key-removal
    "$bb" echo KAIBA_STABLEHANDOFF_ONE_BOOT_KEY_REMOVED
    "$bb" echo KAIBA_KEXEC_FILE_BOOT_FDT_SMP4_OK
    "$bb" sync
    "$bb" poweroff -f
    while "$bb" true; do
      "$bb" echo KAIBA_KEXEC_FILE_SECOND_STAGE_POWEROFF_RETURNED
      "$bb" sleep 10
    done
  '';

  secondStageInitramfs =
    guestPkgs.runCommand "kaiba-kexec-file-vm-initramfs"
      {
        nativeBuildInputs = [
          guestPkgs.binutils
          guestPkgs.coreutils
          guestPkgs.cpio
          guestPkgs.findutils
          guestPkgs.gnugrep
        ];
        passthru.kaibaStableHandoffKexecFileInitramfs = {
          architecture = "aarch64-linux";
          staticBusybox = true;
          init = "/init";
          receivesSealedCredentialArchive = true;
          productionReady = false;
        };
      }
      ''
        set -euo pipefail
        export LC_ALL=C
        export TZ=UTC

        busybox=${guestPkgs.pkgsStatic.busybox}/bin/busybox
        test -x "$busybox"
        readelf --file-header "$busybox" \
          | grep -E 'Machine:[[:space:]]+AArch64$' > /dev/null
        if readelf --program-headers "$busybox" \
          | grep -F ' INTERP ' > /dev/null; then
          echo "the second-stage BusyBox must be statically linked" >&2
          exit 1
        fi
        "$busybox" --list > "$TMPDIR/busybox-applets"
        for applet in echo mkdir mount od poweroff rm sh sleep stat sync test tr true wc; do
          grep -F -x "$applet" "$TMPDIR/busybox-applets" > /dev/null
        done

        root="$TMPDIR/root"
        mkdir -p "$root/bin" "$root/dev" "$root/proc" "$root/sys"
        install -m 0555 "$busybox" "$root/bin/busybox"
        install -m 0555 ${secondStageInit} "$root/init"
        find "$root" -exec touch -h --date=@1 '{}' +
        (
          cd "$root"
          find . -print0 | sort -z \
            | cpio \
                --null \
                --create \
                --format=newc \
                --owner=0:0 \
                --reproducible \
                --quiet
        ) > "$out"
        test -s "$out"
      '';

  # Start from tinyconfig and name every dependency of the NixOS/QEMU and
  # stablehandoff paths explicitly. Keep the module framework enabled because
  # Nixpkgs' generic kernel builder uses CONFIG_MODULES=y in its output
  # metadata, but request no option as a module and prove that the realized
  # configuration contains no =m entries before exercising kexec.
  vmKernelStructuredConfig = with lib.kernel; {
    "9P_FS" = yes;
    ARM64_4K_PAGES = yes;
    ARM64_KEXEC_FILE_REQUIRE_IN_PLACE = yes;
    ARM64_VA_BITS_48 = yes;
    AUTOFS_FS = yes;
    BINFMT_ELF = yes;
    BINFMT_SCRIPT = yes;
    BLK_DEV = yes;
    BLK_DEV_INITRD = yes;
    BLOCK = yes;
    CGROUPS = yes;
    CMA = yes;
    CRYPTO = yes;
    CRYPTO_HMAC = yes;
    CRYPTO_SHA256 = yes;
    CRYPTO_USER_API_HASH = yes;
    DEVTMPFS = yes;
    DEVTMPFS_MOUNT = yes;
    DMI = yes;
    DMIID = yes;
    DMA_CMA = yes;
    EFI = yes;
    EFIVAR_FS = no;
    EPOLL = yes;
    EVENTFD = yes;
    EXT4_FS = yes;
    FHANDLE = yes;
    FILE_LOCKING = yes;
    FUTEX = yes;
    FW_LOADER = yes;
    HOTPLUG_CPU = yes;
    HW_RANDOM = yes;
    HW_RANDOM_VIRTIO = yes;
    INET = yes;
    INOTIFY_USER = yes;
    IPV6 = yes;
    KEXEC_FILE = yes;
    MEMFD_CREATE = yes;
    MODULES = yes;
    MULTIUSER = yes;
    NAMESPACES = yes;
    NET = yes;
    NETDEVICES = yes;
    NET_9P = yes;
    NET_9P_VIRTIO = yes;
    NET_CORE = yes;
    NETWORK_FILESYSTEMS = yes;
    NR_CPUS = freeform "4";
    OF = yes;
    OVERLAY_FS = yes;
    PACKET = yes;
    PCI = yes;
    PCI_HOST_GENERIC = yes;
    PCI_MSI = yes;
    POSIX_MQUEUE = yes;
    POSIX_TIMERS = yes;
    PRINTK = yes;
    PROC_FS = yes;
    RD_ZSTD = yes;
    RELOCATABLE = yes;
    SECCOMP = yes;
    SECCOMP_FILTER = yes;
    SERIAL_8250 = yes;
    SERIAL_8250_CONSOLE = yes;
    SERIAL_AMBA_PL011 = yes;
    SERIAL_AMBA_PL011_CONSOLE = yes;
    SHMEM = yes;
    SIGNALFD = yes;
    SMP = yes;
    SYSCTL = yes;
    SYSFS = yes;
    SYSVIPC = yes;
    TIMERFD = yes;
    TMPFS = yes;
    TMPFS_POSIX_ACL = yes;
    TMPFS_XATTR = yes;
    TTY = yes;
    UNIX = yes;
    VIRTIO = yes;
    VIRTIO_BLK = yes;
    VIRTIO_CONSOLE = yes;
    VIRTIO_MENU = yes;
    VIRTIO_NET = yes;
    VIRTIO_PCI = yes;
    VIRTIO_PCI_LEGACY = yes;
  };

  vmKernelYesOptions = builtins.filter (
    option:
    !(builtins.elem option [
      "EFIVAR_FS"
      "NR_CPUS"
    ])
  ) (builtins.attrNames vmKernelStructuredConfig);

  vmKernelPackages = guestPkgs.linuxPackagesFor (
    guestPkgs.linuxPackages.kernel.override {
      defconfig = "tinyconfig";
      autoModules = false;
      buildDTBs = false;
      enableCommonConfig = false;
      ignoreConfigErrors = false;
    }
  );

  mkNode =
    {
      cmaParameter,
      expectedCMAKilobytes,
      expectLoadFailure,
    }:
    {
      config,
      lib,
      pkgs,
      ...
    }:
    {
      boot.kernelPackages = vmKernelPackages;
      boot.kernelParams = [
        "console=ttyAMA0,115200"
        "earlycon=pl011,0x09000000"
        "maxcpus=1"
        cmaParameter
      ];
      boot.kernel.sysctl = {
        "kernel.dmesg_restrict" = 0;
        "kernel.kexec_load_disabled" = 0;
      };
      boot.kernelPatches = [
        {
          name = "kaiba-arm64-kexec-file-require-in-place-vm";
          patch = requireInPlacePatch;
          structuredExtraConfig = vmKernelStructuredConfig;
        }
      ];
      hardware.deviceTree.enable = lib.mkForce false;

      # Every test dependency is built in. Eliminate NixOS' generic module
      # request lists while retaining strict missing-module failures if a
      # future request escapes these exact overrides.
      boot.initrd.includeDefaultModules = lib.mkForce false;
      boot.initrd.availableKernelModules = lib.mkForce [ ];
      boot.initrd.kernelModules = lib.mkForce [ ];
      boot.initrd.allowMissingModules = false;
      boot.kernelModules = lib.mkForce [ ];

      # Neither isolated test node accepts network ingress. Avoid unrelated
      # nftables and accounting dependencies in the purpose-built kernel.
      networking.firewall.enable = lib.mkForce false;
      systemd.settings.Manager.DefaultIPAccounting = lib.mkForce false;
      systemd.settings.Manager.DefaultIOAccounting = lib.mkForce false;

      system.stateVersion = "26.05";
      virtualisation.cores = 4;
      virtualisation.graphics = false;
      virtualisation.memorySize = 1536;
      virtualisation.qemu.package = lib.mkForce qemuPackage;
      # GICv2 has reliable reset semantics across in-guest kexec under TCG.
      # The explicit DTB matches these fixed machine, CPU, and memory values.
      virtualisation.qemu.options = [
        "-machine gic-version=2,dtb-randomness=off"
        "-dtb ${firstStageDeviceTree}"
      ];

      systemd.services.kaiba-stable-handoff-kexec-file-vm = {
        description = "Kaiba generic arm64 stablehandoff kexec_file VM exercise";
        path = [
          pkgs.coreutils
          pkgs.gawk
          pkgs.gnugrep
        ];
        serviceConfig = {
          Type = "oneshot";
          TimeoutStartSec = 0;
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
          CapabilityBoundingSet = [ "CAP_SYS_BOOT" ];
          AmbientCapabilities = [ "CAP_SYS_BOOT" ];
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
        script = ''
          set -euo pipefail

          fail() {
            printf 'KAIBA_KEXEC_FILE_FIRST_STAGE_FAILED:%s\n' "$1"
            exit 1
          }

          read_text() {
            tr -d '\000\n' <"$1"
          }

          test "$(uname -m)" = aarch64 || fail architecture
          kernel_config=${config.boot.kernelPackages.kernel.configfile}
          for option in ${lib.escapeShellArgs vmKernelYesOptions}; do
            grep -Fx "CONFIG_$option=y" "$kernel_config" > /dev/null \
              || fail "missing-kernel-config-$option"
          done
          grep -Fx 'CONFIG_NR_CPUS=4' "$kernel_config" > /dev/null \
            || fail unexpected-kernel-config-NR_CPUS
          grep -Fx '# CONFIG_EFIVAR_FS is not set' "$kernel_config" > /dev/null \
            || fail unexpected-kernel-config-EFIVAR_FS
          if grep -Eq '^CONFIG_[A-Z0-9_]+=m$' "$kernel_config"; then
            grep -E '^CONFIG_[A-Z0-9_]+=m$' "$kernel_config" >&2
            fail loadable-kernel-module-present
          fi
          test "$(cat /proc/sys/kernel/dmesg_restrict)" = 0 \
            || fail dmesg-restrict

          expected_capabilities=0000000000400000
          for field in CapInh CapPrm CapEff CapBnd CapAmb; do
            actual="$(
              awk -v field="$field:" '$1 == field { print tolower($2) }' \
                /proc/self/status
            )"
            printf 'KAIBA_KEXEC_FILE_FIRST_STAGE_%s:%s\n' "$field" "$actual"
            test "$actual" = "$expected_capabilities" \
              || fail "unexpected-$field-capabilities"
          done

          online="$(read_text /sys/devices/system/cpu/online)"
          possible="$(read_text /sys/devices/system/cpu/possible)"
          present="$(read_text /sys/devices/system/cpu/present)"
          printf 'KAIBA_KEXEC_FILE_FIRST_STAGE_CPU_ONLINE:%s\n' "$online"
          printf 'KAIBA_KEXEC_FILE_FIRST_STAGE_CPU_POSSIBLE:%s\n' "$possible"
          printf 'KAIBA_KEXEC_FILE_FIRST_STAGE_CPU_PRESENT:%s\n' "$present"
          test "$online" = 0 || fail cpu-online-not-zero
          test "$possible" = 0-3 || fail cpu-possible-not-four
          test "$present" = 0-3 || fail cpu-present-not-four

          cma_total="$(
            awk '$1 == "CmaTotal:" { print $2 }' /proc/meminfo
          )"
          printf 'KAIBA_KEXEC_FILE_FIRST_STAGE_CMA_TOTAL_KB:%s\n' "$cma_total"
          test "$cma_total" = ${toString expectedCMAKilobytes} \
            || fail unexpected-cma-total

          provenance="$(
            read_text \
              /proc/device-tree/chosen/kaiba,kexec-file-vm-provenance
          )"
          printf 'KAIBA_KEXEC_FILE_FIRST_STAGE_FDT_PROVENANCE:%s\n' \
            "$provenance"
          test "$provenance" = ${lib.escapeShellArg firstStageFdtProvenance} \
            || fail first-stage-fdt-provenance

          exec ${handoffDriver}/bin/kaiba-stablehandoff-kexec-file-vm \
            --kernel /run/current-system/kernel \
            --base-initramfs ${secondStageInitramfs} \
            --kexec ${pkgs.kexec-tools}/bin/kexec \
            --dmesg ${pkgs.util-linux}/bin/dmesg \
            --command-line=${lib.escapeShellArg secondStageCommandLine} \
            ${lib.optionalString expectLoadFailure "--expect-load-failure"}
        '';
      };

      # The successful second stage contains only the static BusyBox archive.
      # The negative node never executes its rejected image. Neither node has
      # an SSH server, swap-backed credential storage, or Raspberry Pi claims.
      services.openssh.enable = lib.mkForce false;
      swapDevices = lib.mkForce [ ];
      zramSwap.enable = false;
    };

  vmTestRequiringKVM = pkgs.testers.runNixOSTest {
    name = "kaiba-stable-handoff-aarch64-kexec-file";
    # The negative and positive AArch64 guests run sequentially and may both
    # use TCG. Per-marker waits remain bounded by console_timeout below.
    globalTimeout = 1800;

    # Keep the Python driver and QEMU native to the build host while allowing
    # callers to supply an independently selected AArch64 guest package set.
    node.pkgs = lib.mkForce guestPkgs;

    passthru.kaibaStableHandoffAarch64KexecFileVM = {
      architecture = "aarch64-linux";
      emulatedMachine = "qemu-virt";
      emulatedInterruptController = "gicv2";
      virtualCPUCount = 4;
      firstStageMaxCPUCount = 1;
      firstStageCMABytes = 128 * 1024 * 1024;
      realKexecFileSyscall = true;
      userspaceSyscallFallbackDisabled = true;
      repositoryStableHandoffIntegrated = true;
      prepareInitramfsObserved = true;
      sealedCredentialInitramfsObserved = true;
      inheritedProcSelfFDsObserved = true;
      experimentalFileLiveDeviceTreePlanObserved = true;
      serviceCapabilityBoundingSet = [ "CAP_SYS_BOOT" ];
      serviceCapabilitiesRuntimeObserved = true;
      kernelRequireInPlacePolicyEnabled = true;
      directCMAEvidenceRequired = true;
      noCMARejectionObserved = true;
      rejectedLoadNeverExecuted = true;
      secondKernelByteIdenticalToFirst = true;
      bootFdtProvenanceCanary = firstStageFdtProvenance;
      secondStageCredentialsObserved = true;
      secondStageSMPObserved = true;
      kvmRequired = false;
      raspberryPiFirmwareObserved = false;
      bcm2712Observed = false;
      rp1Observed = false;
      nvmeObserved = false;
      productionReady = false;
    };

    nodes = {
      # cma=0 explicitly suppresses Linux's default CMA reservation. Every
      # non-empty kexec_file segment consequently uses
      # kimage_load_normal_segment(), which always adds IND_DESTINATION and
      # IND_SOURCE entries. The final image head therefore cannot be the bare
      # IND_DONE value accepted by the require-in-place policy. This makes the
      # rejection independent of page-allocation coincidence.
      negative = mkNode {
        cmaParameter = "cma=0";
        expectedCMAKilobytes = 0;
        expectLoadFailure = true;
      };
      positive = mkNode {
        cmaParameter = "cma=128M";
        expectedCMAKilobytes = 131072;
        expectLoadFailure = false;
      };
    };

    testScript = ''
      console_timeout = 600
      backdoor_console_marker = r"connecting to host\.\.\."

      negative.start()
      # The NixOS test driver's guest-shell handshake has a fixed 300-second
      # budget. A cold four-vCPU AArch64 guest under TCG can legitimately take
      # longer than that to start the backdoor. Follow the already-live serial
      # console to the instrumentation's readiness marker, then connect.
      negative.wait_for_console_text(backdoor_console_marker, timeout=console_timeout)
      negative.wait_for_unit("multi-user.target")
      negative.succeed("test \"$(tr -d '\\n' </sys/devices/system/cpu/online)\" = 0")
      negative.succeed("""test "$(awk '$1 == "CmaTotal:" { print $2 }' /proc/meminfo)" = 0""")
      negative.succeed("systemctl start --no-block kaiba-stable-handoff-kexec-file-vm.service")
      negative.wait_for_console_text("KAIBA_KEXEC_FILE_FIRST_STAGE_CMA_TOTAL_KB:0", timeout=console_timeout)
      negative.wait_for_console_text("KAIBA_STABLEHANDOFF_PREPARED_INITRAMFS_SEALED", timeout=console_timeout)
      negative.wait_for_console_text(r"KAIBA_STABLEHANDOFF_PLAN_LOAD_ARGS:--kexec-file-syscall\|--load\|/proc/self/fd/3\|--initrd=/proc/self/fd/4", timeout=console_timeout)
      negative.wait_for_console_text("Refusing kexec_file image that requires relocation", timeout=console_timeout)
      negative.wait_for_console_text("KAIBA_STABLEHANDOFF_RELOCATION_REJECTED_WITHOUT_EXECUTE", timeout=console_timeout)
      negative.wait_until_succeeds("test \"$(systemctl show -p Result --value kaiba-stable-handoff-kexec-file-vm.service)\" = success")
      negative.fail("journalctl -u kaiba-stable-handoff-kexec-file-vm.service --no-pager | grep -F KAIBA_STABLEHANDOFF_PLAN_EXECUTE")
      negative.shutdown()

      positive.start()
      positive.wait_for_console_text(backdoor_console_marker, timeout=console_timeout)
      positive.wait_for_unit("multi-user.target")
      positive.succeed("test \"$(tr -d '\\n' </sys/devices/system/cpu/online)\" = 0")
      positive.succeed("""test "$(awk '$1 == "CmaTotal:" { print $2 }' /proc/meminfo)" = 131072""")
      positive.succeed("systemctl start --no-block kaiba-stable-handoff-kexec-file-vm.service")
      positive.wait_for_console_text("KAIBA_KEXEC_FILE_FIRST_STAGE_CPU_ONLINE:0", timeout=console_timeout)
      positive.wait_for_console_text("KAIBA_KEXEC_FILE_FIRST_STAGE_CMA_TOTAL_KB:131072", timeout=console_timeout)
      positive.wait_for_console_text("KAIBA_STABLEHANDOFF_PREPARED_INITRAMFS_SEALED", timeout=console_timeout)
      positive.wait_for_console_text(r"KAIBA_STABLEHANDOFF_PLAN_LOAD_ARGS:--kexec-file-syscall\|--load\|/proc/self/fd/3\|--initrd=/proc/self/fd/4", timeout=console_timeout)
      # The final userspace writes immediately before kexec can be lost when
      # the kernel replaces the journald/console pipeline. Observe the
      # kernel's accepted direct image instead. The exact authenticated
      # second-stage sequence below is deterministic proof that Plan.Execute
      # then transferred control to that image.
      positive.wait_for_console_text(r"kexec_file: kexec_file_load: type:0, start:0x[0-9a-f]+ head:0x4 flags:0x8", timeout=console_timeout)
      positive.wait_for_console_text("KAIBA_STABLEHANDOFF_CREDENTIAL_ARCHIVE_OK", timeout=console_timeout)
      positive.wait_for_console_text("KAIBA_KEXEC_FILE_SECOND_STAGE_CMDLINE:${secondStageCommandLine}", timeout=console_timeout)
      positive.wait_for_console_text("KAIBA_KEXEC_FILE_SECOND_STAGE_CPU_POSSIBLE:0-3", timeout=console_timeout)
      positive.wait_for_console_text("KAIBA_KEXEC_FILE_SECOND_STAGE_CPU_PRESENT:0-3", timeout=console_timeout)
      positive.wait_for_console_text("KAIBA_KEXEC_FILE_SECOND_STAGE_CPU_ONLINE:0-3", timeout=console_timeout)
      positive.wait_for_console_text("KAIBA_KEXEC_FILE_SECOND_STAGE_FDT_PROVENANCE:${firstStageFdtProvenance}", timeout=console_timeout)
      positive.wait_for_console_text("KAIBA_STABLEHANDOFF_ONE_BOOT_KEY_REMOVED", timeout=console_timeout)
      positive.wait_for_console_text("KAIBA_KEXEC_FILE_BOOT_FDT_SMP4_OK", timeout=console_timeout)
      positive.wait_for_shutdown()
    '';
  };

  # Native ARM64 CI does not necessarily expose /dev/kvm. The NixOS VM
  # launcher already falls back from KVM to TCG, so require only nixos-test.
  vmTest = vmTestRequiringKVM.overrideTestDerivation (_: {
    requiredSystemFeatures = [ "nixos-test" ];
  });
in
vmTest
