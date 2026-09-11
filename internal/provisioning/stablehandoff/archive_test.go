//go:build linux

package stablehandoff

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestAppendCredentialArchive(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	base := []byte("verified-base-initramfs")
	var output bytes.Buffer
	err = AppendCredentialArchive(&output, bytes.NewReader(base), int64(len(base)), Credential{
		Authorization:     []byte(`{"schema_version":"test"}`),
		OneBootPrivateKey: privateKey,
		DMVerityMetadata:  []byte(`{"root_hash":"test"}`),
		SlotMetadata:      []byte("a\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(output.Bytes(), base) {
		t.Fatal("base initramfs was not preserved byte-for-byte")
	}
	padding := (4 - len(base)%4) % 4
	if got := output.Bytes()[len(base) : len(base)+padding]; !bytes.Equal(got, make([]byte, padding)) {
		t.Fatalf("inter-member padding = %x, want %d zero bytes", got, padding)
	}
	archive := output.Bytes()[len(base)+padding:]
	if (len(base)+padding)%4 != 0 {
		t.Fatal("appended raw cpio archive is not four-byte aligned")
	}
	for _, expected := range []string{
		"070701", "run/kaiba/boot-authorization.json", "run/kaiba/one-boot-ed25519.pk8",
		"run/kaiba/dm-verity.json", "run/kaiba/slot.txt", "TRAILER!!!",
	} {
		if !bytes.Contains(archive, []byte(expected)) {
			t.Fatalf("archive does not contain %q", expected)
		}
	}
	if bytes.Contains(archive, []byte(hex.EncodeToString(privateKey))) {
		t.Fatal("archive unexpectedly contains a textual private-key encoding")
	}
	entries := parseNewc(t, archive)
	for name, mode := range map[string]uint64{
		"run": 0040755, "run/kaiba": 0040700,
		"run/kaiba/boot-authorization.json": 0100400,
		"run/kaiba/one-boot-ed25519.pk8":    0100400,
		"run/kaiba/dm-verity.json":          0100444,
		"run/kaiba/slot.txt":                0100444,
	} {
		if entries[name].mode != mode {
			t.Fatalf("archive entry %q mode = %#o, want %#o", name, entries[name].mode, mode)
		}
	}
	if got := string(entries["run/kaiba/boot-authorization.json"].contents); got != `{"schema_version":"test"}` {
		t.Fatalf("authorization entry = %q", got)
	}
	if got := string(entries["run/kaiba/dm-verity.json"].contents); got != `{"root_hash":"test"}` {
		t.Fatalf("dm-verity entry = %q", got)
	}
	if got := string(entries["run/kaiba/slot.txt"].contents); got != "a\n" {
		t.Fatalf("slot entry = %q", got)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(entries["run/kaiba/one-boot-ed25519.pk8"].contents)
	if err != nil {
		t.Fatalf("parse archived one-boot key: %v", err)
	}
	archivedKey, ok := parsed.(ed25519.PrivateKey)
	if !ok || !bytes.Equal(archivedKey, privateKey) {
		t.Fatal("archived one-boot key does not match the supplied key")
	}
}

type parsedNewcEntry struct {
	mode     uint64
	contents []byte
}

func parseNewc(t *testing.T, archive []byte) map[string]parsedNewcEntry {
	t.Helper()
	entries := make(map[string]parsedNewcEntry)
	for offset := 0; ; {
		if len(archive)-offset < 110 || string(archive[offset:offset+6]) != "070701" {
			t.Fatalf("invalid newc header at byte %d", offset)
		}
		field := func(start int) uint64 {
			value, err := strconv.ParseUint(string(archive[offset+start:offset+start+8]), 16, 32)
			if err != nil {
				t.Fatalf("parse newc field at byte %d: %v", offset+start, err)
			}
			return value
		}
		mode := field(14)
		contentSize := int(field(54))
		nameSize := int(field(94))
		offset += 110
		if nameSize < 2 || len(archive)-offset < nameSize || archive[offset+nameSize-1] != 0 {
			t.Fatalf("invalid newc name at byte %d", offset)
		}
		name := string(archive[offset : offset+nameSize-1])
		offset += nameSize
		offset = (offset + 3) &^ 3
		if contentSize < 0 || len(archive)-offset < contentSize {
			t.Fatalf("invalid newc contents for %q", name)
		}
		contents := append([]byte(nil), archive[offset:offset+contentSize]...)
		offset += contentSize
		offset = (offset + 3) &^ 3
		if name == "TRAILER!!!" {
			if mode != 0 || contentSize != 0 || offset != len(archive) {
				t.Fatal("non-canonical newc trailer")
			}
			return entries
		}
		if _, exists := entries[name]; exists {
			t.Fatalf("duplicate newc entry %q", name)
		}
		entries[name] = parsedNewcEntry{mode: mode, contents: contents}
	}
}

func TestAppendCredentialArchiveRejectsBoundaryMismatch(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	err = AppendCredentialArchive(&output, strings.NewReader("too-long"), 3, Credential{
		Authorization:     []byte(`{}`),
		OneBootPrivateKey: privateKey,
		DMVerityMetadata:  []byte(`{}`),
		SlotMetadata:      []byte("a\n"),
	})
	if err == nil || !strings.Contains(err.Error(), "beyond its retained size") {
		t.Fatalf("expected boundary error, got %v", err)
	}
}

func TestPrepareInitramfsUsesSealedMemory(t *testing.T) {
	base, err := os.CreateTemp(t.TempDir(), "base-initramfs")
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	if _, err := base.WriteString("base"); err != nil {
		t.Fatal(err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := PrepareInitramfs(base, Credential{
		Authorization:     []byte(`{}`),
		OneBootPrivateKey: privateKey,
		DMVerityMetadata:  []byte(`{}`),
		SlotMetadata:      []byte("a\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	contents, err := io.ReadAll(prepared)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(contents, []byte("base")) {
		t.Fatalf("prepared initramfs does not contain the base: %q", contents)
	}
	if _, err := prepared.Write([]byte("mutation")); err == nil {
		t.Fatal("sealed initramfs accepted a write")
	}
}

func TestPlanValidationRejectsUnsafeInputs(t *testing.T) {
	plan := Plan{KexecPath: "relative/kexec"}
	if err := plan.validate(); err == nil {
		t.Fatal("relative kexec path was accepted")
	}

	plan.KexecPath = "/run/current-system/sw/bin/kexec"
	plan.CommandLine = strings.Repeat("x", MaxCommandLineBytes+1)
	if err := plan.validate(); err == nil {
		t.Fatal("oversized command line was accepted")
	}
}

func TestPlanValidationEnforcesArm64CommandLineBufferBoundary(t *testing.T) {
	plan := Plan{
		KexecPath:   "/run/current-system/sw/bin/kexec",
		Kernel:      writeRetainedFile(t, "kernel"),
		Initramfs:   writeRetainedFile(t, "initramfs"),
		DeviceTree:  writeRetainedFile(t, "dtb"),
		CommandLine: strings.Repeat("x", MaxCommandLineBytes),
	}
	if err := plan.validate(); err != nil {
		t.Fatalf("command line at arm64 limit was rejected: %v", err)
	}
	plan.CommandLine += "x"
	if err := plan.validate(); err == nil || !strings.Contains(err.Error(), "between 1 and 2047 bytes") {
		t.Fatalf("over-limit command line error = %v", err)
	}
}

func TestPlanLoadUsesOnlyRetainedDescriptors(t *testing.T) {
	kernel := writeRetainedFile(t, "kernel")
	initramfs := writeRetainedFile(t, "initramfs")
	dtb := writeRetainedFile(t, "dtb")
	runner := &recordingRunner{}
	plan := Plan{
		KexecPath: "/nix/store/test/bin/kexec",
		Kernel:    kernel, Initramfs: initramfs, DeviceTree: dtb,
		CommandLine: "root=/dev/dm-0 ro",
		Runner:      runner,
	}
	loaded, err := plan.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if loaded == nil {
		t.Fatal("load returned no execution capability")
	}
	wantArguments := []string{
		"--kexec-syscall", "--load", "/proc/self/fd/3", "--initrd=/proc/self/fd/4", "--dtb=/proc/self/fd/5",
		"--command-line=root=/dev/dm-0 ro",
	}
	if runner.path != plan.KexecPath || !slices.Equal(runner.arguments, wantArguments) {
		t.Fatalf("unexpected kexec invocation: path=%q arguments=%q", runner.path, runner.arguments)
	}
	if len(runner.extraFiles) != 3 || runner.extraFiles[0] != kernel || runner.extraFiles[1] != initramfs || runner.extraFiles[2] != dtb {
		t.Fatalf("unexpected retained descriptor order: %#v", runner.extraFiles)
	}
}

func TestPlanExperimentalFileLiveDeviceTreeModeUsesOnlyKernelAndInitramfs(t *testing.T) {
	kernel := writeRetainedFile(t, "kernel")
	initramfs := writeRetainedFile(t, "initramfs")
	runner := &recordingRunner{}
	plan := Plan{
		Mode:        KexecModeExperimentalFileLiveDeviceTree,
		KexecPath:   "/nix/store/test/bin/kexec",
		Kernel:      kernel,
		Initramfs:   initramfs,
		CommandLine: "root=/dev/dm-0 ro",
		Runner:      runner,
	}
	loaded, err := plan.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if loaded == nil {
		t.Fatal("load returned no execution capability")
	}
	wantArguments := []string{
		"--kexec-file-syscall", "--load", "/proc/self/fd/3", "--initrd=/proc/self/fd/4",
		"--command-line=root=/dev/dm-0 ro",
	}
	if runner.path != plan.KexecPath || !slices.Equal(runner.arguments, wantArguments) {
		t.Fatalf("unexpected kexec invocation: path=%q arguments=%q", runner.path, runner.arguments)
	}
	if len(runner.extraFiles) != 2 || runner.extraFiles[0] != kernel || runner.extraFiles[1] != initramfs {
		t.Fatalf("unexpected retained descriptor order: %#v", runner.extraFiles)
	}
}

func TestPlanValidationRejectsContradictoryKexecModeInputs(t *testing.T) {
	base := func() Plan {
		return Plan{
			KexecPath:   "/nix/store/test/bin/kexec",
			Kernel:      writeRetainedFile(t, "kernel"),
			Initramfs:   writeRetainedFile(t, "initramfs"),
			CommandLine: "ro",
			Runner:      &recordingRunner{},
		}
	}
	tests := []struct {
		name      string
		configure func(*Plan)
		wantError string
	}{
		{
			name:      "default legacy mode requires explicit device tree",
			configure: func(*Plan) {},
			wantError: "device tree retained file is required in legacy explicit-device-tree mode",
		},
		{
			name: "experimental file mode rejects explicit device tree",
			configure: func(plan *Plan) {
				plan.Mode = KexecModeExperimentalFileLiveDeviceTree
				plan.DeviceTree = writeRetainedFile(t, "dtb")
			},
			wantError: "device tree retained file must be omitted in experimental file/live-device-tree mode",
		},
		{
			name: "unknown mode is rejected",
			configure: func(plan *Plan) {
				plan.Mode = KexecMode(255)
			},
			wantError: "unsupported kexec mode 255",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan := base()
			test.configure(&plan)
			_, err := plan.Load(context.Background())
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("load error = %v, want error containing %q", err, test.wantError)
			}
			if runner := plan.Runner.(*recordingRunner); runner.calls != 0 {
				t.Fatalf("validation failure invoked runner %d times", runner.calls)
			}
		})
	}
}

func TestPlanStopsBetweenFailedLoadAndExecute(t *testing.T) {
	runner := &recordingRunner{err: errors.New("load rejected")}
	plan := Plan{
		KexecPath:   "/nix/store/test/bin/kexec",
		Kernel:      writeRetainedFile(t, "kernel"),
		Initramfs:   writeRetainedFile(t, "initramfs"),
		DeviceTree:  writeRetainedFile(t, "dtb"),
		CommandLine: "ro",
		Runner:      runner,
	}
	if _, err := plan.Load(context.Background()); err == nil || !strings.Contains(err.Error(), "load verified release") {
		t.Fatalf("expected fail-closed load error, got %v", err)
	}
	if runner.calls != 1 {
		t.Fatalf("unexpected invocation count %d", runner.calls)
	}
}

func TestPlanRejectsMissingOrCancelledContext(t *testing.T) {
	plan := Plan{
		KexecPath:   "/nix/store/test/bin/kexec",
		Kernel:      writeRetainedFile(t, "kernel"),
		Initramfs:   writeRetainedFile(t, "initramfs"),
		DeviceTree:  writeRetainedFile(t, "dtb"),
		CommandLine: "ro",
		Runner:      &recordingRunner{},
	}
	if _, err := plan.Load(nil); err == nil {
		t.Fatal("nil load context was accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := plan.Load(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled load context error = %v", err)
	}
	if err := (*Loaded)(nil).Execute(nil); err == nil {
		t.Fatal("nil execution context was accepted")
	}
}

func TestLoadedCapabilityIsSingleUse(t *testing.T) {
	runner := &recordingRunner{}
	plan := Plan{
		KexecPath:   "/nix/store/test/bin/kexec",
		Kernel:      writeRetainedFile(t, "kernel"),
		Initramfs:   writeRetainedFile(t, "initramfs"),
		DeviceTree:  writeRetainedFile(t, "dtb"),
		CommandLine: "ro",
		Runner:      runner,
	}
	loaded, err := plan.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := loaded.Execute(context.Background()); err == nil || !strings.Contains(err.Error(), "returned without transferring control") {
		t.Fatalf("expected test runner return to be treated as an execution failure, got %v", err)
	}
	if err := loaded.Execute(context.Background()); err == nil || !strings.Contains(err.Error(), "already consumed") {
		t.Fatalf("expected consumed-capability error, got %v", err)
	}
	if runner.calls != 2 {
		t.Fatalf("wanted one load and one execute call, got %d", runner.calls)
	}
}

type recordingRunner struct {
	path       string
	arguments  []string
	extraFiles []*os.File
	err        error
	calls      int
}

func (runner *recordingRunner) Run(_ context.Context, path string, arguments []string, extraFiles []*os.File, _ io.Writer) error {
	runner.calls++
	runner.path = path
	runner.arguments = append([]string(nil), arguments...)
	runner.extraFiles = append([]*os.File(nil), extraFiles...)
	return runner.err
}

func writeRetainedFile(t *testing.T, contents string) *os.File {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "retained")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { file.Close() })
	if _, err := file.WriteString(contents); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	return file
}
