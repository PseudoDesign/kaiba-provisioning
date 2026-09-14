//go:build linux

// The generic tool has no device configuration. Nix binds a candidate to one
// reviewed campaign leg, staging plan and immutable payload set.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaignmedia"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaignstaging"
)

var configurationPath string // Linker-fixed; there is no flag or environment fallback.

const maximumJSONBytes = 4 * 1024 * 1024

type configuration struct {
	Leg             campaignmedia.Leg                      `json:"leg"`
	PayloadPaths    map[campaignmedia.PartitionRole]string `json:"payload_paths"`
	SchemaVersion   string                                 `json:"schema_version"`
	StagingPlanPath string                                 `json:"staging_plan_path"`
}

type singleValue struct {
	value string
	set   bool
}

func (v *singleValue) String() string { return v.value }
func (v *singleValue) Set(value string) error {
	if v.set {
		return errors.New("argument may be supplied exactly once")
	}
	v.value, v.set = value, true
	return nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: kaiba-rpi5-stable-campaign-stage COMMAND [FLAGS]")
	fmt.Fprintln(w, "  prepare --directory NEW_ABS --requirements ABS --sd-envelope ABS --nvme-envelope ABS")
	fmt.Fprintln(w, "  approve --preview ABS --expected-preview-digest sha256:HEX --reviewer ID")
	fmt.Fprintln(w, "  execute --directory ABS --approval ABS --requirements ABS --sd-envelope ABS --nvme-envelope ABS")
	fmt.Fprintln(w, "  verify --requirements ABS --sd-envelope ABS --nvme-envelope ABS")
	fmt.Fprintln(w, "Device operations require a Nix-configured candidate, root, and the fixed inactive device on its fixed host.")
	fmt.Fprintln(w, "Approval is an explicit local operator acknowledgement, not authenticated campaign claim closure.")
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "help") {
		usage(stderr)
		return 0
	}
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	command := args[0]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() { usage(stderr) }
	values := map[string]*singleValue{}
	add := func(name string) {
		v := &singleValue{}
		values[name] = v
		flags.Var(v, name, "required explicit value")
	}
	switch command {
	case "prepare", "execute", "verify":
		for _, name := range []string{"requirements", "sd-envelope", "nvme-envelope"} {
			add(name)
		}
		if command != "verify" {
			add("directory")
		}
		if command == "execute" {
			add("approval")
		}
	case "approve":
		for _, name := range []string{"preview", "expected-preview-digest", "reviewer"} {
			add(name)
		}
	default:
		usage(stderr)
		return 2
	}
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		usage(stderr)
		return 2
	}
	for name, v := range values {
		if !v.set || v.value == "" {
			fmt.Fprintf(stderr, "--%s is required exactly once\n", name)
			return 2
		}
	}
	value := func(name string) string { return values[name].value }
	fail := func(err error) int { fmt.Fprintf(stderr, "campaign staging: %v\n", err); return 1 }
	emit := func(data []byte, err error) int {
		if err != nil {
			return fail(err)
		}
		for len(data) != 0 {
			n, err := stdout.Write(data)
			if err != nil {
				return fail(err)
			}
			if n <= 0 || n > len(data) {
				return fail(io.ErrShortWrite)
			}
			data = data[n:]
		}
		return 0
	}
	if command == "approve" {
		data, err := readJSON(value("preview"))
		if err != nil {
			return fail(err)
		}
		preview, err := campaignstaging.ParsePreview(data)
		if err != nil {
			return fail(err)
		}
		approval, err := campaignstaging.Approve(preview, bundle.Digest(value("expected-preview-digest")), value("reviewer"))
		if err != nil {
			return fail(err)
		}
		return emit(approval.CanonicalJSON())
	}
	// Check the linker boundary before opening any caller input or device.
	fixed, err := loadConfiguration(configurationPath)
	if err != nil {
		return fail(err)
	}
	config, err := loadInputs(fixed, value("requirements"), value("sd-envelope"), value("nvme-envelope"))
	if err != nil {
		return fail(err)
	}
	var identity campaignmedia.DeviceIdentity
	for _, d := range config.Plan.Devices {
		if d.Identity.Leg == config.Leg {
			identity = d.Identity
		}
	}
	protected := []string{}
	if config.Leg == campaignmedia.LegMalakSD {
		protected = []string{"/dev/nvme0n1"}
	}
	opener := campaignstaging.FixedDeviceOpener{Identity: identity, ProtectedDevicePaths: protected}
	switch command {
	case "prepare":
		preview, err := campaignstaging.Prepare(ctx, value("directory"), config, opener)
		if err != nil {
			return fail(err)
		}
		return emit(preview.CanonicalJSON())
	case "execute":
		data, err := readJSON(value("approval"))
		if err != nil {
			return fail(err)
		}
		approval, err := campaignstaging.ParseApproval(data)
		if err != nil {
			return fail(err)
		}
		report, err := campaignstaging.Execute(ctx, value("directory"), config, approval, opener)
		if err != nil {
			return fail(err)
		}
		return emit(report.CanonicalJSON())
	case "verify":
		report, err := campaignstaging.Verify(ctx, config, opener)
		if err != nil {
			return fail(err)
		}
		return emit(report.CanonicalJSON())
	}
	return 2
}

func storePath(path string) bool {
	return strings.HasPrefix(path, "/nix/store/") && filepath.Clean(path) == path && !strings.ContainsAny(path, "\x00\n\r")
}

func loadConfiguration(path string) (configuration, error) {
	var config configuration
	if !storePath(path) {
		return config, errors.New("generic build has no linker-fixed candidate configuration")
	}
	data, err := readJSON(path)
	if err != nil {
		return config, fmt.Errorf("read configured candidate: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return config, err
	}
	canonical, err := json.Marshal(config)
	if err != nil || !bytes.Equal(bytes.TrimSuffix(data, []byte{'\n'}), canonical) {
		return config, errors.New("candidate configuration is not canonical JSON")
	}
	if config.SchemaVersion != "kaiba.provisioning.rpi5-stable-campaign-staging-configuration/v1alpha1" || !storePath(config.StagingPlanPath) {
		return config, errors.New("candidate configuration requires the fixed schema and immutable plan")
	}
	if config.Leg != campaignmedia.LegMalakSD && config.Leg != campaignmedia.LegPiLocalNVMe {
		return config, errors.New("candidate leg is unsupported")
	}
	if len(config.PayloadPaths) == 0 {
		return config, errors.New("candidate has no immutable payloads")
	}
	for _, path := range config.PayloadPaths {
		if !storePath(path) {
			return config, errors.New("candidate payload is outside the immutable store")
		}
	}
	return config, nil
}

func loadInputs(fixed configuration, requirementsPath, sdPath, nvmePath string) (campaignstaging.Config, error) {
	config := campaignstaging.Config{Leg: fixed.Leg, Payloads: fixed.PayloadPaths}
	data, err := readJSON(fixed.StagingPlanPath)
	if err != nil {
		return config, err
	}
	config.Plan, err = campaignmedia.ParseStagingPlan(data)
	if err != nil {
		return config, err
	}
	data, err = readJSON(requirementsPath)
	if err != nil {
		return config, err
	}
	config.Requirements, err = campaignmedia.ParseRecoveryBackupRequirementsV1Alpha2(data)
	if err != nil {
		return config, err
	}
	for _, path := range []string{sdPath, nvmePath} {
		data, err := readJSON(path)
		if err != nil {
			return config, err
		}
		envelope, err := campaignmedia.ParseInitialGPTRecoveryEnvelopeV1Alpha2(data)
		if err != nil {
			return config, err
		}
		config.Envelopes = append(config.Envelopes, envelope)
	}
	return config, config.Validate()
}

// Pin every directory and the final inode without following symlinks; inspect
// the inode before giving a FIFO or device driver a readable open.
func readJSON(path string) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, errors.New("JSON path must be canonical and absolute")
	}
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(filepath.Dir(path), "/"), "/") {
		if part == "" {
			continue
		}
		next, err := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		syscall.Close(fd)
		if err != nil {
			return nil, err
		}
		fd = next
	}
	defer syscall.Close(fd)
	const oPath = 0x200000
	pinFD, err := syscall.Openat(fd, filepath.Base(path), oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	pin := os.NewFile(uintptr(pinFD), path)
	defer pin.Close()
	info, err := pin.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maximumJSONBytes {
		return nil, errors.New("JSON input must be a bounded nonempty regular file")
	}
	f, err := os.Open(fmt.Sprintf("/proc/self/fd/%d", pinFD))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maximumJSONBytes+1))
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil {
		return nil, err
	}
	initialStat := info.Sys().(*syscall.Stat_t)
	finalStat := after.Sys().(*syscall.Stat_t)
	if len(data) != int(info.Size()) || !os.SameFile(info, after) || initialStat.Mtim != finalStat.Mtim || initialStat.Ctim != finalStat.Ctim || after.Size() != info.Size() {
		return nil, errors.New("JSON input changed during the read")
	}
	return data, nil
}
