//go:build linux

// kaiba-rpi5-stable-campaign-sandbox rehearses recovery and staging on private
// regular-file copies. Its approval and reports are explicitly synthetic.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaignmedia"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaignsandbox"
)

type option struct {
	value string
	set   bool
	path  bool
}

func (o *option) String() string { return o.value }
func (o *option) Set(value string) error {
	if o.set || value == "" {
		return errors.New("option must be nonempty and supplied exactly once")
	}
	if o.path && (!filepath.IsAbs(value) || filepath.Clean(value) != value) {
		return errors.New("path must be absolute and canonical")
	}
	o.set, o.value = true, value
	return nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func usage(out io.Writer) {
	fmt.Fprintln(out, "Usage: kaiba-rpi5-stable-campaign-sandbox prepare|approve|execute [OPTIONS]")
	fmt.Fprintln(out, "Rehearses recovery and staging on newly created regular files; all evidence and approval are synthetic.")
	fmt.Fprintln(out, "Use COMMAND --help for its required options. No physical write authority is granted.")
}

func run(ctx context.Context, arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 1 && (arguments[0] == "--help" || arguments[0] == "-h") {
		usage(stderr)
		return 0
	}
	if len(arguments) == 0 {
		usage(stderr)
		return 2
	}
	action := arguments[0]
	flags := flag.NewFlagSet("campaign-sandbox "+action, flag.ContinueOnError)
	flags.SetOutput(stderr)
	options := map[string]*option{}
	add := func(name, help string, path bool) {
		o := &option{path: path}
		options[name] = o
		flags.Var(o, name, help)
	}
	switch action {
	case "prepare":
		for _, item := range [][2]string{
			{"directory", "new private sandbox directory"},
			{"staging-plan", "canonical campaign staging-plan JSON"},
			{"requirements", "canonical v1alpha2 recovery-requirements JSON"},
			{"sd-envelope", "independently supplied v1alpha2 SD capture JSON"},
			{"nvme-envelope", "independently supplied v1alpha2 NVMe capture JSON"},
			{"sd-image", "regular-file SD fixture; copied into sandbox"},
			{"nvme-image", "regular-file NVMe fixture; copied into sandbox"},
			{"boot-filesystem", "complete boot-filesystem source fixture"},
			{"root-data", "root-data source fixture"},
			{"root-hash", "root-hash source fixture"},
			{"release-filesystem", "release-filesystem source fixture"},
		} {
			add(item[0], item[1], true)
		}
	case "approve":
		add("preview", "canonical prepared sandbox preview JSON", true)
		add("reviewer", "synthetic reviewer identifier", false)
	case "execute":
		add("directory", "previously prepared private sandbox directory", true)
		add("approval", "canonical synthetic approval JSON", true)
	default:
		usage(stderr)
		return 2
	}
	if err := flags.Parse(arguments[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "campaign sandbox: positional arguments are not accepted")
		return 2
	}
	missing := false
	flags.VisitAll(func(f *flag.Flag) {
		if !options[f.Name].set {
			fmt.Fprintf(stderr, "campaign sandbox: --%s is required\n", f.Name)
			missing = true
		}
	})
	if missing {
		return 2
	}
	value := func(name string) string { return options[name].value }
	var encoded []byte
	var err error
	switch action {
	case "prepare":
		encoded, err = prepare(ctx, value)
	case "approve":
		var preview campaignsandbox.Preview
		preview, err = readRecord(value("preview"), campaignsandbox.ParsePreview)
		if err == nil {
			var approval campaignsandbox.Approval
			approval, err = campaignsandbox.Approve(preview, value("reviewer"))
			if err == nil {
				encoded, err = approval.CanonicalJSON()
			}
		}
	case "execute":
		var approval campaignsandbox.Approval
		approval, err = readRecord(value("approval"), campaignsandbox.ParseApproval)
		if err == nil {
			var report campaignsandbox.Report
			report, err = campaignsandbox.Execute(ctx, value("directory"), approval)
			if err == nil {
				encoded, err = report.CanonicalJSON()
			}
		}
	}
	if err == nil {
		var n int
		n, err = stdout.Write(encoded)
		if err == nil && n != len(encoded) {
			err = io.ErrShortWrite
		}
	}
	if err != nil {
		fmt.Fprintf(stderr, "campaign sandbox %s: %v\n", action, err)
		return 1
	}
	return 0
}

func prepare(ctx context.Context, value func(string) string) ([]byte, error) {
	plan, err := readRecord(value("staging-plan"), campaignmedia.ParseStagingPlan)
	if err != nil {
		return nil, fmt.Errorf("staging plan: %w", err)
	}
	requirements, err := readRecord(value("requirements"), campaignmedia.ParseRecoveryBackupRequirementsV1Alpha2)
	if err != nil {
		return nil, fmt.Errorf("requirements: %w", err)
	}
	envelopes := make([]campaignmedia.InitialGPTRecoveryEnvelopeV1Alpha2, 2)
	for index, name := range []string{"sd-envelope", "nvme-envelope"} {
		envelopes[index], err = readRecord(value(name), campaignmedia.ParseInitialGPTRecoveryEnvelopeV1Alpha2)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
	}
	preview, err := campaignsandbox.Prepare(ctx, value("directory"), campaignsandbox.Input{
		Plan: plan, Requirements: requirements, Envelopes: envelopes,
		Disks: []campaignsandbox.DiskInput{
			{Leg: campaignmedia.LegMalakSD, Path: value("sd-image")},
			{Leg: campaignmedia.LegPiLocalNVMe, Path: value("nvme-image")},
		},
		Payloads: []campaignsandbox.PayloadInput{
			{Leg: campaignmedia.LegMalakSD, Role: campaignmedia.PartitionBootFilesystem, Path: value("boot-filesystem")},
			{Leg: campaignmedia.LegMalakSD, Role: campaignmedia.PartitionRootData, Path: value("root-data")},
			{Leg: campaignmedia.LegMalakSD, Role: campaignmedia.PartitionRootHash, Path: value("root-hash")},
			{Leg: campaignmedia.LegPiLocalNVMe, Role: campaignmedia.PartitionReleaseFilesystem, Path: value("release-filesystem")},
		},
	})
	if err != nil {
		return nil, err
	}
	return preview.CanonicalJSON()
}

func readRecord[T any](path string, parse func([]byte) (T, error)) (T, error) {
	var zero T
	const oPath = 0x200000
	fd, err := syscall.Open(path, oPath|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return zero, err
	}
	pinned := os.NewFile(uintptr(fd), path)
	defer pinned.Close()
	info, err := pinned.Stat()
	if err != nil {
		return zero, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 4*1024*1024 {
		return zero, errors.New("record must be a nonempty regular file no larger than 4 MiB")
	}
	file, err := os.Open(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return zero, err
	}
	defer file.Close()
	encoded, err := io.ReadAll(io.LimitReader(file, 4*1024*1024+1))
	if err != nil {
		return zero, err
	}
	after, err := file.Stat()
	if err != nil {
		return zero, err
	}
	beforeStat, afterStat := info.Sys().(*syscall.Stat_t), after.Sys().(*syscall.Stat_t)
	if info.Size() != int64(len(encoded)) || info.Size() != after.Size() || beforeStat.Mtim != afterStat.Mtim || beforeStat.Ctim != afterStat.Ctim {
		return zero, errors.New("record changed while being read")
	}
	return parse(encoded)
}
