//go:build linux

// kaiba-rpi5-stable-campaign-recovery-requirements binds previously captured
// v1alpha2 GPT envelopes to an independently supplied staging plan. It reads
// bounded regular JSON files and emits a descriptive catalog on stdout; it
// never reads device bytes, captures recovery bytes, or grants write authority.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaignmedia"
)

const maximumInputBytes = 1024 * 1024

type singlePath struct {
	value string
	set   bool
}

func (path *singlePath) String() string { return path.value }

func (path *singlePath) Set(value string) error {
	if path.set {
		return errors.New("each input may be supplied exactly once")
	}
	if !filepath.IsAbs(value) || filepath.Clean(value) != value {
		return errors.New("input must be a canonical absolute regular-file path")
	}
	path.value, path.set = value, true
	return nil
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("kaiba-rpi5-stable-campaign-recovery-requirements", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var planPath, sdPath, nvmePath singlePath
	flags.Var(&planPath, "staging-plan", "canonical staging-plan JSON file")
	flags.Var(&sdPath, "sd-envelope", "canonical v1alpha2 development-SD capture JSON file")
	flags.Var(&nvmePath, "nvme-envelope", "canonical v1alpha2 Pi-local NVMe capture JSON file")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: kaiba-rpi5-stable-campaign-recovery-requirements --staging-plan PATH --sd-envelope PATH --nvme-envelope PATH")
		fmt.Fprintln(stderr, "Reads regular JSON files; emits a descriptive v1alpha2 recovery catalog on stdout.")
		fmt.Fprintln(stderr, "No recovery-byte capture, signing, device access, or staging authorization.")
	}
	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 || !planPath.set || !sdPath.set || !nvmePath.set {
		flags.Usage()
		return 2
	}
	encoded, err := construct(planPath.value, sdPath.value, nvmePath.value)
	if err != nil {
		fmt.Fprintf(stderr, "recovery requirements: %v\n", err)
		return 1
	}
	encoded = append(encoded, '\n')
	n, err := stdout.Write(encoded)
	if err == nil && n != len(encoded) {
		err = io.ErrShortWrite
	}
	if err != nil {
		fmt.Fprintf(stderr, "recovery requirements: write stdout: %v\n", err)
		return 1
	}
	return 0
}

func construct(planPath, sdPath, nvmePath string) ([]byte, error) {
	planJSON, err := readInput(planPath)
	if err != nil {
		return nil, fmt.Errorf("staging plan: %w", err)
	}
	plan, err := campaignmedia.ParseStagingPlan(planJSON)
	if err != nil {
		return nil, err
	}
	envelopes := make([]campaignmedia.InitialGPTRecoveryEnvelopeV1Alpha2, 2)
	for index, path := range []string{sdPath, nvmePath} {
		encoded, err := readInput(path)
		if err != nil {
			return nil, fmt.Errorf("envelope %d: %w", index+1, err)
		}
		envelopes[index], err = campaignmedia.ParseInitialGPTRecoveryEnvelopeV1Alpha2(encoded)
		if err != nil {
			return nil, fmt.Errorf("envelope %d: %w", index+1, err)
		}
	}
	requirements, err := campaignmedia.NewRecoveryBackupRequirementsV1Alpha2(plan, envelopes)
	if err != nil {
		return nil, err
	}
	return requirements.CanonicalJSON()
}

func readInput(path string) ([]byte, error) {
	// Pin metadata before acquiring any readable descriptor. O_PATH avoids
	// opening a substituted device or FIFO for I/O; a symlink remains a
	// symlink and is rejected by fstat. /proc then reopens the pinned inode.
	const oPath = 0x200000
	fd, err := syscall.Open(path, oPath|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	pinned := os.NewFile(uintptr(fd), path)
	defer pinned.Close()
	before, err := pinned.Stat()
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > maximumInputBytes {
		return nil, errors.New("input must be a nonempty regular file no larger than 1 MiB")
	}
	file, err := os.Open(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	encoded, err := io.ReadAll(io.LimitReader(file, maximumInputBytes+1))
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	beforeStat := before.Sys().(*syscall.Stat_t)
	afterStat := after.Sys().(*syscall.Stat_t)
	if int64(len(encoded)) != before.Size() || before.Size() != after.Size() ||
		beforeStat.Mtim != afterStat.Mtim || beforeStat.Ctim != afterStat.Ctim ||
		beforeStat.Mode != afterStat.Mode || beforeStat.Nlink != afterStat.Nlink {
		return nil, errors.New("input changed while being read")
	}
	return encoded, nil
}
