//go:build linux

// kaiba-rpi5-stable-campaign-packet verifies public regular-file inputs for
// runs 1 and 2. It emits preparation data only and never opens device bytes.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaignmedia"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaignpacket"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stablecampaign"
)

const maximumJSONBytes = 1024 * 1024
const maximumSourceBytes = 16 * 1024 * 1024 * 1024

var contractNames = []string{"campaign-plan", "artifact-set", "run-1-materialization", "run-2-materialization", "staging-plan", "requirements", "sd-envelope", "nvme-envelope"}
var payloadNames = []string{"boot-filesystem", "root-data", "root-hash", "release-filesystem"}

type singleValue struct {
	value string
	set   bool
	path  bool
}

func (value *singleValue) String() string { return value.value }
func (value *singleValue) Set(candidate string) error {
	if value.set {
		return errors.New("each option must be supplied exactly once")
	}
	if value.path {
		if err := validPath(candidate); err != nil {
			return err
		}
	}
	value.value, value.set = candidate, true
	return nil
}

type namedPaths map[string]string

func (paths namedPaths) String() string { return "NAME=ABSOLUTE_PATH" }
func (paths namedPaths) Set(candidate string) error {
	name, path, ok := strings.Cut(candidate, "=")
	if !ok || name == "" {
		return errors.New("named input must be NAME=ABSOLUTE_PATH")
	}
	if _, exists := paths[name]; exists {
		return fmt.Errorf("input name %q was supplied more than once", name)
	}
	if err := validPath(path); err != nil {
		return err
	}
	paths[name] = path
	return nil
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("kaiba-rpi5-stable-campaign-packet", flag.ContinueOnError)
	flags.SetOutput(stderr)
	paths := make(map[string]*singleValue)
	for _, name := range append(append([]string(nil), contractNames...), payloadNames...) {
		paths[name] = &singleValue{path: true}
		flags.Var(paths[name], name, "required canonical absolute regular-file path")
	}
	var revision singleValue
	publicPaths, targetPaths := namedPaths{}, namedPaths{}
	flags.Var(&revision, "source-revision", "asserted complete lowercase 40-character source SHA; provenance remains unverified")
	flags.Var(publicPaths, "public-input", "NAME=ABSOLUTE_PATH; repeat for all 27 plan inputs")
	flags.Var(targetPaths, "byte-mutation-target", "TARGET=ABSOLUTE_PATH; repeat for all 10 plan targets")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: kaiba-rpi5-stable-campaign-packet --source-revision SHA [required contract and payload paths] --public-input NAME=PATH ... --byte-mutation-target TARGET=PATH ...")
		fmt.Fprintln(stderr, "Verifies public regular files for runs 1 and 2; emits a preparation-only packet on stdout.")
		fmt.Fprintln(stderr, "No signing, device access, staging authorization, hardware observation, or claim closure.")
		flags.PrintDefaults()
	}
	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 || !revision.set {
		flags.Usage()
		return 2
	}
	for _, name := range append(append([]string(nil), contractNames...), payloadNames...) {
		if !paths[name].set {
			fmt.Fprintf(stderr, "packet: --%s is required\n", name)
			return 2
		}
	}
	if len(publicPaths) != 27 || len(targetPaths) != 10 {
		fmt.Fprintln(stderr, "packet: all 27 public inputs and 10 byte-mutation targets are required")
		return 2
	}
	encoded, err := construct(revision.value, paths, publicPaths, targetPaths)
	if err != nil {
		fmt.Fprintf(stderr, "packet: %v\n", err)
		return 1
	}
	encoded = append(encoded, '\n')
	n, err := stdout.Write(encoded)
	if err == nil && n != len(encoded) {
		err = io.ErrShortWrite
	}
	if err != nil {
		fmt.Fprintf(stderr, "packet: write stdout: %v\n", err)
		return 1
	}
	return 0
}

func construct(revision string, paths map[string]*singleValue, publicPaths, targetPaths namedPaths) ([]byte, error) {
	var opened []*pinnedFile
	defer func() {
		for _, input := range opened {
			_ = input.file.Close()
		}
	}()
	open := func(path string, limit int64) (*pinnedFile, error) {
		input, err := openRegular(path, limit)
		if err == nil {
			opened = append(opened, input)
		}
		return input, err
	}
	contracts := make(map[string][]byte, len(contractNames))
	for _, name := range contractNames {
		input, err := open(paths[name].value, maximumJSONBytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		encoded, err := io.ReadAll(io.LimitReader(input.file, maximumJSONBytes+1))
		if err != nil {
			return nil, err
		}
		if int64(len(encoded)) != input.identity.size {
			return nil, fmt.Errorf("%s changed while being read", name)
		}
		contracts[name] = encoded
	}
	input, err := parseContracts(contracts)
	if err != nil {
		return nil, err
	}
	input.SourceRevision = revision
	input.PublicSources = stablecampaign.PublicArtifactSources{PublicInputs: map[string]stablecampaign.PublicArtifactSource{}, ByteMutationTargets: map[string]stablecampaign.PublicArtifactSource{}}
	seen := make(map[[2]uint64]string)
	for _, group := range []struct {
		paths       namedPaths
		destination map[string]stablecampaign.PublicArtifactSource
	}{
		{publicPaths, input.PublicSources.PublicInputs}, {targetPaths, input.PublicSources.ByteMutationTargets},
	} {
		names := make([]string, 0, len(group.paths))
		for name := range group.paths {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			file, err := open(group.paths[name], maximumSourceBytes)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			key := [2]uint64{file.identity.device, file.identity.inode}
			if previous, exists := seen[key]; exists {
				return nil, fmt.Errorf("public source %q reuses the opened inode of %q", name, previous)
			}
			seen[key] = name
			group.destination[name] = stablecampaign.PublicArtifactSource{SizeBytes: uint64(file.identity.size), ReaderAt: file.file}
		}
	}
	input.Payloads = map[campaignmedia.PartitionRole]stablecampaign.PublicArtifactSource{}
	seenPayloads := make(map[[2]uint64]string)
	for _, name := range payloadNames {
		file, err := open(paths[name].value, maximumSourceBytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		key := [2]uint64{file.identity.device, file.identity.inode}
		if previous, exists := seenPayloads[key]; exists {
			return nil, fmt.Errorf("payload %q reuses the opened inode of %q", name, previous)
		}
		seenPayloads[key] = name
		input.Payloads[campaignmedia.PartitionRole(name)] = stablecampaign.PublicArtifactSource{SizeBytes: uint64(file.identity.size), ReaderAt: file.file}
	}
	report, err := campaignpacket.Prepare(input)
	if err != nil {
		return nil, err
	}
	for _, file := range opened {
		if err := file.revalidate(); err != nil {
			return nil, err
		}
	}
	return report.CanonicalJSON()
}

func parseContracts(encoded map[string][]byte) (campaignpacket.Input, error) {
	var result campaignpacket.Input
	var err error
	result.Plan, err = stablecampaign.ParsePlan(encoded["campaign-plan"])
	if err != nil {
		return result, fmt.Errorf("campaign plan: %w", err)
	}
	result.ArtifactSet, err = campaignmedia.ParseArtifactSet(encoded["artifact-set"])
	if err != nil {
		return result, fmt.Errorf("artifact set: %w", err)
	}
	result.StagingPlan, err = campaignmedia.ParseStagingPlan(encoded["staging-plan"])
	if err != nil {
		return result, fmt.Errorf("staging plan: %w", err)
	}
	result.Requirements, err = campaignmedia.ParseRecoveryBackupRequirementsV1Alpha2(encoded["requirements"])
	if err != nil {
		return result, fmt.Errorf("requirements: %w", err)
	}
	for _, name := range []string{"sd-envelope", "nvme-envelope"} {
		envelope, err := campaignmedia.ParseInitialGPTRecoveryEnvelopeV1Alpha2(encoded[name])
		if err != nil {
			return result, fmt.Errorf("%s: %w", name, err)
		}
		result.Envelopes = append(result.Envelopes, envelope)
	}
	for _, name := range []string{"run-1-materialization", "run-2-materialization"} {
		materialization, err := campaignmedia.ParseRunArtifactMaterialization(encoded[name])
		if err != nil {
			return result, fmt.Errorf("%s: %w", name, err)
		}
		result.Materializations = append(result.Materializations, materialization)
	}
	return result, nil
}

type fileIdentity struct {
	device, inode, links uint64
	size                 int64
	mode                 uint32
	mtime, ctime         syscall.Timespec
}
type pinnedFile struct {
	file     *os.File
	identity fileIdentity
	path     string
}

func validPath(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || !utf8.ValidString(path) ||
		strings.ContainsAny(path, "\x00\r\n") || path == "/dev" || strings.HasPrefix(path, "/dev/") {
		return errors.New("input must be a canonical absolute regular-file path outside /dev")
	}
	return nil
}

func identityOf(fd int) (fileIdentity, error) {
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return fileIdentity{}, err
	}
	return fileIdentity{device: uint64(stat.Dev), inode: stat.Ino, links: uint64(stat.Nlink), size: stat.Size, mode: stat.Mode, mtime: stat.Mtim, ctime: stat.Ctim}, nil
}

func openRegular(path string, limit int64) (*pinnedFile, error) {
	if err := validPath(path); err != nil {
		return nil, err
	}
	// Walk every parent without symlinks, then inspect an O_PATH descriptor.
	// No readable descriptor exists until fstat has rejected special files.
	const oPath = 0x200000
	fd, err := syscall.Open("/", oPath|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	components := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for index, component := range components {
		flags := oPath | syscall.O_CLOEXEC | syscall.O_NOFOLLOW
		if index < len(components)-1 {
			flags |= syscall.O_DIRECTORY
		}
		next, openErr := syscall.Openat(fd, component, flags, 0)
		_ = syscall.Close(fd)
		if openErr != nil {
			return nil, openErr
		}
		fd = next
	}
	defer syscall.Close(fd)
	before, err := identityOf(fd)
	if err != nil {
		return nil, err
	}
	if before.mode&syscall.S_IFMT != syscall.S_IFREG || before.links != 1 || before.size <= 0 || before.size > limit {
		return nil, fmt.Errorf("input must be a singly linked nonempty regular file no larger than %d bytes", limit)
	}
	file, err := os.Open(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return nil, err
	}
	result := &pinnedFile{file: file, identity: before, path: path}
	if err := result.revalidate(); err != nil {
		_ = file.Close()
		return nil, err
	}
	return result, nil
}

func (file *pinnedFile) revalidate() error {
	current, err := identityOf(int(file.file.Fd()))
	if err != nil {
		return err
	}
	if current != file.identity {
		return fmt.Errorf("input %q changed while the packet was checked", file.path)
	}
	return nil
}
