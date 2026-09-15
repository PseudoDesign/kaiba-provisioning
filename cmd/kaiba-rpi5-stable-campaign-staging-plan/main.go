//go:build linux

// This command prepares descriptive staging-plan JSON from public regular
// files. It opens no devices and grants no signing, staging or recovery authority.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaignmedia"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stablecampaign"
)

const maximumJSONBytes = 1024*1024 + 1

type preparation struct {
	campaignPath, artifactPath string
	guids                      campaignmedia.StagingGUIDs
	payloadPaths               map[campaignmedia.PartitionRole]string
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

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, prepareFromFiles)) }

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: kaiba-rpi5-stable-campaign-staging-plan --campaign-plan ABS --artifact-set ABS \\")
	fmt.Fprintln(w, "  --sd-disk-guid GUID --nvme-disk-guid GUID --boot-partition-guid GUID \\")
	fmt.Fprintln(w, "  --root-data-partition-guid GUID --root-hash-partition-guid GUID --release-partition-guid GUID \\")
	fmt.Fprintln(w, "  --boot-filesystem ABS --root-data ABS --root-hash ABS --release-filesystem ABS")
	fmt.Fprintln(w, "Emits canonical descriptive JSON; initial recovery binding and destructive staging readiness remain false.")
}

func run(args []string, stdout, stderr io.Writer, prepare func(preparation) ([]byte, error)) int {
	flags := flag.NewFlagSet("staging-plan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() { usage(stderr) }
	names := []string{
		"campaign-plan", "artifact-set", "sd-disk-guid", "nvme-disk-guid", "boot-partition-guid",
		"root-data-partition-guid", "root-hash-partition-guid", "release-partition-guid",
		"boot-filesystem", "root-data", "root-hash", "release-filesystem",
	}
	values := make(map[string]*singleValue, len(names))
	for _, name := range names {
		value := &singleValue{}
		values[name] = value
		flags.Var(value, name, "required explicit value")
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		usage(stderr)
		return 2
	}
	for _, name := range names {
		if !values[name].set || values[name].value == "" {
			fmt.Fprintf(stderr, "--%s is required exactly once\n", name)
			return 2
		}
	}
	value := func(name string) string { return values[name].value }
	request := preparation{
		campaignPath: value("campaign-plan"), artifactPath: value("artifact-set"),
		guids: campaignmedia.StagingGUIDs{
			SDDisk: value("sd-disk-guid"), NVMeDisk: value("nvme-disk-guid"),
			Boot: value("boot-partition-guid"), RootData: value("root-data-partition-guid"),
			RootHash: value("root-hash-partition-guid"), Release: value("release-partition-guid"),
		},
		payloadPaths: map[campaignmedia.PartitionRole]string{
			campaignmedia.PartitionBootFilesystem:    value("boot-filesystem"),
			campaignmedia.PartitionRootData:          value("root-data"),
			campaignmedia.PartitionRootHash:          value("root-hash"),
			campaignmedia.PartitionReleaseFilesystem: value("release-filesystem"),
		},
	}
	if prepare == nil {
		fmt.Fprintln(stderr, "staging plan: preparation is unavailable")
		return 1
	}
	encoded, err := prepare(request)
	if err != nil {
		fmt.Fprintf(stderr, "staging plan: %v\n", err)
		return 1
	}
	encoded = append(encoded, '\n')
	for len(encoded) > 0 {
		n, err := stdout.Write(encoded)
		if err != nil || n <= 0 || n > len(encoded) {
			if err == nil {
				err = io.ErrShortWrite
			}
			fmt.Fprintf(stderr, "staging plan output: %v\n", err)
			return 1
		}
		encoded = encoded[n:]
	}
	return 0
}

type fileIdentity struct {
	device, inode uint64
	size          int64
	mode          uint32
	mtime, ctime  syscall.Timespec
}

type publicFile struct {
	path     string
	file     *os.File
	identity fileIdentity
	maximum  uint64
}

func prepareFromFiles(request preparation) ([]byte, error) {
	type input struct {
		name, path string
		maximum    uint64
	}
	inputs := []input{
		{"campaign-plan", request.campaignPath, maximumJSONBytes},
		{"artifact-set", request.artifactPath, maximumJSONBytes},
		{string(campaignmedia.PartitionBootFilesystem), request.payloadPaths[campaignmedia.PartitionBootFilesystem], campaignmedia.MalakSDBootCapacityBytes},
		{string(campaignmedia.PartitionRootData), request.payloadPaths[campaignmedia.PartitionRootData], campaignmedia.MalakSDRootDataCapacityBytes},
		{string(campaignmedia.PartitionRootHash), request.payloadPaths[campaignmedia.PartitionRootHash], campaignmedia.MalakSDRootHashCapacityBytes},
		{string(campaignmedia.PartitionReleaseFilesystem), request.payloadPaths[campaignmedia.PartitionReleaseFilesystem], campaignmedia.PiLocalNVMeReleaseCapacityBytes},
	}
	opened := make([]*publicFile, 0, len(inputs))
	defer func() {
		for _, file := range opened {
			_ = file.file.Close()
		}
	}()
	seen := make(map[[2]uint64]string)
	for _, input := range inputs {
		file, err := openPublicFile(input.path, input.maximum)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", input.name, err)
		}
		opened = append(opened, file)
		identity := [2]uint64{file.identity.device, file.identity.inode}
		if previous, exists := seen[identity]; exists {
			return nil, fmt.Errorf("%s reuses the same opened file identity as %s", input.name, previous)
		}
		seen[identity] = input.name
	}
	campaignJSON, err := readJSON(opened[0])
	if err != nil {
		return nil, err
	}
	plan, err := stablecampaign.ParsePlan(campaignJSON)
	if err != nil {
		return nil, err
	}
	artifactJSON, err := readJSON(opened[1])
	if err != nil {
		return nil, err
	}
	artifacts, err := campaignmedia.ParseArtifactSet(artifactJSON)
	if err != nil {
		return nil, err
	}
	if artifacts.Provenance.CampaignPlan.SHA256 != bundle.Sum(campaignJSON) ||
		artifacts.Provenance.CampaignPlan.SizeBytes != uint64(len(campaignJSON)) {
		return nil, errors.New("artifact-set provenance does not bind the actual campaign-plan file bytes")
	}
	sources := make(map[campaignmedia.PartitionRole]campaignmedia.PayloadSource, 4)
	for index, file := range opened[2:] {
		sources[campaignmedia.PartitionRole(inputs[index+2].name)] = campaignmedia.PayloadSource{Reader: file.file, SizeBytes: uint64(file.identity.size)}
	}
	prepared, err := campaignmedia.PrepareStagingPlan(plan, artifacts, request.guids, sources)
	if err != nil {
		return nil, err
	}
	for _, file := range opened {
		if err := file.revalidate(); err != nil {
			return nil, err
		}
	}
	return prepared.CanonicalJSON()
}

func readJSON(file *publicFile) ([]byte, error) {
	encoded, err := io.ReadAll(io.LimitReader(file.file, maximumJSONBytes+1))
	if err != nil || int64(len(encoded)) != file.identity.size || len(encoded) > maximumJSONBytes {
		return nil, errors.New("public JSON changed or exceeds its size bound")
	}
	if err := file.revalidate(); err != nil {
		return nil, err
	}
	return encoded, nil
}

func statIdentity(file *os.File) (fileIdentity, error) {
	var st syscall.Stat_t
	if err := syscall.Fstat(int(file.Fd()), &st); err != nil {
		return fileIdentity{}, err
	}
	return fileIdentity{device: uint64(st.Dev), inode: st.Ino, size: st.Size, mode: st.Mode, mtime: st.Mtim, ctime: st.Ctim}, nil
}

func (file *publicFile) revalidate() error {
	current, err := statIdentity(file.file)
	if err != nil || current != file.identity {
		return errors.New("public input changed while preparing the staging plan")
	}
	reopened, err := openPublicFile(file.path, file.maximum)
	if err != nil {
		return fmt.Errorf("reopen public input: %w", err)
	}
	defer reopened.file.Close()
	if reopened.identity != file.identity {
		return errors.New("public input path changed while preparing the staging plan")
	}
	return nil
}

func openPublicFile(path string, maximum uint64) (*publicFile, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" ||
		strings.ContainsAny(path, "\x00\n\r") || !utf8.ValidString(path) ||
		path == "/dev" || strings.HasPrefix(path, "/dev/") {
		return nil, errors.New("input must be an absolute clean public-file path outside /dev")
	}
	// O_PATH pins identities without opening a device or FIFO for I/O. Follow
	// no symlinks in any component, then reopen only the pinned regular inode.
	const oPath = 0x200000
	fd, err := syscall.Open("/", oPath|syscall.O_CLOEXEC|syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	components := strings.Split(path[1:], "/")
	for index, component := range components {
		flags := oPath | syscall.O_CLOEXEC | syscall.O_NOFOLLOW
		if index < len(components)-1 {
			flags |= syscall.O_DIRECTORY
		}
		next, openErr := syscall.Openat(fd, component, flags, 0)
		_ = syscall.Close(fd)
		if openErr != nil {
			return nil, fmt.Errorf("open public path without symlinks: %w", openErr)
		}
		fd = next
	}
	pinned := os.NewFile(uintptr(fd), path)
	defer pinned.Close()
	identity, err := statIdentity(pinned)
	if err != nil || identity.mode&syscall.S_IFMT != syscall.S_IFREG {
		return nil, errors.New("input must be a regular non-symlink file")
	}
	if identity.size <= 0 || uint64(identity.size) > maximum {
		return nil, fmt.Errorf("input size must be 1 through %d bytes", maximum)
	}
	file, err := os.OpenFile(fmt.Sprintf("/proc/self/fd/%d", fd), os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	opened, err := statIdentity(file)
	if err != nil || opened != identity {
		_ = file.Close()
		return nil, errors.New("public input changed while opening")
	}
	return &publicFile{path: path, file: file, identity: identity, maximum: maximum}, nil
}
