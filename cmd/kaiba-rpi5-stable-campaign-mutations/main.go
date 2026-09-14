// kaiba-rpi5-stable-campaign-mutations prepares twenty public manifest inputs.
// It contains no signer, key generation, media access, or execution authority.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaignprepare"
)

const (
	exitOK      = 0
	exitInvalid = 1
	exitUsage   = 2
)

type singlePath struct {
	name, value string
	set         bool
}

func (value *singlePath) String() string { return value.value }
func (value *singlePath) Set(candidate string) error {
	if value.set {
		return fmt.Errorf("--%s may be specified exactly once", value.name)
	}
	value.value = candidate
	value.set = true
	return nil
}

type mutationBuilder func(campaignprepare.MutationInputs) (map[string][]byte, error)
type sourceIdentity struct {
	device, inode uint64
	size          int64
	mode          uint32
	mtime, ctime  syscall.Timespec
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
func run(arguments []string, stdout, stderr io.Writer) int {
	return runWithBuilder(arguments, stdout, stderr, campaignprepare.BuildMutations)
}
func runWithBuilder(arguments []string, stdout, stderr io.Writer, build mutationBuilder) int {
	flags := flag.NewFlagSet("kaiba-rpi5-stable-campaign-mutations", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: kaiba-rpi5-stable-campaign-mutations --policy ABSOLUTE_FILE --root-public-key ABSOLUTE_FILE --positive-manifest ABSOLUTE_FILE --replacement-manifest ABSOLUTE_FILE --revoked-manifest ABSOLUTE_FILE --output ABSOLUTE_NEW_DIRECTORY")
	}
	paths := make([]*singlePath, 0, 6)
	for _, name := range []string{"policy", "root-public-key", "positive-manifest", "replacement-manifest", "revoked-manifest", "output"} {
		value := &singlePath{name: name}
		paths = append(paths, value)
		flags.Var(value, name, "required clean absolute path")
	}
	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if flags.NArg() != 0 {
		flags.Usage()
		return exitUsage
	}
	for _, path := range paths {
		if !path.set || path.value == "" {
			flags.Usage()
			return exitUsage
		}
		if err := validateAbsolutePath(path.value); err != nil {
			fmt.Fprintf(stderr, "--%s: %v\n", path.name, err)
			return exitUsage
		}
	}
	output := paths[5].value
	if _, err := os.Lstat(output); err == nil {
		fmt.Fprintln(stderr, "mutation output already exists")
		return exitInvalid
	} else if !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(stderr, err)
		return exitInvalid
	}
	data := make([][]byte, 5)
	identities := make(map[[2]uint64]string, 5)
	for index, path := range paths[:5] {
		maximum := campaignprepare.MutationMetadataMaxBytes
		if path.name == "root-public-key" {
			maximum = campaignprepare.MutationRootPublicMaxBytes
		}
		contents, identity, err := readPublicInput(path.value, maximum)
		if err != nil {
			fmt.Fprintf(stderr, "--%s: %v\n", path.name, err)
			return exitInvalid
		}
		key := [2]uint64{identity.device, identity.inode}
		if previous, exists := identities[key]; exists {
			fmt.Fprintf(stderr, "--%s aliases --%s; inputs must be independently supplied files\n", path.name, previous)
			return exitInvalid
		}
		identities[key] = path.name
		data[index] = contents
	}
	outputs, err := build(campaignprepare.MutationInputs{PolicyJSON: data[0], RootPublicPEM: data[1], PositiveManifestJSON: data[2], ReplacementManifestJSON: data[3], RevokedManifestJSON: data[4]})
	if err != nil {
		fmt.Fprintf(stderr, "prepare campaign mutations: %v\n", err)
		return exitInvalid
	}
	if err := publishDirectory(output, outputs); err != nil {
		fmt.Fprintf(stderr, "publish campaign mutations: %v\n", err)
		return exitInvalid
	}
	if err := json.NewEncoder(stdout).Encode(struct {
		Status           string `json:"status"`
		FileCount        int    `json:"file_count"`
		SigningPerformed bool   `json:"signing_performed"`
		HardwareObserved bool   `json:"hardware_observed"`
	}{Status: "prepared", FileCount: len(outputs)}); err != nil {
		fmt.Fprintln(stderr, err)
		return exitInvalid
	}
	return exitOK
}

func validateAbsolutePath(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || strings.ContainsRune(path, 0) || path == "/dev" || strings.HasPrefix(path, "/dev/") {
		return errors.New("path must be clean, absolute, non-root and outside /dev")
	}
	return nil
}

// openAbsolute walks every parent with O_NOFOLLOW. A final file is pinned
// with O_PATH, without opening any device or FIFO for I/O before type checks.
func openAbsolute(path string, directory bool) (*os.File, error) {
	if err := validateAbsolutePath(path); err != nil {
		return nil, err
	}
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	current := os.NewFile(uintptr(fd), "/")
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for index, name := range parts {
		flags := syscall.O_RDONLY | syscall.O_CLOEXEC | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
		if index < len(parts)-1 || directory {
			flags |= syscall.O_DIRECTORY
		} else {
			flags |= 0x200000 // Linux O_PATH: inspect the node before any I/O open.
		}
		nextFD, err := syscall.Openat(int(current.Fd()), name, flags, 0)
		if err != nil {
			current.Close()
			return nil, err
		}
		next := os.NewFile(uintptr(nextFD), name)
		if err := current.Close(); err != nil {
			next.Close()
			return nil, err
		}
		current = next
	}
	return current, nil
}
func identityOf(file *os.File) (sourceIdentity, error) {
	var stat syscall.Stat_t
	if err := syscall.Fstat(int(file.Fd()), &stat); err != nil {
		return sourceIdentity{}, err
	}
	return sourceIdentity{device: uint64(stat.Dev), inode: uint64(stat.Ino), size: stat.Size, mode: stat.Mode, mtime: stat.Mtim, ctime: stat.Ctim}, nil
}
func readPublicInput(path string, maximum int) ([]byte, sourceIdentity, error) {
	file, err := openAbsolute(path, false)
	if err != nil {
		return nil, sourceIdentity{}, err
	}
	defer file.Close()
	before, err := identityOf(file)
	if err != nil {
		return nil, sourceIdentity{}, err
	}
	if before.mode&syscall.S_IFMT != syscall.S_IFREG || before.size <= 0 || before.size > int64(maximum) {
		return nil, sourceIdentity{}, fmt.Errorf("input must be a regular file of 1 through %d bytes", maximum)
	}
	// Reopen only the process-owned descriptor after the pinned node is known
	// to be regular. O_NOFOLLOW is intentionally absent for this fixed procfs
	// descriptor link; caller-supplied pathnames are never reopened for I/O.
	reader, err := os.OpenFile("/proc/self/fd/"+strconv.FormatUint(uint64(file.Fd()), 10), os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, sourceIdentity{}, err
	}
	defer reader.Close()
	opened, err := identityOf(reader)
	if err != nil || opened != before {
		return nil, sourceIdentity{}, errors.New("public input changed while opening for reading")
	}
	encoded, err := io.ReadAll(io.LimitReader(reader, int64(maximum)+1))
	if err != nil {
		return nil, sourceIdentity{}, err
	}
	after, err := identityOf(reader)
	if err != nil {
		return nil, sourceIdentity{}, err
	}
	if before != after || int64(len(encoded)) != before.size {
		return nil, sourceIdentity{}, errors.New("public input changed while reading")
	}
	return encoded, before, nil
}

func publishDirectory(path string, files map[string][]byte) error {
	if len(files) != 20 {
		return errors.New("mutation output must contain exactly twenty files")
	}
	for name, contents := range files {
		if filepath.Base(name) != name || name == "." || !strings.HasSuffix(name, ".json") || len(contents) == 0 || len(contents) > campaignprepare.MutationMetadataMaxBytes {
			return errors.New("mutation output contains an invalid bounded filename or document")
		}
	}
	parentPath := filepath.Dir(path)
	parent, err := openAbsolute(parentPath, true)
	if err != nil {
		return fmt.Errorf("output parent: %w", err)
	}
	defer parent.Close()
	parentBefore, err := identityOf(parent)
	if err != nil {
		return err
	}
	temporary, err := os.MkdirTemp(parentPath, ".kaiba-campaign-mutations-")
	if err != nil {
		return err
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.Chmod(temporary, 0700)
			_ = os.RemoveAll(temporary)
		}
	}()
	currentParent, err := openAbsolute(parentPath, true)
	if err != nil {
		return err
	}
	parentAfter, statErr := identityOf(currentParent)
	currentParent.Close()
	if statErr != nil || parentBefore.device != parentAfter.device || parentBefore.inode != parentAfter.inode {
		return errors.New("output parent changed during preparation")
	}
	stage, err := openAbsolute(temporary, true)
	if err != nil {
		return err
	}
	defer stage.Close()
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fd, err := syscall.Openat(int(stage.Fd()), name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
		if err != nil {
			return err
		}
		file := os.NewFile(uintptr(fd), name)
		if _, err := io.Copy(file, bytes.NewReader(files[name])); err != nil {
			file.Close()
			return err
		}
		if err := file.Chmod(0444); err != nil {
			file.Close()
			return err
		}
		if err := file.Sync(); err != nil {
			file.Close()
			return err
		}
		if err := file.Close(); err != nil {
			return err
		}
	}
	if err := stage.Chmod(0555); err != nil {
		return err
	}
	if err := stage.Sync(); err != nil {
		return err
	}
	if err := renameDirectoryNoReplace(int(parent.Fd()), filepath.Base(temporary), filepath.Base(path)); err != nil {
		return err
	}
	keep = true
	return parent.Sync()
}
