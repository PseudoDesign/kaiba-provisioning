// kaiba-rpi5-stable-campaign-plan constructs descriptive, path-free
// development Raspberry Pi 5 stable-verifier plan data from caller-labelled
// files. It has no signing, staging, physical-execution, or hardware authority,
// and it does not establish the provenance of those files.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/evidencefile"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stablecampaign"
)

const (
	exitOK        = 0
	exitInvalid   = 1
	exitUsage     = 2
	readChunkSize = 128 * 1024
)

var privateKeyPEMMarkers = [][]byte{
	[]byte("-----BEGIN PRIVATE KEY-----"),
	[]byte("-----BEGIN ENCRYPTED PRIVATE KEY-----"),
	[]byte("-----BEGIN RSA PRIVATE KEY-----"),
	[]byte("-----BEGIN EC PRIVATE KEY-----"),
	[]byte("-----BEGIN DSA PRIVATE KEY-----"),
	[]byte("-----BEGIN OPENSSH PRIVATE KEY-----"),
}

var privateKeyPEMMarkerPattern = regexp.MustCompile(`-----BEGIN [A-Z0-9 -]{0,64}PRIVATE KEY-----`)
var campaignIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,127}$`)

var publishCanonicalNew = evidencefile.WriteCanonicalNew

type singleValue struct {
	name  string
	value string
	set   bool
}

func (value *singleValue) String() string { return value.value }

func (value *singleValue) Set(candidate string) error {
	if value.set {
		return fmt.Errorf("%s may be specified exactly once", value.name)
	}
	value.value = candidate
	value.set = true
	return nil
}

type namedPaths struct {
	option string
	values map[string]string
}

func newNamedPaths(option string) *namedPaths {
	return &namedPaths{option: option, values: make(map[string]string)}
}

func (paths *namedPaths) String() string { return "NAME=ABSOLUTE_PATH" }

func (paths *namedPaths) Set(candidate string) error {
	name, path, ok := strings.Cut(candidate, "=")
	if !ok || name == "" || path == "" {
		return fmt.Errorf("%s value must be NAME=ABSOLUTE_PATH", paths.option)
	}
	if _, duplicate := paths.values[name]; duplicate {
		return fmt.Errorf("%s name %q was specified more than once", paths.option, name)
	}
	if err := validateCanonicalAbsolutePath(path); err != nil {
		return fmt.Errorf("%s %q path: %w", paths.option, name, err)
	}
	paths.values[name] = path
	return nil
}

type byteRecipeSpec struct {
	testID    string
	subcaseID string
	target    string
}

type replacementRecipeSpec struct {
	testID    string
	subcaseID string
	inputName string
}

type inspectedFile struct {
	file      *os.File
	source    stablecampaign.PublicArtifactSource
	identity  fileIdentity
	digest    bundle.Digest
	xorDigest bundle.Digest
}

type fileIdentity struct {
	device uint64
	inode  uint64
	size   int64
	mode   uint32
	mtime  syscall.Timespec
	ctime  syscall.Timespec
}

type openedFileIdentity struct {
	device uint64
	inode  uint64
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("kaiba-rpi5-stable-campaign-plan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() { printUsage(stderr) }
	campaignID := &singleValue{name: "--campaign-id"}
	outputPath := &singleValue{name: "--output"}
	publicPaths := newNamedPaths("--public-input")
	targetPaths := newNamedPaths("--byte-mutation-target")
	flags.Var(campaignID, "campaign-id", "canonical development campaign identifier")
	flags.Var(publicPaths, "public-input", "required public input as NAME=ABSOLUTE_PATH (repeat exactly 27 times)")
	flags.Var(targetPaths, "byte-mutation-target", "positive mutation target as TARGET=ABSOLUTE_PATH (repeat exactly 10 times)")
	flags.Var(outputPath, "output", "new absolute output path; omit to write canonical JSON to stdout")
	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "stable campaign plan: positional arguments are not accepted")
		return exitUsage
	}
	if !campaignID.set || campaignID.value == "" {
		fmt.Fprintln(stderr, "stable campaign plan: --campaign-id is required exactly once")
		return exitUsage
	}
	if !campaignIDPattern.MatchString(campaignID.value) {
		fmt.Fprintln(stderr, "stable campaign plan: --campaign-id must be a canonical identifier")
		return exitUsage
	}
	if outputPath.set {
		if outputPath.value == "" {
			fmt.Fprintln(stderr, "stable campaign plan: --output must not be empty")
			return exitUsage
		}
		if err := validateCanonicalAbsolutePath(outputPath.value); err != nil {
			fmt.Fprintf(stderr, "stable campaign plan: --output: %v\n", err)
			return exitUsage
		}
	}
	if err := requireExactPublicInputNames(publicPaths.values); err != nil {
		fmt.Fprintf(stderr, "stable campaign plan: %v\n", err)
		return exitUsage
	}
	byteSpecs, err := requireExactByteMutationTargets(targetPaths.values)
	if err != nil {
		fmt.Fprintf(stderr, "stable campaign plan: %v\n", err)
		return exitUsage
	}

	plan, opened, err := constructPlan(campaignID.value, publicPaths.values, targetPaths.values, byteSpecs)
	defer closeInspectedFiles(opened)
	if err != nil {
		fmt.Fprintf(stderr, "stable campaign plan: %v\n", err)
		return exitInvalid
	}
	encoded, err := plan.CanonicalJSON()
	if err != nil {
		fmt.Fprintf(stderr, "stable campaign plan: encode canonical plan: %v\n", err)
		return exitInvalid
	}
	transport := append(encoded, '\n')
	if !outputPath.set {
		if err := writeAll(stdout, transport); err != nil {
			fmt.Fprintf(stderr, "stable campaign plan: write stdout: %v\n", err)
			return exitInvalid
		}
		return exitOK
	}
	if err := writeNewOutput(outputPath.value, transport); err != nil {
		fmt.Fprintf(stderr, "stable campaign plan: write output: %v\n", err)
		return exitInvalid
	}
	return exitOK
}

func constructPlan(
	campaignID string,
	publicPaths, targetPaths map[string]string,
	byteSpecs []byteRecipeSpec,
) (stablecampaign.Plan, []*inspectedFile, error) {
	opened := make([]*inspectedFile, 0, len(publicPaths)+len(targetPaths))
	openedRoles := make(map[openedFileIdentity]string, cap(opened))
	publicSources := make(map[string]stablecampaign.PublicArtifactSource, len(publicPaths))
	publicBindings := make([]stablecampaign.ArtifactBinding, 0, len(publicPaths))
	bindingsByName := make(map[string]stablecampaign.ArtifactBinding, len(publicPaths))
	for _, name := range stablecampaign.RequiredPublicInputNames() {
		inspected, err := openAndInspect(publicPaths[name], false)
		if err != nil {
			return stablecampaign.Plan{}, opened, fmt.Errorf("public input %q: %w", name, err)
		}
		opened = append(opened, inspected)
		if err := registerOpenedRole(openedRoles, fmt.Sprintf("public input %q", name), inspected.identity); err != nil {
			return stablecampaign.Plan{}, opened, err
		}
		binding := stablecampaign.ArtifactBinding{
			Name: name, Digest: inspected.digest, SizeBytes: inspected.source.SizeBytes,
		}
		publicBindings = append(publicBindings, binding)
		bindingsByName[name] = binding
		publicSources[name] = inspected.source
	}

	byteSources := make(map[string]stablecampaign.PublicArtifactSource, len(targetPaths))
	byteRecipes := make([]stablecampaign.ByteXORMutationRecipe, 0, len(byteSpecs))
	for _, spec := range byteSpecs {
		inspected, err := openAndInspect(targetPaths[spec.target], true)
		if err != nil {
			return stablecampaign.Plan{}, opened, fmt.Errorf("byte mutation target %q: %w", spec.target, err)
		}
		opened = append(opened, inspected)
		if err := registerOpenedRole(openedRoles, fmt.Sprintf("byte mutation target %q", spec.target), inspected.identity); err != nil {
			return stablecampaign.Plan{}, opened, err
		}
		bindingName := spec.testID + "-" + spec.subcaseID
		before := stablecampaign.ArtifactBinding{
			Name: bindingName, Digest: inspected.digest, SizeBytes: inspected.source.SizeBytes,
		}
		after := stablecampaign.ArtifactBinding{
			Name: bindingName, Digest: inspected.xorDigest, SizeBytes: inspected.source.SizeBytes,
		}
		recipe, err := stablecampaign.NewByteXORMutationRecipe(
			spec.testID, spec.subcaseID, spec.target, before, after,
		)
		if err != nil {
			return stablecampaign.Plan{}, opened, fmt.Errorf("construct byte mutation %q:%q: %w", spec.testID, spec.subcaseID, err)
		}
		byteRecipes = append(byteRecipes, recipe)
		byteSources[spec.target] = inspected.source
	}

	replacementSpecs := fixedReplacementRecipeSpecs()
	replacements := make([]stablecampaign.BoundReplacementMutationRecipe, 0, len(replacementSpecs))
	positive := bindingsByName["positive-release-manifest"]
	for _, spec := range replacementSpecs {
		recipe, err := stablecampaign.NewBoundReplacementMutationRecipe(
			spec.testID, spec.subcaseID, positive, bindingsByName[spec.inputName],
		)
		if err != nil {
			return stablecampaign.Plan{}, opened, fmt.Errorf("construct replacement %q:%q: %w", spec.testID, spec.subcaseID, err)
		}
		replacements = append(replacements, recipe)
	}

	plan, err := stablecampaign.NewPlan(campaignID, publicBindings, byteRecipes, replacements)
	if err != nil {
		return stablecampaign.Plan{}, opened, fmt.Errorf("construct campaign plan: %w", err)
	}
	if _, err := stablecampaign.ResolvePublicArtifactSources(plan, stablecampaign.PublicArtifactSources{
		PublicInputs: publicSources, ByteMutationTargets: byteSources,
	}); err != nil {
		return stablecampaign.Plan{}, opened, fmt.Errorf("resolve campaign plan against supplied public files: %w", err)
	}
	for _, inspected := range opened {
		identity, err := statIdentity(int(inspected.file.Fd()))
		if err != nil || identity != inspected.identity {
			return stablecampaign.Plan{}, opened, errors.New("supplied public file changed while the completed plan was resolved")
		}
	}
	return plan, opened, nil
}

func registerOpenedRole(registry map[openedFileIdentity]string, role string, identity fileIdentity) error {
	key := openedFileIdentity{device: identity.device, inode: identity.inode}
	if previous, exists := registry[key]; exists {
		return fmt.Errorf("%s reuses the same opened file identity as %s", role, previous)
	}
	registry[key] = role
	return nil
}

func openAndInspect(path string, xor bool) (*inspectedFile, error) {
	file, before, err := openAbsoluteRegular(path)
	if err != nil {
		return nil, err
	}
	if before.size <= 0 {
		_ = file.Close()
		return nil, errors.New("input must be nonempty")
	}
	source := stablecampaign.PublicArtifactSource{SizeBytes: uint64(before.size), ReaderAt: file}
	beforeDigest, afterDigest, err := inspectSource(source, xor)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	afterRead, err := statIdentity(int(file.Fd()))
	if err != nil || afterRead != before {
		_ = file.Close()
		return nil, errors.New("input changed while it was inspected")
	}
	return &inspectedFile{
		file: file, source: source, identity: afterRead, digest: beforeDigest, xorDigest: afterDigest,
	}, nil
}

func inspectSource(source stablecampaign.PublicArtifactSource, xor bool) (bundle.Digest, bundle.Digest, error) {
	if source.SizeBytes == 0 {
		return "", "", errors.New("source must be nonempty")
	}
	beforeHash := sha256.New()
	var afterHash hash.Hash
	if xor {
		afterHash = sha256.New()
	}
	scanner := newMarkerScanner()
	buffer := make([]byte, readChunkSize)
	for offset := uint64(0); offset < source.SizeBytes; {
		remaining := source.SizeBytes - offset
		readSize := uint64(len(buffer))
		if remaining < readSize {
			readSize = remaining
		}
		chunk := buffer[:int(readSize)]
		n, err := source.ReaderAt.ReadAt(chunk, int64(offset))
		if n != len(chunk) {
			return "", "", fmt.Errorf("short read at byte %d: got %d, want %d", offset, n, len(chunk))
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return "", "", fmt.Errorf("read at byte %d: %w", offset, err)
		}
		_, _ = beforeHash.Write(chunk)
		if xor {
			if offset == 0 {
				_, _ = afterHash.Write([]byte{chunk[0] ^ 1})
				_, _ = afterHash.Write(chunk[1:])
			} else {
				_, _ = afterHash.Write(chunk)
			}
		}
		if scanner.Consume(chunk) {
			return "", "", errors.New("input contains a private-key PEM marker (scoped defense in depth; this is not a proof that other inputs lack private material)")
		}
		offset += uint64(n)
	}
	before := digestFromHash(beforeHash)
	if !xor {
		return before, "", nil
	}
	return before, digestFromHash(afterHash), nil
}

func digestFromHash(value hash.Hash) bundle.Digest {
	return bundle.Digest("sha256:" + hex.EncodeToString(value.Sum(nil)))
}

type markerScanner struct {
	tail []byte
	keep int
}

func newMarkerScanner() *markerScanner {
	maximum := 128
	for _, marker := range privateKeyPEMMarkers {
		if len(marker) > maximum {
			maximum = len(marker)
		}
	}
	return &markerScanner{keep: maximum - 1}
}

func (scanner *markerScanner) Consume(chunk []byte) bool {
	window := make([]byte, 0, len(scanner.tail)+len(chunk))
	window = append(window, scanner.tail...)
	window = append(window, chunk...)
	for _, marker := range privateKeyPEMMarkers {
		if bytes.Contains(window, marker) {
			return true
		}
	}
	if privateKeyPEMMarkerPattern.Match(window) {
		return true
	}
	keep := scanner.keep
	if keep > len(window) {
		keep = len(window)
	}
	scanner.tail = append(scanner.tail[:0], window[len(window)-keep:]...)
	return false
}

func requireExactPublicInputNames(supplied map[string]string) error {
	expected := stablecampaign.RequiredPublicInputNames()
	if len(supplied) != len(expected) {
		return fmt.Errorf("--public-input must provide exactly %d named public files", len(expected))
	}
	for _, name := range expected {
		if _, ok := supplied[name]; !ok {
			return fmt.Errorf("--public-input is missing required name %q", name)
		}
	}
	return nil
}

func requireExactByteMutationTargets(supplied map[string]string) ([]byteRecipeSpec, error) {
	specs := fixedByteRecipeSpecs()
	if len(supplied) != len(specs)+1 {
		return nil, fmt.Errorf("--byte-mutation-target must provide exactly %d named target files", len(specs)+1)
	}
	fixed := make(map[string]struct{}, len(specs))
	for _, spec := range specs {
		fixed[spec.target] = struct{}{}
		if _, ok := supplied[spec.target]; !ok {
			return nil, fmt.Errorf("--byte-mutation-target is missing required target %q", spec.target)
		}
	}
	overlay := ""
	for target := range supplied {
		if _, ok := fixed[target]; ok {
			continue
		}
		if overlay != "" {
			return nil, errors.New("--byte-mutation-target must contain exactly one canonical release overlay target")
		}
		overlay = target
	}
	if overlay == "" {
		return nil, errors.New("--byte-mutation-target is missing its canonical release overlay target")
	}
	// NewByteXORMutationRecipe performs the authoritative overlay target
	// vocabulary check after the target bytes have been bound.
	specs = append(specs, byteRecipeSpec{
		testID: "component-byte-mutations-rejected", subcaseID: "overlay", target: overlay,
	})
	sort.Slice(specs, func(left, right int) bool {
		return specs[left].testID+":"+specs[left].subcaseID < specs[right].testID+":"+specs[right].subcaseID
	})
	return specs, nil
}

func fixedByteRecipeSpecs() []byteRecipeSpec {
	return []byteRecipeSpec{
		{testID: "component-byte-mutations-rejected", subcaseID: "kernel", target: "release/kernel"},
		{testID: "component-byte-mutations-rejected", subcaseID: "initramfs", target: "release/initramfs"},
		{testID: "component-byte-mutations-rejected", subcaseID: "resolved-device-tree", target: "release/device-tree.dtb"},
		{testID: "component-byte-mutations-rejected", subcaseID: "kernel-command-line", target: "release/cmdline.txt"},
		{testID: "component-byte-mutations-rejected", subcaseID: "root-image", target: "release/root.img"},
		{testID: "component-byte-mutations-rejected", subcaseID: "dm-verity-metadata", target: "release/dm-verity.json"},
		{testID: "component-byte-mutations-rejected", subcaseID: "slot-metadata", target: "release/slot.txt"},
		{testID: "dm-verity-corruption-rejected", subcaseID: "root-data", target: "media/root-data"},
		{testID: "dm-verity-corruption-rejected", subcaseID: "root-hash", target: "media/root-hash"},
	}
}

func fixedReplacementRecipeSpecs() []replacementRecipeSpec {
	specs := make([]replacementRecipeSpec, 0, 20)
	for _, inputName := range stablecampaign.RequiredPublicInputNames() {
		spec := replacementRecipeSpec{inputName: inputName}
		switch {
		case strings.HasPrefix(inputName, "manifest-field-"):
			spec.testID = "manifest-field-mutations-rejected"
			spec.subcaseID = strings.TrimPrefix(inputName, "manifest-field-")
		case inputName == "replacement-release-manifest":
			spec.testID = "delegated-key-replacement-boots"
			spec.subcaseID = "replacement-manifest"
		case inputName == "revoked-release-manifest":
			spec.testID = "revoked-delegated-key-rejected"
			spec.subcaseID = "revoked-manifest"
		case inputName == "unsigned-release-manifest":
			spec.testID = "unsigned-release-rejected"
			spec.subcaseID = "unsigned-manifest"
		case inputName == "wrong-key-release-manifest":
			spec.testID = "wrong-delegated-key-rejected"
			spec.subcaseID = "wrong-key-manifest"
		default:
			continue
		}
		specs = append(specs, spec)
	}
	sort.Slice(specs, func(left, right int) bool {
		return specs[left].testID+":"+specs[left].subcaseID < specs[right].testID+":"+specs[right].subcaseID
	})
	return specs
}

func validateCanonicalAbsolutePath(path string) error {
	if path == "" || path == string(filepath.Separator) || strings.ContainsRune(path, '\x00') ||
		strings.ContainsAny(path, "\r\n") || !utf8.ValidString(path) {
		return errors.New("path must be a nonempty single-line UTF-8 path other than filesystem root")
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("path must be absolute and lexically canonical")
	}
	if path == "/dev" || strings.HasPrefix(path, "/dev/") {
		return errors.New("device paths are outside the public-file plan boundary")
	}
	return nil
}

func openAbsoluteRegular(path string) (*os.File, fileIdentity, error) {
	if err := validateCanonicalAbsolutePath(path); err != nil {
		return nil, fileIdentity{}, err
	}
	rootFD, err := syscall.Open(
		string(filepath.Separator),
		syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_DIRECTORY,
		0,
	)
	if err != nil {
		return nil, fileIdentity{}, fmt.Errorf("open filesystem root: %w", err)
	}
	current := os.NewFile(uintptr(rootFD), string(filepath.Separator))
	if current == nil {
		_ = syscall.Close(rootFD)
		return nil, fileIdentity{}, errors.New("construct filesystem root handle")
	}
	components := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	for index, component := range components {
		flags := syscall.O_RDONLY | syscall.O_CLOEXEC | syscall.O_NOFOLLOW
		if index < len(components)-1 {
			flags |= syscall.O_DIRECTORY
		} else {
			flags |= syscall.O_NONBLOCK
		}
		fd, err := syscall.Openat(int(current.Fd()), component, flags, 0)
		if err != nil {
			_ = current.Close()
			return nil, fileIdentity{}, fmt.Errorf("open path component %q without following symlinks: %w", component, err)
		}
		next := os.NewFile(uintptr(fd), component)
		if next == nil {
			_ = syscall.Close(fd)
			_ = current.Close()
			return nil, fileIdentity{}, fmt.Errorf("construct handle for path component %q", component)
		}
		if err := current.Close(); err != nil {
			_ = next.Close()
			return nil, fileIdentity{}, fmt.Errorf("close prior path component: %w", err)
		}
		current = next
	}
	identity, err := statIdentity(int(current.Fd()))
	if err != nil {
		_ = current.Close()
		return nil, fileIdentity{}, fmt.Errorf("inspect opened input: %w", err)
	}
	if identity.mode&syscall.S_IFMT != syscall.S_IFREG {
		_ = current.Close()
		return nil, fileIdentity{}, errors.New("input must be a regular non-symlink file")
	}
	if err := syscall.SetNonblock(int(current.Fd()), false); err != nil {
		_ = current.Close()
		return nil, fileIdentity{}, fmt.Errorf("clear input nonblocking mode: %w", err)
	}
	return current, identity, nil
}

func statIdentity(fd int) (fileIdentity, error) {
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return fileIdentity{}, err
	}
	return fileIdentity{
		device: uint64(stat.Dev), inode: stat.Ino, size: stat.Size, mode: stat.Mode,
		mtime: stat.Mtim, ctime: stat.Ctim,
	}, nil
}

func writeNewOutput(path string, contents []byte) error {
	return publishCanonicalNew(path, contents)
}

func writeAll(destination io.Writer, contents []byte) error {
	for len(contents) > 0 {
		written, err := destination.Write(contents)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(contents) {
			return io.ErrShortWrite
		}
		contents = contents[written:]
	}
	return nil
}

func closeInspectedFiles(files []*inspectedFile) {
	for _, inspected := range files {
		if inspected != nil && inspected.file != nil {
			_ = inspected.file.Close()
		}
	}
}

func printUsage(output io.Writer) {
	fmt.Fprintln(output, "usage: kaiba-rpi5-stable-campaign-plan --campaign-id ID \\")
	fmt.Fprintln(output, "         --public-input NAME=ABSOLUTE_PATH ... \\")
	fmt.Fprintln(output, "         --byte-mutation-target TARGET=ABSOLUTE_PATH ... [--output NEW_ABSOLUTE_PATH]")
	fmt.Fprintln(output, "requires exactly 27 fixed public-input names and 10 fixed mutation targets; output is descriptive path-free canonical JSON")
	fmt.Fprintln(output, "required --public-input names:")
	for _, name := range stablecampaign.RequiredPublicInputNames() {
		fmt.Fprintf(output, "  %s\n", name)
	}
	targets := make([]string, 0, len(fixedByteRecipeSpecs()))
	for _, spec := range fixedByteRecipeSpecs() {
		targets = append(targets, spec.target)
	}
	sort.Strings(targets)
	fmt.Fprintln(output, "required --byte-mutation-target names:")
	for _, target := range targets {
		fmt.Fprintf(output, "  %s\n", target)
	}
	fmt.Fprintln(output, "  release/overlays/<canonical-name>.dtbo (exactly one)")
}
