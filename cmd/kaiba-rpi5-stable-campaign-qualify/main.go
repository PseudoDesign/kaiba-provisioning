//go:build linux

// This command reads public regular files and validates independent-review
// signatures. It has no device, target command, signing, or power interface.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaignmedia"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaignqualification"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stablecampaign"
)

const maxJSON = 1024 * 1024

type singleValue struct {
	value *string
	set   bool
}

func (value *singleValue) String() string { return *value.value }

func (value *singleValue) Set(encoded string) error {
	if value.set {
		return errors.New("option must be supplied only once")
	}
	value.set = true
	*value.value = encoded
	return nil
}

// Request paths are private operator inputs, never included in acceptance
// reports. Trust and the preselected session must be supplied independently.
type request struct {
	Plan                string                                 `json:"plan"`
	Baseline            string                                 `json:"baseline"`
	Materialization     string                                 `json:"materialization"`
	Layout              string                                 `json:"layout"`
	PublicInputs        map[string]string                      `json:"public_inputs"`
	ByteMutationTargets map[string]string                      `json:"byte_mutation_targets"`
	Payloads            map[campaignmedia.PartitionRole]string `json:"payloads"`
	DeviceFingerprint   bundle.Digest                          `json:"device_fingerprint"`
	ProfileDigest       bundle.Digest                          `json:"profile_digest"`
	Result              string                                 `json:"result"`
	Raw                 map[stablecampaign.RawRole]string      `json:"raw"`
	Witnesses           []string                               `json:"witnesses"`
	Supporting          map[string]string                      `json:"supporting"`
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 0 {
		fmt.Fprintln(stderr, "Usage: kaiba-rpi5-stable-campaign-qualify prepare|validate|preimage [options]")
		return 2
	}
	command := arguments[0]
	if command != "prepare" && command != "validate" && command != "preimage" {
		fmt.Fprintln(stderr, "unknown qualification command")
		return 2
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	var requestPath, sessionPath, trustPath, admissionDirectory, witnessPath, role string
	flags.Var(&singleValue{value: &requestPath}, "request", "canonical qualification request JSON, absolute regular-file path")
	flags.Var(&singleValue{value: &sessionPath}, "session", "independently preselected admission session, absolute regular-file path")
	flags.Var(&singleValue{value: &trustPath}, "trust-policy", "independently reviewed public role keys, absolute regular-file path")
	flags.Var(&singleValue{value: &admissionDirectory}, "admission-directory", "existing private admission-authority directory (validate only)")
	flags.Var(&singleValue{value: &witnessPath}, "witness", "canonical public witness, absolute regular-file path (preimage only)")
	flags.Var(&singleValue{value: &role}, "role", "collector or independent-reviewer (preimage only)")
	if err := flags.Parse(arguments[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		return 2
	}
	var output []byte
	var err error
	if command == "preimage" {
		if witnessPath == "" || role == "" || requestPath != "" || sessionPath != "" || trustPath != "" || admissionDirectory != "" {
			return 2
		}
		var data []byte
		data, err = readPublic(witnessPath, campaignqualification.MaximumWitnessBytes)
		if err == nil {
			var witness campaignqualification.SignedWitness
			witness, err = campaignqualification.ParseWitness(data)
			if err == nil {
				output, err = witness.Statement.SigningBytes(role)
			}
		}
	} else {
		if requestPath == "" || witnessPath != "" || role != "" || (command == "prepare" && (sessionPath != "" || trustPath != "" || admissionDirectory != "")) || (command == "validate" && (sessionPath == "" || trustPath == "" || admissionDirectory == "")) {
			return 2
		}
		output, err = qualify(command, requestPath, sessionPath, trustPath, admissionDirectory)
	}
	if err != nil {
		fmt.Fprintf(stderr, "qualification: %v\n", err)
		return 1
	}
	if command != "preimage" {
		output = append(output, '\n')
	}
	n, err := stdout.Write(output)
	if err == nil && n != len(output) {
		err = io.ErrShortWrite
	}
	if err != nil {
		fmt.Fprintf(stderr, "qualification: output unavailable; preserve any consumed admission: %v\n", err)
		return 1
	}
	return 0
}

func qualify(command, requestPath, sessionPath, trustPath, directory string) ([]byte, error) {
	encoded, err := readPublic(requestPath, maxJSON)
	if err != nil {
		return nil, err
	}
	var req request
	if err := campaignqualification.DecodeCanonical(encoded, &req, maxJSON); err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	var input campaignqualification.Input
	input.DeviceFingerprint, input.ProfileDigest = req.DeviceFingerprint, req.ProfileDigest
	encoded, err = readPublic(req.Plan, maxJSON)
	if err != nil {
		return nil, err
	}
	input.Plan, err = stablecampaign.ParsePlan(encoded)
	if err != nil {
		return nil, err
	}
	encoded, err = readPublic(req.Baseline, maxJSON)
	if err != nil {
		return nil, err
	}
	input.Baseline, err = campaignmedia.ParseArtifactSet(encoded)
	if err != nil {
		return nil, err
	}
	encoded, err = readPublic(req.Materialization, maxJSON)
	if err != nil {
		return nil, err
	}
	input.Materialization, err = campaignmedia.ParseRunArtifactMaterialization(encoded)
	if err != nil {
		return nil, err
	}
	encoded, err = readPublic(req.Layout, maxJSON)
	if err != nil {
		return nil, err
	}
	input.Layout, err = campaignmedia.ParseStagingPlan(encoded)
	if err != nil {
		return nil, err
	}
	input.PublicSources = stablecampaign.PublicArtifactSources{PublicInputs: map[string]stablecampaign.PublicArtifactSource{}, ByteMutationTargets: map[string]stablecampaign.PublicArtifactSource{}}
	input.Payloads = map[campaignmedia.PartitionRole]stablecampaign.PublicArtifactSource{}
	files := []*os.File{}
	stats := []os.FileInfo{}
	defer func() {
		for _, file := range files {
			file.Close()
		}
	}()
	open := func(path string) (stablecampaign.PublicArtifactSource, error) {
		file, info, err := openPublic(path, 16*1024*1024*1024)
		if err != nil {
			return stablecampaign.PublicArtifactSource{}, err
		}
		files = append(files, file)
		stats = append(stats, info)
		return stablecampaign.PublicArtifactSource{ReaderAt: file, SizeBytes: uint64(info.Size())}, nil
	}
	if len(req.PublicInputs) != 27 || len(req.ByteMutationTargets) != 10 || len(req.Payloads) != 4 {
		return nil, errors.New("exact public inputs, mutation targets and all four payloads are required")
	}
	for name, path := range req.PublicInputs {
		source, err := open(path)
		if err != nil {
			return nil, err
		}
		input.PublicSources.PublicInputs[name] = source
	}
	for name, path := range req.ByteMutationTargets {
		source, err := open(path)
		if err != nil {
			return nil, err
		}
		input.PublicSources.ByteMutationTargets[name] = source
	}
	for name, path := range req.Payloads {
		source, err := open(path)
		if err != nil {
			return nil, err
		}
		input.Payloads[name] = source
	}
	expectation, err := campaignqualification.Prepare(input)
	if err != nil {
		return nil, err
	}
	for index, file := range files {
		now, err := file.Stat()
		if err != nil {
			return nil, err
		}
		if !sameFileState(stats[index], now) {
			return nil, errors.New("public source changed during expectation preparation")
		}
	}
	if command == "prepare" {
		expected, err := expectation.CanonicalJSON()
		if err != nil {
			return nil, err
		}
		requirements, err := expectation.Requirements()
		if err != nil {
			return nil, err
		}
		return json.Marshal(struct {
			Expectation                 json.RawMessage                            `json:"expectation"`
			Witnesses                   []campaignqualification.WitnessRequirement `json:"witnesses"`
			PhysicalExecutionAuthorized bool                                       `json:"physical_execution_authorized"`
		}{expected, requirements, false})
	}
	var session campaignqualification.Session
	encoded, err = readPublic(sessionPath, maxJSON)
	if err != nil {
		return nil, err
	}
	if err := campaignqualification.DecodeCanonical(encoded, &session, maxJSON); err != nil {
		return nil, err
	}
	var trust campaignqualification.TrustPolicy
	encoded, err = readPublic(trustPath, maxJSON)
	if err != nil {
		return nil, err
	}
	if err := campaignqualification.DecodeCanonical(encoded, &trust, maxJSON); err != nil {
		return nil, err
	}
	encoded, err = readPublic(req.Result, maxJSON)
	if err != nil {
		return nil, err
	}
	result, err := stablecampaign.ParseExecutionResult(encoded, input.Plan)
	if err != nil {
		return nil, err
	}
	raw := map[stablecampaign.RawRole][]byte{}
	if len(req.Raw) > 4 || len(req.Witnesses) > 32 || len(req.Supporting) > 128 {
		return nil, errors.New("too many evidence files")
	}
	for role, path := range req.Raw {
		maximum := stablecampaign.MaximumAuxiliaryEvidenceBytes
		if role == stablecampaign.RawRoleUARTCapture {
			maximum = stablecampaign.MaximumUARTCaptureBytes
		}
		raw[role], err = readPublic(path, maximum)
		if err != nil {
			return nil, err
		}
	}
	witnesses := []campaignqualification.SignedWitness{}
	for _, path := range req.Witnesses {
		encoded, err = readPublic(path, campaignqualification.MaximumWitnessBytes)
		if err != nil {
			return nil, err
		}
		witness, err := campaignqualification.ParseWitness(encoded)
		if err != nil {
			return nil, err
		}
		witnesses = append(witnesses, witness)
	}
	supporting := map[string][]byte{}
	for name, path := range req.Supporting {
		supporting[name], err = readPublic(path, maxJSON)
		if err != nil {
			return nil, err
		}
	}
	report, err := campaignqualification.Validate(expectation, session, time.Now().Unix(), trust, result, raw, witnesses, supporting, campaignqualification.FileAdmission{Directory: directory})
	if err != nil {
		return nil, err
	}
	return report.CanonicalJSON()
}

func readPublic(path string, maximum int) ([]byte, error) {
	file, info, err := openPublic(path, int64(maximum))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	encoded, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil {
		return nil, err
	}
	now, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if len(encoded) != int(info.Size()) || !sameFileState(info, now) {
		return nil, errors.New("public evidence file changed during read")
	}
	return encoded, nil
}

func sameFileState(before, after os.FileInfo) bool {
	a, b := before.Sys().(*syscall.Stat_t), after.Sys().(*syscall.Stat_t)
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Size == b.Size && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

// Pin every directory without following symlinks; inspect the final inode
// through O_PATH before acquiring a readable descriptor. FIFOs and devices
// therefore fail without being opened for I/O or blocking the command.
func openPublic(path string, maximum int64) (*os.File, os.FileInfo, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsRune(path, 0) {
		return nil, nil, errors.New("public file requires a canonical absolute path")
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	for _, part := range parts[:len(parts)-1] {
		next, err := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		syscall.Close(fd)
		if err != nil {
			return nil, nil, err
		}
		fd = next
	}
	const oPath = 0x200000
	last, err := syscall.Openat(fd, parts[len(parts)-1], oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	syscall.Close(fd)
	if err != nil {
		return nil, nil, err
	}
	pinned := os.NewFile(uintptr(last), path)
	defer pinned.Close()
	info, err := pinned.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		return nil, nil, errors.New("public evidence must be a bounded nonempty regular file")
	}
	file, err := os.Open(fmt.Sprintf("/proc/self/fd/%d", last))
	if err != nil {
		return nil, nil, err
	}
	now, err := file.Stat()
	if err != nil || !os.SameFile(info, now) || info.Size() != now.Size() {
		file.Close()
		return nil, nil, errors.New("public file identity changed")
	}
	return file, now, nil
}
