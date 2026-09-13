//go:build linux

// kaiba-rpi5-stable-campaign-gpt-inspect performs a range-bound, read-only
// inspection of the initial GPT and planned recovery ranges on one fixed
// development campaign selector. v1alpha1 remains the default; v1alpha2 must
// be selected explicitly to parse a distinct valid physical-end backup
// lineage. It has no output-path, filesystem-staging, repair,
// writable-target-descriptor, signing, or authorization capability.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaignmedia"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediadevice"
)

const (
	exitOK      = 0
	exitInvalid = 1
	exitUsage   = 2

	envelopeVersionV1Alpha1 = "v1alpha1"
	envelopeVersionV1Alpha2 = "v1alpha2"
)

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

type readAtCloser interface {
	io.ReaderAt
	io.Closer
}

// openedAttachment carries one exclusively locked read-only descriptor and a
// callback which repeats both the inactive-device inventory and the descriptor
// binding check. Tests replace this boundary without acquiring a real device.
type openedAttachment struct {
	reader     readAtCloser
	revalidate func(context.Context) error
}

type dependencies struct {
	hostname        func() (string, error)
	random          io.Reader
	open            func(context.Context, campaignmedia.DeviceIdentity) (openedAttachment, error)
	inspect         func(io.ReaderAt, campaignmedia.DeviceIdentity, string, []campaignmedia.PlannedPayloadRange) (campaignmedia.InitialGPTRecoveryEnvelope, error)
	verify          func(campaignmedia.InitialGPTRecoveryEnvelope, io.ReaderAt) error
	encode          func(campaignmedia.InitialGPTRecoveryEnvelope) ([]byte, error)
	inspectV1Alpha2 func(io.ReaderAt, campaignmedia.DeviceIdentity, string, []campaignmedia.PlannedPayloadRange) (campaignmedia.InitialGPTRecoveryEnvelopeV1Alpha2, error)
	verifyV1Alpha2  func(campaignmedia.InitialGPTRecoveryEnvelopeV1Alpha2, io.ReaderAt) error
	encodeV1Alpha2  func(campaignmedia.InitialGPTRecoveryEnvelopeV1Alpha2) ([]byte, error)
}

func productionDependencies() dependencies {
	return dependencies{
		hostname: os.Hostname,
		random:   rand.Reader,
		open:     openFixedAttachment,
		inspect:  campaignmedia.InspectInitialGPTRecovery,
		verify: func(envelope campaignmedia.InitialGPTRecoveryEnvelope, reader io.ReaderAt) error {
			return envelope.VerifyAgainst(reader)
		},
		encode: func(envelope campaignmedia.InitialGPTRecoveryEnvelope) ([]byte, error) {
			return envelope.CanonicalJSON()
		},
		inspectV1Alpha2: campaignmedia.InspectInitialGPTRecoveryV1Alpha2,
		verifyV1Alpha2: func(envelope campaignmedia.InitialGPTRecoveryEnvelopeV1Alpha2, reader io.ReaderAt) error {
			return envelope.VerifyAgainst(reader)
		},
		encodeV1Alpha2: func(envelope campaignmedia.InitialGPTRecoveryEnvelopeV1Alpha2) ([]byte, error) {
			return envelope.CanonicalJSON()
		},
	}
}

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr, productionDependencies()))
}

func run(ctx context.Context, arguments []string, stdout, stderr io.Writer, deps dependencies) int {
	flags := flag.NewFlagSet("kaiba-rpi5-stable-campaign-gpt-inspect", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() { printUsage(stderr) }
	leg := &singleValue{name: "--leg"}
	diskGUID := &singleValue{name: "--disk-guid"}
	envelopeVersion := &singleValue{name: "--envelope-version"}
	flags.Var(leg, "leg", "fixed device leg: malak-sd or pi-local-nvme")
	flags.Var(diskGUID, "disk-guid", "operator-asserted lowercase selected LBA-1 GPT disk GUID; not authenticated")
	flags.Var(envelopeVersion, "envelope-version", "explicit envelope parser: v1alpha1 or v1alpha2; default v1alpha1")
	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "initial GPT inspection: positional arguments are not accepted")
		return exitUsage
	}
	for _, required := range []*singleValue{leg, diskGUID} {
		if !required.set || required.value == "" {
			fmt.Fprintf(stderr, "initial GPT inspection: %s is required exactly once\n", required.name)
			return exitUsage
		}
	}
	selectedEnvelopeVersion := envelopeVersionV1Alpha1
	if envelopeVersion.set {
		selectedEnvelopeVersion = envelopeVersion.value
	}
	if selectedEnvelopeVersion != envelopeVersionV1Alpha1 && selectedEnvelopeVersion != envelopeVersionV1Alpha2 {
		fmt.Fprintf(stderr, "initial GPT inspection: --envelope-version must be %q or %q\n", envelopeVersionV1Alpha1, envelopeVersionV1Alpha2)
		return exitUsage
	}

	identity, planned, err := fixedInspectionInputs(campaignmedia.Leg(leg.value), diskGUID.value)
	if err != nil {
		fmt.Fprintf(stderr, "initial GPT inspection: %v\n", err)
		return exitUsage
	}
	if err := requireFixedHostname(deps.hostname, identity); err != nil {
		fmt.Fprintf(stderr, "initial GPT inspection: %v\n", err)
		return exitInvalid
	}
	captureID, err := newCaptureID(deps.random)
	if err != nil {
		fmt.Fprintf(stderr, "initial GPT inspection: generate capture identifier: %v\n", err)
		return exitInvalid
	}

	attachment, err := deps.open(ctx, identity)
	if err != nil {
		fmt.Fprintf(stderr, "initial GPT inspection: open fixed inactive attachment read-only: %v\n", err)
		return exitInvalid
	}
	if attachment.reader == nil || attachment.revalidate == nil {
		if attachment.reader != nil {
			_ = attachment.reader.Close()
		}
		fmt.Fprintln(stderr, "initial GPT inspection: opened attachment boundary is incomplete")
		return exitInvalid
	}
	closed := false
	defer func() {
		if !closed {
			_ = attachment.reader.Close()
		}
	}()

	if err := attachment.revalidate(ctx); err != nil {
		fmt.Fprintf(stderr, "initial GPT inspection: validate attachment before first range read: %v\n", err)
		return exitInvalid
	}
	if err := requireFixedHostname(deps.hostname, identity); err != nil {
		fmt.Fprintf(stderr, "initial GPT inspection: validate hostname before first range read: %v\n", err)
		return exitInvalid
	}
	var envelopeV1Alpha1 campaignmedia.InitialGPTRecoveryEnvelope
	var envelopeV1Alpha2 campaignmedia.InitialGPTRecoveryEnvelopeV1Alpha2
	switch selectedEnvelopeVersion {
	case envelopeVersionV1Alpha1:
		if deps.inspect == nil || deps.verify == nil || deps.encode == nil {
			fmt.Fprintln(stderr, "initial GPT inspection: v1alpha1 inspection boundary is incomplete")
			return exitInvalid
		}
		envelopeV1Alpha1, err = deps.inspect(attachment.reader, identity, captureID, planned)
	case envelopeVersionV1Alpha2:
		if deps.inspectV1Alpha2 == nil || deps.verifyV1Alpha2 == nil || deps.encodeV1Alpha2 == nil {
			fmt.Fprintln(stderr, "initial GPT inspection: v1alpha2 inspection boundary is incomplete")
			return exitInvalid
		}
		envelopeV1Alpha2, err = deps.inspectV1Alpha2(attachment.reader, identity, captureID, planned)
	}
	if err != nil {
		fmt.Fprintf(stderr, "initial GPT inspection: inspect first range read: %v\n", err)
		return exitInvalid
	}
	// This boundary check is both the after-first-read and before-second-read
	// attachment check. It does not make the two sequential passes atomic or
	// establish physical quiescence.
	if err := attachment.revalidate(ctx); err != nil {
		fmt.Fprintf(stderr, "initial GPT inspection: validate attachment between range reads: %v\n", err)
		return exitInvalid
	}
	if err := requireFixedHostname(deps.hostname, identity); err != nil {
		fmt.Fprintf(stderr, "initial GPT inspection: validate hostname between range reads: %v\n", err)
		return exitInvalid
	}
	switch selectedEnvelopeVersion {
	case envelopeVersionV1Alpha1:
		err = deps.verify(envelopeV1Alpha1, attachment.reader)
	case envelopeVersionV1Alpha2:
		err = deps.verifyV1Alpha2(envelopeV1Alpha2, attachment.reader)
	}
	if err != nil {
		fmt.Fprintf(stderr, "initial GPT inspection: repeated range read verification: %v\n", err)
		return exitInvalid
	}
	if err := attachment.revalidate(ctx); err != nil {
		fmt.Fprintf(stderr, "initial GPT inspection: validate attachment after second range read: %v\n", err)
		return exitInvalid
	}
	if err := requireFixedHostname(deps.hostname, identity); err != nil {
		fmt.Fprintf(stderr, "initial GPT inspection: validate hostname after second range read: %v\n", err)
		return exitInvalid
	}
	var encoded []byte
	switch selectedEnvelopeVersion {
	case envelopeVersionV1Alpha1:
		encoded, err = deps.encode(envelopeV1Alpha1)
	case envelopeVersionV1Alpha2:
		encoded, err = deps.encodeV1Alpha2(envelopeV1Alpha2)
	}
	if err != nil {
		fmt.Fprintf(stderr, "initial GPT inspection: encode canonical envelope: %v\n", err)
		return exitInvalid
	}
	closeErr := attachment.reader.Close()
	closed = true
	if closeErr != nil {
		fmt.Fprintf(stderr, "initial GPT inspection: close locked read-only attachment: %v\n", closeErr)
		return exitInvalid
	}
	if err := writeAll(stdout, append(encoded, '\n')); err != nil {
		fmt.Fprintf(stderr, "initial GPT inspection: write canonical envelope to stdout: %v\n", err)
		return exitInvalid
	}
	return exitOK
}

func newCaptureID(random io.Reader) (string, error) {
	if random == nil {
		return "", errors.New("random source is nil")
	}
	nonce := make([]byte, 32)
	if _, err := io.ReadFull(random, nonce); err != nil {
		return "", err
	}
	return "capture:" + hex.EncodeToString(nonce), nil
}

func requireFixedHostname(read func() (string, error), identity campaignmedia.DeviceIdentity) error {
	hostname, err := read()
	if err != nil {
		return fmt.Errorf("read hostname: %w", err)
	}
	if hostname != identity.Hostname {
		return fmt.Errorf("leg %q requires fixed hostname %q, not %q; hostname equality is not host authentication", identity.Leg, identity.Hostname, hostname)
	}
	return nil
}

func fixedInspectionInputs(leg campaignmedia.Leg, operatorAssertedDiskGUID string) (campaignmedia.DeviceIdentity, []campaignmedia.PlannedPayloadRange, error) {
	identity := campaignmedia.DeviceIdentity{
		Leg: leg, DiskGUID: operatorAssertedDiskGUID, LogicalSectorSizeBytes: campaignmedia.LogicalSectorSizeBytes,
	}
	var planned []campaignmedia.PlannedPayloadRange
	switch leg {
	case campaignmedia.LegMalakSD:
		identity.ConfigID = campaignmedia.MalakSDConfigID
		identity.Hostname = campaignmedia.MalakSDHostname
		identity.Selector = campaignmedia.MalakSDSelector
		identity.CapacityBytes = campaignmedia.MalakSDCapacityBytes
		planned = []campaignmedia.PlannedPayloadRange{
			{Role: campaignmedia.PartitionBootFilesystem, PartitionNumber: 1, OffsetBytes: campaignmedia.MalakSDBootStartBytes, SizeBytes: campaignmedia.MalakSDBootCapacityBytes},
			{Role: campaignmedia.PartitionRootData, PartitionNumber: 2, OffsetBytes: campaignmedia.MalakSDRootDataStartBytes, SizeBytes: campaignmedia.MalakSDRootDataCapacityBytes},
			{Role: campaignmedia.PartitionRootHash, PartitionNumber: 3, OffsetBytes: campaignmedia.MalakSDRootHashStartBytes, SizeBytes: campaignmedia.MalakSDRootHashCapacityBytes},
		}
	case campaignmedia.LegPiLocalNVMe:
		identity.ConfigID = campaignmedia.PiLocalNVMeConfigID
		identity.Hostname = campaignmedia.PiLocalNVMeHostname
		identity.Selector = campaignmedia.PiLocalNVMeSelector
		identity.CapacityBytes = campaignmedia.PiLocalNVMeCapacityBytes
		planned = []campaignmedia.PlannedPayloadRange{{
			Role: campaignmedia.PartitionReleaseFilesystem, PartitionNumber: 1,
			OffsetBytes: campaignmedia.PiLocalNVMeReleaseStartBytes, SizeBytes: campaignmedia.PiLocalNVMeReleaseCapacityBytes,
		}}
	default:
		return campaignmedia.DeviceIdentity{}, nil, fmt.Errorf("--leg must be %q or %q", campaignmedia.LegMalakSD, campaignmedia.LegPiLocalNVMe)
	}
	if err := identity.Validate(); err != nil {
		return campaignmedia.DeviceIdentity{}, nil, fmt.Errorf("fixed selector and operator-asserted disk GUID: %w", err)
	}
	return identity, planned, nil
}

type lockedReadDevice struct {
	*os.File
}

func (device *lockedReadDevice) Close() error {
	return mediadevice.CloseLocked(device.File)
}

func openFixedAttachment(ctx context.Context, identity campaignmedia.DeviceIdentity) (openedAttachment, error) {
	geometry := mediadevice.ReadOnlyTargetGeometry{
		SizeBytes:              identity.CapacityBytes,
		LogicalSectorSizeBytes: identity.LogicalSectorSizeBytes,
	}
	inspector := mediadevice.Inspector{}
	initial, err := inspector.InspectInactiveSelected(ctx, identity.Selector, geometry)
	if err != nil {
		return openedAttachment{}, err
	}
	file, err := mediadevice.OpenLocked(initial, false)
	if err != nil {
		return openedAttachment{}, err
	}
	device := &lockedReadDevice{File: file}
	revalidate := func(ctx context.Context) error {
		current, err := inspector.ReinspectInactiveSame(ctx, identity.Selector, geometry, initial)
		if err != nil {
			return err
		}
		return mediadevice.ValidateOpened(file, current)
	}
	return openedAttachment{reader: device, revalidate: revalidate}, nil
}

func writeAll(output io.Writer, data []byte) error {
	for len(data) != 0 {
		written, err := output.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

func printUsage(output io.Writer) {
	fmt.Fprintln(output, "usage: kaiba-rpi5-stable-campaign-gpt-inspect \\")
	fmt.Fprintln(output, "         --leg malak-sd|pi-local-nvme --disk-guid OPERATOR_ASSERTED_LOWERCASE_GUID [--envelope-version v1alpha1|v1alpha2]")
	fmt.Fprintln(output, "pins only the leg's fixed inactive whole-device selector read-only and emits one canonical JSON envelope on stdout")
	fmt.Fprintln(output, "v1alpha2 must be selected explicitly to parse and hash a distinct valid physical-end backup lineage; it performs no repair")
	fmt.Fprintln(output, "the internally generated capture ID is not authenticated; the two range-scoped reads are sequential, not atomic")
}
