//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaignmedia"
)

const testDiskGUID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"

type inertDevice struct {
	closes   int
	closeErr error
}

func (*inertDevice) ReadAt([]byte, int64) (int, error) { return 0, io.EOF }
func (device *inertDevice) Close() error {
	device.closes++
	return device.closeErr
}

func validArguments() []string {
	return []string{"--leg", "malak-sd", "--disk-guid", testDiskGUID}
}

func deterministicRandom() io.Reader {
	return bytes.NewReader(bytes.Repeat([]byte{0xab}, 32))
}

func expectedCaptureID() string {
	return "capture:" + strings.Repeat("ab", 32)
}

func TestRunPinsAndRevalidatesOneReaderAndEmitsOnlyCanonicalJSON(t *testing.T) {
	device := &inertDevice{}
	var opened campaignmedia.DeviceIdentity
	var inspected campaignmedia.DeviceIdentity
	var planned []campaignmedia.PlannedPayloadRange
	var inspectedReader, verifiedReader io.ReaderAt
	revalidations := 0
	deps := dependencies{
		hostname: func() (string, error) { return campaignmedia.MalakSDHostname, nil },
		random:   deterministicRandom(),
		open: func(_ context.Context, identity campaignmedia.DeviceIdentity) (openedAttachment, error) {
			opened = identity
			return openedAttachment{
				reader: device,
				revalidate: func(context.Context) error {
					revalidations++
					return nil
				},
			}, nil
		},
		inspect: func(reader io.ReaderAt, identity campaignmedia.DeviceIdentity, captureID string, ranges []campaignmedia.PlannedPayloadRange) (campaignmedia.InitialGPTRecoveryEnvelope, error) {
			inspectedReader = reader
			inspected = identity
			planned = append([]campaignmedia.PlannedPayloadRange(nil), ranges...)
			if captureID != expectedCaptureID() {
				t.Fatalf("capture ID = %q", captureID)
			}
			return campaignmedia.InitialGPTRecoveryEnvelope{CaptureID: captureID}, nil
		},
		verify: func(envelope campaignmedia.InitialGPTRecoveryEnvelope, reader io.ReaderAt) error {
			verifiedReader = reader
			if envelope.CaptureID != expectedCaptureID() {
				t.Fatalf("verify received wrong envelope: %#v", envelope)
			}
			return nil
		},
		encode: func(campaignmedia.InitialGPTRecoveryEnvelope) ([]byte, error) {
			return []byte(`{"destructive_staging_ready":false}`), nil
		},
	}
	var stdout, stderr bytes.Buffer
	if exit := run(context.Background(), validArguments(), &stdout, &stderr, deps); exit != exitOK {
		t.Fatalf("exit = %d, stderr = %s", exit, stderr.String())
	}
	if opened != inspected || opened.Selector != campaignmedia.MalakSDSelector || opened.DiskGUID != testDiskGUID {
		t.Fatalf("fixed identity changed: opened=%#v inspected=%#v", opened, inspected)
	}
	wantRanges := []campaignmedia.PlannedPayloadRange{
		{Role: campaignmedia.PartitionBootFilesystem, PartitionNumber: 1, OffsetBytes: campaignmedia.MalakSDBootStartBytes, SizeBytes: campaignmedia.MalakSDBootCapacityBytes},
		{Role: campaignmedia.PartitionRootData, PartitionNumber: 2, OffsetBytes: campaignmedia.MalakSDRootDataStartBytes, SizeBytes: campaignmedia.MalakSDRootDataCapacityBytes},
		{Role: campaignmedia.PartitionRootHash, PartitionNumber: 3, OffsetBytes: campaignmedia.MalakSDRootHashStartBytes, SizeBytes: campaignmedia.MalakSDRootHashCapacityBytes},
	}
	if !reflect.DeepEqual(planned, wantRanges) {
		t.Fatalf("planned ranges = %#v, want %#v", planned, wantRanges)
	}
	if inspectedReader != device || verifiedReader != device || revalidations != 3 || device.closes != 1 {
		t.Fatalf("reader binding/revalidation/close = %v/%v/%d/%d", inspectedReader == device, verifiedReader == device, revalidations, device.closes)
	}
	if stdout.String() != "{\"destructive_staging_ready\":false}\n" || stderr.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestRunSelectsV1Alpha2OnlyWhenExplicitlyRequested(t *testing.T) {
	device := &inertDevice{}
	inspections, verifications, encodes, revalidations := 0, 0, 0, 0
	deps := dependencies{
		hostname: func() (string, error) { return campaignmedia.MalakSDHostname, nil },
		random:   deterministicRandom(),
		open: func(_ context.Context, identity campaignmedia.DeviceIdentity) (openedAttachment, error) {
			return openedAttachment{reader: device, revalidate: func(context.Context) error {
				revalidations++
				return nil
			}}, nil
		},
		inspect: func(io.ReaderAt, campaignmedia.DeviceIdentity, string, []campaignmedia.PlannedPayloadRange) (campaignmedia.InitialGPTRecoveryEnvelope, error) {
			t.Fatal("legacy v1alpha1 inspector called for explicit v1alpha2 selection")
			return campaignmedia.InitialGPTRecoveryEnvelope{}, nil
		},
		verify: func(campaignmedia.InitialGPTRecoveryEnvelope, io.ReaderAt) error {
			t.Fatal("legacy v1alpha1 verifier called for explicit v1alpha2 selection")
			return nil
		},
		encode: func(campaignmedia.InitialGPTRecoveryEnvelope) ([]byte, error) {
			t.Fatal("legacy v1alpha1 encoder called for explicit v1alpha2 selection")
			return nil, nil
		},
		inspectV1Alpha2: func(reader io.ReaderAt, identity campaignmedia.DeviceIdentity, captureID string, ranges []campaignmedia.PlannedPayloadRange) (campaignmedia.InitialGPTRecoveryEnvelopeV1Alpha2, error) {
			inspections++
			if reader != device || identity.DiskGUID != testDiskGUID || captureID != expectedCaptureID() || len(ranges) != 3 {
				t.Fatal("v1alpha2 inspector did not retain the fixed reader, identity, capture, and ranges")
			}
			return campaignmedia.InitialGPTRecoveryEnvelopeV1Alpha2{CaptureID: captureID}, nil
		},
		verifyV1Alpha2: func(envelope campaignmedia.InitialGPTRecoveryEnvelopeV1Alpha2, reader io.ReaderAt) error {
			verifications++
			if reader != device || envelope.CaptureID != expectedCaptureID() {
				t.Fatal("v1alpha2 verifier received detached input")
			}
			return nil
		},
		encodeV1Alpha2: func(campaignmedia.InitialGPTRecoveryEnvelopeV1Alpha2) ([]byte, error) {
			encodes++
			return []byte(`{"schema_version":"v1alpha2","destructive_staging_ready":false}`), nil
		},
	}
	arguments := append(validArguments(), "--envelope-version", envelopeVersionV1Alpha2)
	var stdout, stderr bytes.Buffer
	if exit := run(context.Background(), arguments, &stdout, &stderr, deps); exit != exitOK {
		t.Fatalf("exit = %d, stderr = %s", exit, stderr.String())
	}
	if inspections != 1 || verifications != 1 || encodes != 1 || revalidations != 3 || device.closes != 1 ||
		stdout.String() != "{\"schema_version\":\"v1alpha2\",\"destructive_staging_ready\":false}\n" || stderr.Len() != 0 {
		t.Fatalf("inspect/verify/encode/revalidate/close/stdout/stderr = %d/%d/%d/%d/%d/%q/%q", inspections, verifications, encodes, revalidations, device.closes, stdout.String(), stderr.String())
	}
}

func TestRunV1Alpha2FailsClosedForUnsupportedVersionAndRejectedLineage(t *testing.T) {
	t.Run("unsupported version before open", func(t *testing.T) {
		opened := false
		deps := dependencies{
			hostname: func() (string, error) { return campaignmedia.MalakSDHostname, nil },
			open: func(context.Context, campaignmedia.DeviceIdentity) (openedAttachment, error) {
				opened = true
				return openedAttachment{}, nil
			},
		}
		var stdout, stderr bytes.Buffer
		arguments := append(validArguments(), "--envelope-version", "v1alpha3")
		if exit := run(context.Background(), arguments, &stdout, &stderr, deps); exit != exitUsage {
			t.Fatalf("exit = %d, stderr = %s", exit, stderr.String())
		}
		if opened || stdout.Len() != 0 || !strings.Contains(stderr.String(), "--envelope-version must be") {
			t.Fatalf("opened=%v stdout=%q stderr=%q", opened, stdout.String(), stderr.String())
		}
	})

	t.Run("invalid physical-end lineage", func(t *testing.T) {
		device := &inertDevice{}
		verified, encoded := false, false
		deps := dependencies{
			hostname: func() (string, error) { return campaignmedia.MalakSDHostname, nil },
			random:   deterministicRandom(),
			open: func(context.Context, campaignmedia.DeviceIdentity) (openedAttachment, error) {
				return openedAttachment{reader: device, revalidate: func(context.Context) error { return nil }}, nil
			},
			inspectV1Alpha2: func(io.ReaderAt, campaignmedia.DeviceIdentity, string, []campaignmedia.PlannedPayloadRange) (campaignmedia.InitialGPTRecoveryEnvelopeV1Alpha2, error) {
				return campaignmedia.InitialGPTRecoveryEnvelopeV1Alpha2{}, errors.New("physical-end GPT backup header CRC is invalid")
			},
			verifyV1Alpha2: func(campaignmedia.InitialGPTRecoveryEnvelopeV1Alpha2, io.ReaderAt) error {
				verified = true
				return nil
			},
			encodeV1Alpha2: func(campaignmedia.InitialGPTRecoveryEnvelopeV1Alpha2) ([]byte, error) {
				encoded = true
				return nil, nil
			},
		}
		var stdout, stderr bytes.Buffer
		arguments := append(validArguments(), "--envelope-version", envelopeVersionV1Alpha2)
		if exit := run(context.Background(), arguments, &stdout, &stderr, deps); exit != exitInvalid {
			t.Fatalf("exit = %d, stderr = %s", exit, stderr.String())
		}
		if verified || encoded || stdout.Len() != 0 || device.closes != 1 || !strings.Contains(stderr.String(), "physical-end GPT") {
			t.Fatalf("verified=%v encoded=%v stdout=%q closes=%d stderr=%q", verified, encoded, stdout.String(), device.closes, stderr.String())
		}
	})
}

func TestRunFailsBeforeOpeningForWrongHostOrAmbiguousArguments(t *testing.T) {
	opened := false
	deps := dependencies{
		hostname: func() (string, error) { return "not-malak", nil },
		random:   deterministicRandom(),
		open: func(context.Context, campaignmedia.DeviceIdentity) (openedAttachment, error) {
			opened = true
			return openedAttachment{}, nil
		},
	}
	var stdout, stderr bytes.Buffer
	if exit := run(context.Background(), validArguments(), &stdout, &stderr, deps); exit != exitInvalid {
		t.Fatalf("wrong-host exit = %d, stderr = %s", exit, stderr.String())
	}
	if opened {
		t.Fatal("wrong-host run opened a device")
	}

	for name, mutate := range map[string]func([]string) []string{
		"missing disk GUID": func(arguments []string) []string { return arguments[:2] },
		"duplicate leg":     func(arguments []string) []string { return append(arguments, "--leg", "malak-sd") },
		"duplicate disk GUID": func(arguments []string) []string {
			return append(arguments, "--disk-guid", testDiskGUID)
		},
		"removed capture option": func(arguments []string) []string {
			return append(arguments, "--capture-id", expectedCaptureID())
		},
		"removed output option": func(arguments []string) []string {
			return append(arguments, "--output", "/tmp/recovery.json")
		},
		"unknown device option": func(arguments []string) []string { return append(arguments, "--device", "/dev/sda") },
		"positional selector":   func(arguments []string) []string { return append(arguments, "/dev/sda") },
		"invalid asserted GUID": func(arguments []string) []string {
			copy := append([]string(nil), arguments...)
			copy[3] = strings.ToUpper(testDiskGUID)
			return copy
		},
		"unsupported leg": func(arguments []string) []string {
			copy := append([]string(nil), arguments...)
			copy[1] = "arbitrary-device"
			return copy
		},
	} {
		t.Run(name, func(t *testing.T) {
			stdout.Reset()
			stderr.Reset()
			if exit := run(context.Background(), mutate(validArguments()), &stdout, &stderr, deps); exit != exitUsage {
				t.Fatalf("exit = %d, want %d; stderr = %s", exit, exitUsage, stderr.String())
			}
			if stdout.Len() != 0 || stderr.Len() == 0 || opened {
				t.Fatalf("stdout=%q stderr=%q opened=%v", stdout.String(), stderr.String(), opened)
			}
		})
	}
}

func TestRunFailsClosedAtEachAttachmentBoundary(t *testing.T) {
	for failAt := 1; failAt <= 3; failAt++ {
		t.Run(string(rune('0'+failAt)), func(t *testing.T) {
			device := &inertDevice{}
			revalidations, inspections, verifications, encodes := 0, 0, 0, 0
			deps := dependencies{
				hostname: func() (string, error) { return campaignmedia.MalakSDHostname, nil },
				random:   deterministicRandom(),
				open: func(context.Context, campaignmedia.DeviceIdentity) (openedAttachment, error) {
					return openedAttachment{reader: device, revalidate: func(context.Context) error {
						revalidations++
						if revalidations == failAt {
							return errors.New("attachment changed")
						}
						return nil
					}}, nil
				},
				inspect: func(io.ReaderAt, campaignmedia.DeviceIdentity, string, []campaignmedia.PlannedPayloadRange) (campaignmedia.InitialGPTRecoveryEnvelope, error) {
					inspections++
					return campaignmedia.InitialGPTRecoveryEnvelope{}, nil
				},
				verify: func(campaignmedia.InitialGPTRecoveryEnvelope, io.ReaderAt) error {
					verifications++
					return nil
				},
				encode: func(campaignmedia.InitialGPTRecoveryEnvelope) ([]byte, error) {
					encodes++
					return []byte("{}"), nil
				},
			}
			var stdout, stderr bytes.Buffer
			if exit := run(context.Background(), validArguments(), &stdout, &stderr, deps); exit != exitInvalid {
				t.Fatalf("exit = %d, stderr = %s", exit, stderr.String())
			}
			wantInspections := 1
			if failAt == 1 {
				wantInspections = 0
			}
			wantVerifications := 1
			if failAt < 3 {
				wantVerifications = 0
			}
			if inspections != wantInspections || verifications != wantVerifications || encodes != 0 || stdout.Len() != 0 || device.closes != 1 {
				t.Fatalf("inspect/verify/encode/stdout/close = %d/%d/%d/%q/%d", inspections, verifications, encodes, stdout.String(), device.closes)
			}
		})
	}
}

func TestRunDoesNotEmitAnUnverifiedEnvelope(t *testing.T) {
	device := &inertDevice{}
	deps := dependencies{
		hostname: func() (string, error) { return campaignmedia.MalakSDHostname, nil },
		random:   deterministicRandom(),
		open: func(context.Context, campaignmedia.DeviceIdentity) (openedAttachment, error) {
			return openedAttachment{reader: device, revalidate: func(context.Context) error { return nil }}, nil
		},
		inspect: func(io.ReaderAt, campaignmedia.DeviceIdentity, string, []campaignmedia.PlannedPayloadRange) (campaignmedia.InitialGPTRecoveryEnvelope, error) {
			return campaignmedia.InitialGPTRecoveryEnvelope{}, nil
		},
		verify: func(campaignmedia.InitialGPTRecoveryEnvelope, io.ReaderAt) error {
			return errors.New("device changed between reads")
		},
		encode: func(campaignmedia.InitialGPTRecoveryEnvelope) ([]byte, error) {
			t.Fatal("encode called after verification failure")
			return nil, nil
		},
	}
	var stdout, stderr bytes.Buffer
	if exit := run(context.Background(), validArguments(), &stdout, &stderr, deps); exit != exitInvalid {
		t.Fatalf("exit = %d, stderr = %s", exit, stderr.String())
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "repeated range read verification") || device.closes != 1 {
		t.Fatalf("stdout=%q stderr=%q closes=%d", stdout.String(), stderr.String(), device.closes)
	}
}

func TestCaptureIDIsGeneratedInternallyFromExactly32RandomBytes(t *testing.T) {
	random := bytes.NewReader(append(bytes.Repeat([]byte{0x42}, 32), 0xff))
	captureID, err := newCaptureID(random)
	if err != nil {
		t.Fatal(err)
	}
	if captureID != "capture:"+strings.Repeat("42", 32) || random.Len() != 1 {
		t.Fatalf("capture ID/random remainder = %q/%d", captureID, random.Len())
	}
	if _, err := newCaptureID(bytes.NewReader(make([]byte, 31))); err == nil {
		t.Fatal("short random source was accepted")
	}
}

func TestFixedInspectionInputsFixBothDeviceGeometries(t *testing.T) {
	for _, test := range []struct {
		leg      campaignmedia.Leg
		selector string
		hostname string
		capacity uint64
		ranges   []campaignmedia.PlannedPayloadRange
	}{
		{
			leg: campaignmedia.LegMalakSD, selector: campaignmedia.MalakSDSelector,
			hostname: campaignmedia.MalakSDHostname, capacity: campaignmedia.MalakSDCapacityBytes,
			ranges: []campaignmedia.PlannedPayloadRange{
				{Role: campaignmedia.PartitionBootFilesystem, PartitionNumber: 1, OffsetBytes: campaignmedia.MalakSDBootStartBytes, SizeBytes: campaignmedia.MalakSDBootCapacityBytes},
				{Role: campaignmedia.PartitionRootData, PartitionNumber: 2, OffsetBytes: campaignmedia.MalakSDRootDataStartBytes, SizeBytes: campaignmedia.MalakSDRootDataCapacityBytes},
				{Role: campaignmedia.PartitionRootHash, PartitionNumber: 3, OffsetBytes: campaignmedia.MalakSDRootHashStartBytes, SizeBytes: campaignmedia.MalakSDRootHashCapacityBytes},
			},
		},
		{
			leg: campaignmedia.LegPiLocalNVMe, selector: campaignmedia.PiLocalNVMeSelector,
			hostname: campaignmedia.PiLocalNVMeHostname, capacity: campaignmedia.PiLocalNVMeCapacityBytes,
			ranges: []campaignmedia.PlannedPayloadRange{{
				Role: campaignmedia.PartitionReleaseFilesystem, PartitionNumber: 1,
				OffsetBytes: campaignmedia.PiLocalNVMeReleaseStartBytes, SizeBytes: campaignmedia.PiLocalNVMeReleaseCapacityBytes,
			}},
		},
	} {
		identity, planned, err := fixedInspectionInputs(test.leg, testDiskGUID)
		if err != nil {
			t.Fatal(err)
		}
		if identity.Selector != test.selector || identity.Hostname != test.hostname || identity.CapacityBytes != test.capacity || !reflect.DeepEqual(planned, test.ranges) {
			t.Fatalf("leg %q identity=%#v planned=%#v", test.leg, identity, planned)
		}
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("stdout closed") }

func TestRunClosesAttachmentBeforeWritingStdout(t *testing.T) {
	device := &inertDevice{}
	deps := dependencies{
		hostname: func() (string, error) { return campaignmedia.MalakSDHostname, nil },
		random:   deterministicRandom(),
		open: func(context.Context, campaignmedia.DeviceIdentity) (openedAttachment, error) {
			return openedAttachment{reader: device, revalidate: func(context.Context) error { return nil }}, nil
		},
		inspect: func(io.ReaderAt, campaignmedia.DeviceIdentity, string, []campaignmedia.PlannedPayloadRange) (campaignmedia.InitialGPTRecoveryEnvelope, error) {
			return campaignmedia.InitialGPTRecoveryEnvelope{}, nil
		},
		verify: func(campaignmedia.InitialGPTRecoveryEnvelope, io.ReaderAt) error { return nil },
		encode: func(campaignmedia.InitialGPTRecoveryEnvelope) ([]byte, error) { return []byte("{}"), nil },
	}
	var stderr bytes.Buffer
	if exit := run(context.Background(), validArguments(), failingWriter{}, &stderr, deps); exit != exitInvalid {
		t.Fatalf("exit = %d, stderr = %s", exit, stderr.String())
	}
	if device.closes != 1 || !strings.Contains(stderr.String(), "write canonical envelope to stdout") {
		t.Fatalf("closes=%d stderr=%q", device.closes, stderr.String())
	}
}
