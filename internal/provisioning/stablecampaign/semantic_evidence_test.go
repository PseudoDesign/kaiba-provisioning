package stablecampaign

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/verifierevents"
)

var _ interface {
	RequirePlannedClaimClosure(Plan, EvidenceConsistencyReport) error
} = ExecutionResult{}

func TestSemanticRecordContractsAreStrictCanonicalBoundedAndDomainSeparated(t *testing.T) {
	plan := validPlan(t)
	context, err := NewEvidenceRecordContext(plan, 1, testCaptureID(1200))
	if err != nil {
		t.Fatal(err)
	}
	partitions := semanticMediaPartitions(1)
	records := []struct {
		name      string
		maximum   int
		canonical func() ([]byte, error)
		parse     func([]byte) error
		digest    func() (bundle.Digest, error)
	}{
		{
			name: "media readback", maximum: MaximumSemanticRecordBytes,
			canonical: (MediaReadbackRecord{
				SchemaVersion: MediaReadbackSchemaV1Alpha1, Context: context, Source: MediaReadbackSource,
				ArtifactSetContentDigest: testDigest(1201), Partitions: partitions,
			}).CanonicalJSON,
			parse: func(encoded []byte) error { _, err := ParseMediaReadbackRecord(encoded); return err },
			digest: (MediaReadbackRecord{
				SchemaVersion: MediaReadbackSchemaV1Alpha1, Context: context, Source: MediaReadbackSource,
				ArtifactSetContentDigest: testDigest(1201), Partitions: partitions,
			}).Digest,
		},
		{
			name: "released OS", maximum: verifierevents.MaxRecordBytes,
			canonical: (ReleasedOSEventRecord{
				SchemaVersion: ReleasedOSEventSchemaV1Alpha1, Context: context, Source: ReleasedOSEventSource,
				Event: ReleasedOSEventReady, PolicyDigest: testDigest(1202), ManifestDigest: testDigest(1203),
				BootstrapPublicKey: semanticPublicKey('a'), OneBootPublicKey: semanticPublicKey('b'),
			}).CanonicalJSON,
			parse: func(encoded []byte) error { _, err := ParseReleasedOSEventRecord(encoded); return err },
			digest: (ReleasedOSEventRecord{
				SchemaVersion: ReleasedOSEventSchemaV1Alpha1, Context: context, Source: ReleasedOSEventSource,
				Event: ReleasedOSEventReady, PolicyDigest: testDigest(1202), ManifestDigest: testDigest(1203),
				BootstrapPublicKey: semanticPublicKey('a'), OneBootPublicKey: semanticPublicKey('b'),
			}).Digest,
		},
		{
			name: "authority audit", maximum: MaximumSemanticRecordBytes,
			canonical: (AuthorityAuditRecord{
				SchemaVersion: AuthorityAuditSchemaV1Alpha1, Context: context, Source: AuthorityAuditSource,
				Event: AuthorityEventAuthorizationIssued, PolicyDigest: testDigest(1202), ManifestDigest: testDigest(1203),
				BootstrapPublicKey: semanticPublicKey('a'), OneBootPublicKey: semanticPublicKey('b'),
			}).CanonicalJSON,
			parse: func(encoded []byte) error { _, err := ParseAuthorityAuditRecord(encoded); return err },
			digest: (AuthorityAuditRecord{
				SchemaVersion: AuthorityAuditSchemaV1Alpha1, Context: context, Source: AuthorityAuditSource,
				Event: AuthorityEventAuthorizationIssued, PolicyDigest: testDigest(1202), ManifestDigest: testDigest(1203),
				BootstrapPublicKey: semanticPublicKey('a'), OneBootPublicKey: semanticPublicKey('b'),
			}).Digest,
		},
		{
			name: "power observation", maximum: MaximumSemanticRecordBytes,
			canonical: (PowerObservationRecord{
				SchemaVersion: PowerObservationSchemaV1Alpha1, Context: context, Source: PowerObservationSource,
				Event: PowerObservationEventColdBoot, ObservationMode: PowerObservationModeManual,
				CompletePowerRemoval: true,
			}).CanonicalJSON,
			parse: func(encoded []byte) error { _, err := ParsePowerObservationRecord(encoded); return err },
			digest: (PowerObservationRecord{
				SchemaVersion: PowerObservationSchemaV1Alpha1, Context: context, Source: PowerObservationSource,
				Event: PowerObservationEventColdBoot, ObservationMode: PowerObservationModeManual,
				CompletePowerRemoval: true,
			}).Digest,
		},
	}

	digests := make(map[bundle.Digest]string, len(records))
	for _, test := range records {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := test.canonical()
			if err != nil {
				t.Fatal(err)
			}
			if err := test.parse(append(append([]byte(nil), encoded...), '\n')); err != nil {
				t.Fatalf("canonical record with one transport LF was rejected: %v", err)
			}

			sourceMarker := []byte(`"source":"`)
			sourceAt := bytes.Index(encoded, sourceMarker)
			if sourceAt < 0 {
				t.Fatal("fixture has no source field")
			}
			sourceValueEnd := sourceAt + len(sourceMarker) + bytes.IndexByte(encoded[sourceAt+len(sourceMarker):], '"')
			completeSource := encoded[sourceAt : sourceValueEnd+1]
			invalid := map[string][]byte{
				"duplicate":          bytes.Replace(encoded, completeSource, append(append([]byte(nil), completeSource...), append([]byte(","), completeSource...)...), 1),
				"null":               bytes.Replace(encoded, completeSource, []byte(`"source":null`), 1),
				"unknown":            bytes.Replace(encoded, []byte(`{"schema_version":`), []byte(`{"unexpected":false,"schema_version":`), 1),
				"whitespace":         append([]byte(" "), encoded...),
				"two newlines":       append(append(append([]byte(nil), encoded...), '\n'), '\n'),
				"trailing":           append(append([]byte(nil), encoded...), []byte(`{}`)...),
				"caller pass":        bytes.Replace(encoded, []byte(`{"schema_version":`), []byte(`{"pass":true,"schema_version":`), 1),
				"caller outcome":     bytes.Replace(encoded, []byte(`{"schema_version":`), []byte(`{"outcome":"pass","schema_version":`), 1),
				"caller disposition": bytes.Replace(encoded, []byte(`{"schema_version":`), []byte(`{"disposition":"released-os-booted","schema_version":`), 1),
				"excessive depth":    bytes.Replace(encoded, []byte(`{"schema_version":`), []byte(`{"unexpected":`+strings.Repeat(`[`, maximumJSONDepth+1)+`false`+strings.Repeat(`]`, maximumJSONDepth+1)+`,"schema_version":`), 1),
				"oversized":          bytes.Repeat([]byte(" "), test.maximum+2),
			}
			for name, candidate := range invalid {
				t.Run(name, func(t *testing.T) {
					if err := test.parse(candidate); err == nil {
						t.Fatal("ambiguous, unauthorized, or noncanonical record was accepted")
					}
				})
			}

			digest, err := test.digest()
			if err != nil {
				t.Fatal(err)
			}
			if previous, duplicate := digests[digest]; duplicate {
				t.Fatalf("record digest domain collided with %s", previous)
			}
			digests[digest] = test.name
		})
	}
}

func TestSemanticEvidenceIsOnlyInternallyConsistentAcrossFixedRunMatrix(t *testing.T) {
	plan := validPlan(t)
	runs, err := ExpectedRuns(plan)
	if err != nil {
		t.Fatal(err)
	}
	for index, spec := range runs {
		t.Run(spec.RunID, func(t *testing.T) {
			result, supplied, declared := semanticEvidenceFixture(t, plan, uint16(index+1), nil)
			report, err := result.CheckEvidenceConsistency(plan, supplied, declared)
			if err != nil {
				t.Fatal(err)
			}
			if report.Assurance != EvidenceConsistencyUnauthenticatedRecords ||
				!report.MediaReadbackConsistent || !report.PowerObservationConsistent {
				t.Fatalf("unexpected consistency report: %#v", report)
			}
			wantAuthority := slices.Contains(spec.RequiredRecordKinds, RecordKindAuthorityAudit)
			wantReleased := slices.Contains(spec.RequiredRecordKinds, RecordKindReleasedOSEvent)
			if report.AuthorityAuditConsistent != wantAuthority || report.ReleasedOSEventConsistent != wantReleased {
				t.Fatalf("consistency check did not cover the exact record set: %#v", report)
			}
			wantSemanticCount := 2
			if wantAuthority {
				wantSemanticCount++
			}
			if wantReleased {
				wantSemanticCount++
			}
			if report.ParsedRecordCount != wantSemanticCount {
				t.Fatalf("parsed %d semantic records, want %d", report.ParsedRecordCount, wantSemanticCount)
			}
			if err := result.RequirePlannedClaimClosure(plan, report); !errors.Is(err, ErrClaimClosureUnavailable) {
				t.Fatalf("claim closure did not fail closed: %v", err)
			}
		})
	}
}

func TestSemanticEvidenceRejectsSelfTrustTransplantsAndWrongRunSemantics(t *testing.T) {
	plan := validPlan(t)
	tests := []struct {
		name     string
		runIndex uint16
		mutate   func(*semanticRecordFixtures)
	}{
		{
			name: "media record differs from declared context", runIndex: 1,
			mutate: func(records *semanticRecordFixtures) { records.media.Partitions[0].Digest = testDigest(13001) },
		},
		{
			name: "record context uses another capture", runIndex: 1,
			mutate: func(records *semanticRecordFixtures) { records.media.Context.CaptureID = testCaptureID(1302) },
		},
		{
			name: "offline run mislabeled as authorization rejection", runIndex: 2,
			mutate: func(records *semanticRecordFixtures) { records.authority.Event = AuthorityEventAuthorizationRejected },
		},
		{
			name: "stale replay audit differs from verifier key", runIndex: 3,
			mutate: func(records *semanticRecordFixtures) { records.authority.BootstrapPublicKey = semanticPublicKey('c') },
		},
		{
			name: "authority policy digest differs from verifier trace", runIndex: 1,
			mutate: func(records *semanticRecordFixtures) { records.authority.PolicyDigest = testDigest(13004) },
		},
		{
			name: "root-data corruption mislabeled as root-hash rejection", runIndex: 13,
			mutate: func(records *semanticRecordFixtures) { records.released.Event = ReleasedOSEventRootHashRejected },
		},
		{
			name: "released OS uses another one-boot key", runIndex: 1,
			mutate: func(records *semanticRecordFixtures) { records.released.OneBootPublicKey = semanticPublicKey('c') },
		},
		{
			name: "released OS manifest differs from verifier trace", runIndex: 12,
			mutate: func(records *semanticRecordFixtures) { records.released.ManifestDigest = testDigest(13005) },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, supplied, declared := semanticEvidenceFixture(t, plan, test.runIndex, test.mutate)
			if _, err := result.CheckEvidenceConsistency(plan, supplied, declared); err == nil {
				t.Fatal("semantically detached or run-inconsistent evidence was accepted")
			}
		})
	}

	t.Run("declared context belongs to another run", func(t *testing.T) {
		result, supplied, declared := semanticEvidenceFixture(t, plan, 1, nil)
		declared.RunIndex = 2
		declared.RunID = "authorization-offline-rejected:authority-offline"
		if _, err := result.CheckEvidenceConsistency(plan, supplied, declared); err == nil {
			t.Fatal("consistency check accepted a declared media context from another run")
		}
	})

	t.Run("semantic record domain digest", func(t *testing.T) {
		result, supplied, declared := semanticEvidenceFixture(t, plan, 1, nil)
		changed := cloneExecutionResult(result)
		changed.RecordRefs[0].RecordDigest = testDigest(13003)
		context := newEvidenceBindingContext(plan, mustExpectedRun(t, plan, 1), changed.CaptureID)
		raw, ok := rawBindingByRole(changed.RawFiles, changed.RecordRefs[0].RawRole)
		if !ok {
			t.Fatal("fixture lost media raw binding")
		}
		recordBindingDigest, err := deriveRecordBindingDigest(context, changed.RecordRefs[0], raw.RawBindingDigest)
		if err != nil {
			t.Fatal(err)
		}
		changed.RecordRefs[0].RecordBindingDigest = recordBindingDigest
		changed.ResultDigest = ""
		changed, err = changed.Seal(plan)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := changed.CheckEvidenceConsistency(plan, supplied, declared); err == nil {
			t.Fatal("consistency check accepted a wrong domain record digest")
		}
	})
}

func TestSemanticRecordsCannotClaimCaptureAuthenticationOrFreshness(t *testing.T) {
	plan := validPlan(t)
	context, err := NewEvidenceRecordContext(plan, 1, testCaptureID(1400))
	if err != nil {
		t.Fatal(err)
	}
	media := MediaReadbackRecord{
		SchemaVersion: MediaReadbackSchemaV1Alpha1, Context: context, Source: MediaReadbackSource,
		ArtifactSetContentDigest: testDigest(1401), Partitions: semanticMediaPartitions(2),
		CaptureAuthenticated: true,
	}
	if err := media.Validate(); err == nil {
		t.Fatal("media record claimed authenticated capture")
	}
	power := PowerObservationRecord{
		SchemaVersion: PowerObservationSchemaV1Alpha1, Context: context, Source: PowerObservationSource,
		Event: PowerObservationEventColdBoot, ObservationMode: PowerObservationModeManual,
		CompletePowerRemoval: true, FreshnessEstablished: true,
	}
	if err := power.Validate(); err == nil {
		t.Fatal("manual observation claimed freshness")
	}

	authority := AuthorityAuditRecord{
		SchemaVersion: AuthorityAuditSchemaV1Alpha1, Context: context, Source: AuthorityAuditSource,
		Event: AuthorityEventAuthorizationIssued, PolicyDigest: testDigest(1402), ManifestDigest: testDigest(1403),
		BootstrapPublicKey: semanticPublicKey('a'), OneBootPublicKey: semanticPublicKey('a'),
	}
	if err := authority.Validate(); err == nil {
		t.Fatal("authority record reused the bootstrap key as the one-boot key")
	}
	released := ReleasedOSEventRecord{
		SchemaVersion: ReleasedOSEventSchemaV1Alpha1, Context: context, Source: ReleasedOSEventSource,
		Event: ReleasedOSEventReady, PolicyDigest: testDigest(1402), ManifestDigest: testDigest(1403),
		BootstrapPublicKey: semanticPublicKey('a'), OneBootPublicKey: semanticPublicKey('a'),
	}
	if err := released.Validate(); err == nil {
		t.Fatal("released-OS record reused the bootstrap key as the one-boot key")
	}
	if _, err := collectVerifierPublicDetails([]verifierevents.Record{
		{BootstrapPublicKey: semanticPublicKey('a')},
		{OneBootPublicKey: semanticPublicKey('a')},
	}); err == nil {
		t.Fatal("verifier detail collection reused the bootstrap key as the one-boot key")
	}
}

type semanticRecordFixtures struct {
	media     MediaReadbackRecord
	released  *ReleasedOSEventRecord
	authority *AuthorityAuditRecord
	power     PowerObservationRecord
}

func semanticEvidenceFixture(
	t *testing.T,
	plan Plan,
	runIndex uint16,
	mutate func(*semanticRecordFixtures),
) (ExecutionResult, map[RawRole][]byte, DeclaredEvidenceContext) {
	t.Helper()
	spec := mustExpectedRun(t, plan, runIndex)
	captureID := testCaptureID(2000 + runIndex)
	context, err := NewEvidenceRecordContext(plan, runIndex, captureID)
	if err != nil {
		t.Fatal(err)
	}
	partitions := semanticMediaPartitions(int(runIndex) + 10)
	declared := DeclaredEvidenceContext{
		CampaignID: plan.CampaignID, PlanDigest: plan.PlanDigest, RunIndex: runIndex, RunID: spec.RunID,
		ArtifactSetContentDigest: testDigest(1500),
		MediaPartitions:          append([]MediaPartitionBinding(nil), partitions...),
	}
	records := semanticRecordFixtures{
		media: MediaReadbackRecord{
			SchemaVersion: MediaReadbackSchemaV1Alpha1, Context: context, Source: MediaReadbackSource,
			ArtifactSetContentDigest: declared.ArtifactSetContentDigest,
			Partitions:               append([]MediaPartitionBinding(nil), partitions...),
		},
		power: PowerObservationRecord{
			SchemaVersion: PowerObservationSchemaV1Alpha1, Context: context, Source: PowerObservationSource,
			Event: PowerObservationEventColdBoot, ObservationMode: PowerObservationModeManual,
			CompletePowerRemoval: true,
		},
	}

	authorityEvent, authorityRequired, err := authorityEventForRun(spec)
	if err != nil {
		t.Fatal(err)
	}
	if authorityRequired {
		authority := AuthorityAuditRecord{
			SchemaVersion: AuthorityAuditSchemaV1Alpha1, Context: context, Source: AuthorityAuditSource,
			Event: authorityEvent, PolicyDigest: testDigest(9600), ManifestDigest: testDigest(9601),
			BootstrapPublicKey: semanticPublicKey('a'),
		}
		if authorityEvent == AuthorityEventAuthorizationIssued {
			authority.OneBootPublicKey = semanticPublicKey('b')
		}
		records.authority = &authority
	}
	releasedEvent, releasedRequired, err := releasedOSEventForRun(spec)
	if err != nil {
		t.Fatal(err)
	}
	if releasedRequired {
		released := ReleasedOSEventRecord{
			SchemaVersion: ReleasedOSEventSchemaV1Alpha1, Context: context, Source: ReleasedOSEventSource,
			Event: releasedEvent, PolicyDigest: testDigest(9600), ManifestDigest: testDigest(9601),
			BootstrapPublicKey: semanticPublicKey('a'), OneBootPublicKey: semanticPublicKey('b'),
		}
		records.released = &released
	}
	if mutate != nil {
		mutate(&records)
	}

	supplied := make(map[RawRole][]byte, len(spec.RequiredRawRoles))
	mediaRange := semanticEncodedRecord(t, records.media.CanonicalJSON, records.media.Digest, false)
	supplied[RawRoleMediaReadback] = mediaRange.encoded
	powerRange := semanticEncodedRecord(t, records.power.CanonicalJSON, records.power.Digest, false)
	supplied[RawRolePowerObservation] = powerRange.encoded

	var authorityRange semanticEncodedFixture
	if records.authority != nil {
		authorityRange = semanticEncodedRecord(t, records.authority.CanonicalJSON, records.authority.Digest, false)
		supplied[RawRoleAuthorityAudit] = authorityRange.encoded
	}

	var uart bytes.Buffer
	uart.WriteString("bounded firmware diagnostic noise\n")
	emitter, err := verifierevents.New(&uart)
	if err != nil {
		t.Fatal(err)
	}
	verifierRanges := make([]semanticEncodedFixture, 0, len(spec.VerifierTrace))
	for _, expected := range spec.VerifierTrace {
		offset := uint64(uart.Len())
		_, recordDigest, err := emitter.Emit(expected.Event, verifierDetailsFixture(expected.DetailStage, expected.FailureCode))
		if err != nil {
			t.Fatal(err)
		}
		encoded := append([]byte(nil), uart.Bytes()[int(offset):]...)
		verifierRanges = append(verifierRanges, semanticEncodedFixture{
			encoded: encoded, offset: offset, rangeDigest: bundle.Sum(encoded), recordDigest: recordDigest,
		})
	}
	var releasedRange semanticEncodedFixture
	if records.released != nil {
		releasedRange = semanticEncodedRecord(t, records.released.CanonicalJSON, records.released.Digest, true)
		releasedRange.offset = uint64(uart.Len())
		uart.Write(releasedRange.encoded)
	}
	supplied[RawRoleUARTCapture] = append([]byte(nil), uart.Bytes()...)

	rawFiles := make([]RawBinding, len(spec.RequiredRawRoles))
	for index, role := range spec.RequiredRawRoles {
		raw := supplied[role]
		rawFiles[index] = RawBinding{Role: role, Digest: bundle.Sum(raw), SizeBytes: uint64(len(raw))}
	}

	refs := make([]RecordRef, len(spec.RequiredRecordKinds))
	verifierIndex := 0
	for index, kind := range spec.RequiredRecordKinds {
		role, ok := rawRoleForRecordKind(kind)
		if !ok {
			t.Fatalf("fixture has unsupported record kind %q", kind)
		}
		var record semanticEncodedFixture
		switch kind {
		case RecordKindMediaReadback:
			record = mediaRange
		case RecordKindVerifierEvent:
			record = verifierRanges[verifierIndex]
			verifierIndex++
		case RecordKindReleasedOSEvent:
			record = releasedRange
		case RecordKindAuthorityAudit:
			record = authorityRange
		case RecordKindPowerObservation:
			record = powerRange
		}
		refs[index] = RecordRef{
			Kind: kind, RawRole: role, OffsetBytes: record.offset, SizeBytes: uint64(len(record.encoded)),
			RawRangeDigest: record.rangeDigest, RecordDigest: record.recordDigest,
		}
	}
	result, err := NewExecutionResult(plan, runIndex, captureID, rawFiles, refs)
	if err != nil {
		t.Fatalf("construct semantic evidence result: %v", err)
	}
	return result, supplied, declared
}

type semanticEncodedFixture struct {
	encoded      []byte
	offset       uint64
	rangeDigest  bundle.Digest
	recordDigest bundle.Digest
}

func semanticEncodedRecord(
	t *testing.T,
	canonical func() ([]byte, error),
	digest func() (bundle.Digest, error),
	transportLF bool,
) semanticEncodedFixture {
	t.Helper()
	encoded, err := canonical()
	if err != nil {
		t.Fatal(err)
	}
	if transportLF {
		encoded = append(encoded, '\n')
	}
	recordDigest, err := digest()
	if err != nil {
		t.Fatal(err)
	}
	return semanticEncodedFixture{
		encoded: append([]byte(nil), encoded...), rangeDigest: bundle.Sum(encoded), recordDigest: recordDigest,
	}
}

func semanticMediaPartitions(seed int) []MediaPartitionBinding {
	roles := []MediaPartitionRole{
		MediaPartitionBootFilesystem,
		MediaPartitionReleaseFilesystem,
		MediaPartitionRootData,
		MediaPartitionRootHash,
	}
	result := make([]MediaPartitionBinding, len(roles))
	for index, role := range roles {
		result[index] = MediaPartitionBinding{
			Role: role, Digest: testDigest(seed*100 + index + 1), SizeBytes: uint64((index + 1) * 4096),
		}
	}
	return result
}

func semanticPublicKey(character byte) string {
	return "ed25519:" + strings.Repeat(string(character), 64)
}

func mustExpectedRun(t *testing.T, plan Plan, runIndex uint16) RunSpec {
	t.Helper()
	runs, err := ExpectedRuns(plan)
	if err != nil {
		t.Fatal(err)
	}
	if runIndex == 0 || int(runIndex) > len(runs) {
		t.Fatalf("run index %d is outside the fixture matrix", runIndex)
	}
	return runs[runIndex-1]
}

func TestDeclaredContextAndRecordsContainNoPathOrOutcomeFields(t *testing.T) {
	plan := validPlan(t)
	result, supplied, declared := semanticEvidenceFixture(t, plan, 1, nil)
	if _, err := result.CheckEvidenceConsistency(plan, supplied, declared); err != nil {
		t.Fatal(err)
	}
	for role, encoded := range supplied {
		if role == RawRoleUARTCapture {
			continue
		}
		for _, forbidden := range []string{`"path"`, `"pass"`, `"outcome"`, `"disposition"`} {
			if bytes.Contains(encoded, []byte(forbidden)) {
				t.Fatalf("%s record contains caller-controlled field %s", role, forbidden)
			}
		}
	}
	if got := fmt.Sprintf("%#v", declared); strings.Contains(got, "/dev/") || strings.Contains(got, "/tmp/") {
		t.Fatal("path-free declared context contains a host or device path")
	}
}

func TestExecutionAndConsistencyContractsCannotRepresentClaimClosure(t *testing.T) {
	executionType := reflect.TypeOf(ExecutionResult{})
	if _, exists := executionType.FieldByName("Claims"); exists {
		t.Fatal("ExecutionResult still exposes a fulfilled-looking Claims field")
	}
	planned, exists := executionType.FieldByName("PlannedClaims")
	if !exists || planned.Tag.Get("json") != "planned_claims" {
		t.Fatal("ExecutionResult does not expose planned claims with the explicit planned_claims tag")
	}

	reportType := reflect.TypeOf(EvidenceConsistencyReport{})
	for index := 0; index < reportType.NumField(); index++ {
		name := strings.ToLower(reportType.Field(index).Name)
		for _, prohibited := range []string{"claim", "disposition", "outcome", "pass"} {
			if strings.Contains(name, prohibited) {
				t.Fatalf("consistency report field %q can represent %s closure", reportType.Field(index).Name, prohibited)
			}
		}
	}

	plan := validPlan(t)
	result, supplied, declared := semanticEvidenceFixture(t, plan, 1, nil)
	report, err := result.CheckEvidenceConsistency(plan, supplied, declared)
	if err != nil {
		t.Fatal(err)
	}
	encodedResult, err := result.CanonicalJSON(plan)
	if err != nil {
		t.Fatal(err)
	}
	encodedReport, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for label, encoded := range map[string][]byte{
		"execution result":   encodedResult,
		"consistency report": encodedReport,
	} {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &fields); err != nil {
			t.Fatal(err)
		}
		for _, prohibited := range []string{
			"claims", "pass", "outcome", "disposition", "validated_claims", "claim_results",
		} {
			if _, exists := fields[prohibited]; exists {
				t.Fatalf("%s exposes prohibited claim-closure field %q", label, prohibited)
			}
		}
	}
	if err := result.RequirePlannedClaimClosure(plan, report); !errors.Is(err, ErrClaimClosureUnavailable) {
		t.Fatalf("claim closure did not return the fail-closed sentinel: %v", err)
	}
}

func TestEvidenceConsistencySnapshotsCallerOwnedSlices(t *testing.T) {
	plan := validPlan(t)
	result, supplied, _ := semanticEvidenceFixture(t, plan, 1, nil)
	snapshot, err := snapshotSuppliedEvidence(result, plan, supplied)
	if err != nil {
		t.Fatal(err)
	}
	original := snapshot[RawRoleMediaReadback][0]
	supplied[RawRoleMediaReadback][0] ^= 0xff
	if snapshot[RawRoleMediaReadback][0] != original {
		t.Fatal("evidence snapshot aliases a caller-owned raw slice")
	}
}
