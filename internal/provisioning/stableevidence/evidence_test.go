package stableevidence

import (
	"bytes"
	"strings"
	"testing"
)

const digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestEvidenceRoundTrip(t *testing.T) {
	evidence := validEvidence()
	encoded, err := evidence.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(append(encoded, '\n'))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.EvidenceID != evidence.EvidenceID {
		t.Fatalf("unexpected parsed evidence %#v", parsed)
	}
}

func TestEvidenceRejectsProductionAndPrivateMaterialClaims(t *testing.T) {
	evidence := validEvidence()
	evidence.ProductionReady = true
	if err := evidence.Validate(); err == nil {
		t.Fatal("production-ready claim was accepted")
	}
	evidence = validEvidence()
	evidence.PrivateMaterialPresent = true
	if err := evidence.Validate(); err == nil {
		t.Fatal("private-material evidence was accepted")
	}
}

func TestValidatedEvidenceRequiresEveryTestToPass(t *testing.T) {
	evidence := validEvidence()
	evidence.TestResults[0].Result = "blocked"
	if err := evidence.Validate(); err == nil {
		t.Fatal("validated evidence with a blocked test was accepted")
	}
	evidence.Outcome = OutcomeBlocked
	if err := evidence.Validate(); err != nil {
		t.Fatalf("blocked evidence rejected: %v", err)
	}
}

func TestEvidenceRejectsDuplicateKeysAndNoncanonicalOrder(t *testing.T) {
	evidence := validEvidence()
	encoded, err := evidence.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	duplicate := bytes.Replace(encoded, []byte(`"evidence_id":"spike-1"`), []byte(`"evidence_id":"spike-1","evidence_id":"spike-2"`), 1)
	if _, err := Parse(duplicate); err == nil {
		t.Fatal("duplicate JSON key was accepted")
	}
	evidence.TestResults[0], evidence.TestResults[1] = evidence.TestResults[1], evidence.TestResults[0]
	if err := evidence.Validate(); err == nil || !strings.Contains(err.Error(), "entry 0") {
		t.Fatalf("noncanonical test order accepted: %v", err)
	}
}

func TestValidatedEvidenceRequiresExactCampaign(t *testing.T) {
	evidence := validEvidence()
	evidence.TestResults = evidence.TestResults[:len(evidence.TestResults)-1]
	if err := evidence.Validate(); err == nil || !strings.Contains(err.Error(), "complete mandatory") {
		t.Fatalf("incomplete validated campaign accepted: %v", err)
	}
	evidence = validEvidence()
	evidence.TestResults[0].TestID = "unreviewed-test"
	if err := evidence.Validate(); err == nil || !strings.Contains(err.Error(), "entry 0") {
		t.Fatalf("unknown campaign test accepted: %v", err)
	}
}

func TestEvidenceRejectsFreeFormVersionFields(t *testing.T) {
	evidence := validEvidence()
	evidence.Software.KernelVersion = "-----BEGIN PRIVATE KEY-----"
	if err := evidence.Validate(); err == nil {
		t.Fatal("free-form kernel version was accepted")
	}
}

func validEvidence() Evidence {
	return Evidence{
		SchemaVersion:   SchemaV1Alpha1,
		EvidenceID:      "spike-1",
		RecordedAt:      "2026-09-08T12:00:00Z",
		Classification:  Classification,
		CampaignProfile: CampaignV1Alpha1,
		Hardware: Hardware{
			DeviceClass: DeviceClass, BoardRevision: BoardRevision, SerialRedacted: true,
			CustomerKeyState: "development-key-fused", CustomerKeyHash: DevelopmentCustomerKeyHash,
			OTPChanged: false, EEPROMChanged: false,
		},
		Software: Software{
			SourceRevision: strings.Repeat("a", 40), VerifierVersion: 1,
			VerifierArtifactDigest: digest, PolicyDigest: digest, ManifestDigest: digest,
			KernelVersion: "6.18.34", FirmwareRevision: strings.Repeat("b", 40), KexecVersion: "2.0.30",
		},
		Outcome: OutcomeValidated,
		TestResults: func() []TestResult {
			results := make([]TestResult, 0, len(mandatoryTestIDs))
			for _, testID := range mandatoryTestIDs {
				results = append(results, TestResult{TestID: testID, Result: "pass"})
			}
			return results
		}(),
		OrderedEvents: []OrderedEvent{{
			Source: "verifier-uart", Event: "verifier-started", RecordDigest: digest,
		}},
		PrivateMaterialPresent: false,
		ProductionReady:        false,
	}
}
