package campaignqualification

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stablecampaign"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/verifierevents"
)

type testAdmission struct {
	count int
	err   error
}

func (admission *testAdmission) Consume(Session, bundle.Digest) error {
	admission.count++
	return admission.err
}

type fixture struct {
	expectation Expectation
	session     Session
	policy      TrustPolicy
	result      stablecampaign.ExecutionResult
	raw         map[stablecampaign.RawRole][]byte
	witnesses   []SignedWitness
	supporting  map[string][]byte
	private     []ed25519.PrivateKey
	admission   testAdmission
}

func digest(value string) bundle.Digest { return bundle.Sum([]byte(value)) }

// This fixture exercises authentication and admission, not payload preparation
// or physical observation. Its entire campaign and all evidence are synthetic.
func newFixture(t *testing.T, index uint16) *fixture {
	t.Helper()
	encoded, err := os.ReadFile("testdata/synthetic-plan.json")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := stablecampaign.ParsePlan(encoded)
	if err != nil {
		t.Fatal(err)
	}
	runs, _ := stablecampaign.ExpectedRuns(plan)
	run := runs[index-1]
	f := &fixture{raw: map[stablecampaign.RawRole][]byte{}, supporting: map[string][]byte{}}
	v := expectationRecord{SchemaVersion: ExpectationSchema, CampaignID: plan.CampaignID, PlanDigest: plan.PlanDigest, RunIndex: index, RunID: run.RunID,
		DeviceFingerprint: digest("synthetic-board"), ProfileDigest: digest("synthetic-profile"), ArtifactSetContentDigest: digest("synthetic-baseline"),
		MaterializationDigest: digest(fmt.Sprintf("synthetic-materialization-%d", index)), LayoutDigest: digest("synthetic-layout"),
		PolicyDigest: digest("synthetic-policy"), ManifestDigest: digest("synthetic-manifest"), KernelCommandLine: "console=ttyAMA10,115200n8 ro"}
	for _, role := range []stablecampaign.MediaPartitionRole{"boot-filesystem", "release-filesystem", "root-data", "root-hash"} {
		v.MediaPartitions = append(v.MediaPartitions, stablecampaign.MediaPartitionBinding{Role: role, Digest: digest(string(role)), SizeBytes: 512})
	}
	b, _ := json.Marshal(v)
	v.ExpectationDigest = domainDigest("kaiba.provisioning.rpi5-campaign-qualification-expectation.v1alpha1", b)
	f.expectation = Expectation{value: v, plan: plan}
	context, err := stablecampaign.NewEvidenceRecordContext(plan, index, stablecampaign.CaptureID(fmt.Sprintf("capture:%064x", index)))
	if err != nil {
		t.Fatal(err)
	}
	f.session = Session{Context: context, DeviceFingerprint: v.DeviceFingerprint, ProfileDigest: v.ProfileDigest, ExpectationDigest: v.ExpectationDigest, NotBefore: 1000, Deadline: 2000}
	bootstrap, oneBoot := "ed25519:"+strings.Repeat("a", 64), "ed25519:"+strings.Repeat("b", 64)
	refs := []stablecampaign.RecordRef{}
	add := func(kind stablecampaign.RecordKind, role stablecampaign.RawRole, encoded []byte, recordDigest bundle.Digest) {
		refs = append(refs, stablecampaign.RecordRef{Kind: kind, RawRole: role, OffsetBytes: uint64(len(f.raw[role])), SizeBytes: uint64(len(encoded)), RawRangeDigest: bundle.Sum(encoded), RecordDigest: recordDigest})
		f.raw[role] = append(f.raw[role], encoded...)
	}
	media := stablecampaign.MediaReadbackRecord{SchemaVersion: stablecampaign.MediaReadbackSchemaV1Alpha1, Context: context, Source: stablecampaign.MediaReadbackSource, ArtifactSetContentDigest: v.ArtifactSetContentDigest, Partitions: v.MediaPartitions}
	b, err = media.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	d, _ := media.Digest()
	add(stablecampaign.RecordKindMediaReadback, stablecampaign.RawRoleMediaReadback, b, d)
	var uart bytes.Buffer
	emitter, _ := verifierevents.New(&uart)
	for _, event := range run.VerifierTrace {
		details := verifierevents.Details{FailureCode: event.FailureCode}
		if event.DetailStage != stablecampaign.VerifierDetailNone {
			details.PolicyDigest, details.ManifestDigest = v.PolicyDigest, v.ManifestDigest
		}
		if event.DetailStage == stablecampaign.VerifierDetailBootstrap || event.DetailStage == stablecampaign.VerifierDetailAuthorization {
			details.BootstrapPublicKey = bootstrap
		}
		if event.DetailStage == stablecampaign.VerifierDetailAuthorization {
			details.OneBootPublicKey = oneBoot
		}
		offset := uart.Len()
		_, d, err := emitter.Emit(event.Event, details)
		if err != nil {
			t.Fatal(err)
		}
		add(stablecampaign.RecordKindVerifierEvent, stablecampaign.RawRoleUARTCapture, bytes.Clone(uart.Bytes()[offset:]), d)
	}
	if run.ExpectedDisposition != stablecampaign.DispositionVerifierRejected {
		event := stablecampaign.ReleasedOSEventReady
		if run.ExpectedDisposition == stablecampaign.DispositionReleasedOSRejected {
			event = stablecampaign.ReleasedOSEventRootDataRejected
			if run.PlannedClaims[0].SubcaseID == "root-hash" {
				event = stablecampaign.ReleasedOSEventRootHashRejected
			}
		}
		released := stablecampaign.ReleasedOSEventRecord{SchemaVersion: stablecampaign.ReleasedOSEventSchemaV1Alpha1, Context: context, Source: stablecampaign.ReleasedOSEventSource, Event: event,
			PolicyDigest: v.PolicyDigest, ManifestDigest: v.ManifestDigest, BootstrapPublicKey: bootstrap, OneBootPublicKey: oneBoot}
		b, err = released.CanonicalJSON()
		if err != nil {
			t.Fatal(err)
		}
		d, _ = released.Digest()
		add(stablecampaign.RecordKindReleasedOSEvent, stablecampaign.RawRoleUARTCapture, append(b, '\n'), d)
	}
	if run.VerifierTerminal.FailureCode != "release-verification-failed" {
		event := stablecampaign.AuthorityEventAuthorizationIssued
		if index == 2 {
			event = stablecampaign.AuthorityEventOffline
		}
		if index == 3 {
			event = stablecampaign.AuthorityEventAuthorizationRejected
		}
		authority := stablecampaign.AuthorityAuditRecord{SchemaVersion: stablecampaign.AuthorityAuditSchemaV1Alpha1, Context: context, Source: stablecampaign.AuthorityAuditSource, Event: event,
			PolicyDigest: v.PolicyDigest, ManifestDigest: v.ManifestDigest, BootstrapPublicKey: bootstrap}
		if event == stablecampaign.AuthorityEventAuthorizationIssued {
			authority.OneBootPublicKey = oneBoot
		}
		b, err = authority.CanonicalJSON()
		if err != nil {
			t.Fatal(err)
		}
		d, _ = authority.Digest()
		add(stablecampaign.RecordKindAuthorityAudit, stablecampaign.RawRoleAuthorityAudit, b, d)
	}
	power := stablecampaign.PowerObservationRecord{SchemaVersion: stablecampaign.PowerObservationSchemaV1Alpha1, Context: context, Source: stablecampaign.PowerObservationSource,
		Event: stablecampaign.PowerObservationEventColdBoot, ObservationMode: stablecampaign.PowerObservationModeManual, CompletePowerRemoval: true}
	b, err = power.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	d, _ = power.Digest()
	add(stablecampaign.RecordKindPowerObservation, stablecampaign.RawRolePowerObservation, b, d)
	bindings := []stablecampaign.RawBinding{}
	for _, role := range run.RequiredRawRoles {
		bindings = append(bindings, stablecampaign.RawBinding{Role: role, Digest: bundle.Sum(f.raw[role]), SizeBytes: uint64(len(f.raw[role]))})
	}
	f.result, err = stablecampaign.NewExecutionResult(plan, index, context.CaptureID, bindings, refs)
	if err != nil {
		t.Fatal(err)
	}
	requirements, _ := stablecampaign.RequiredClaimWitnesses(plan, index)
	kinds := []stablecampaign.ClaimWitnessKind{}
	for _, requirement := range requirements {
		for _, kind := range requirement.Kinds {
			if !slices.Contains(kinds, kind) {
				kinds = append(kinds, kind)
			}
		}
	}
	for _, role := range []string{CollectorRole, ReviewerRole} {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		f.private = append(f.private, private)
		f.policy.Keys = append(f.policy.Keys, TrustedKey{ID: role, Role: role, PublicKey: hex.EncodeToString(public), Kinds: kinds})
	}
	for _, kind := range kinds {
		statement := WitnessStatement{SchemaVersion: WitnessSchema, Session: f.session, ResultDigest: f.result.ResultDigest, Kind: kind, Conclusion: ReviewedSatisfied, CollectedAt: 1100, ReviewedAt: 1200}
		for _, name := range witnessSources[kind] {
			var encoded []byte
			switch {
			case rawName(name):
				encoded = f.raw[stablecampaign.RawRole(name)]
			case name == "expectation":
				encoded, _ = f.expectation.CanonicalJSON()
			default:
				encoded = []byte("synthetic reviewed evidence")
				if strings.Contains(name, "command-line") {
					encoded = []byte(v.KernelCommandLine)
				}
				f.supporting[name] = encoded
			}
			statement.Evidence = append(statement.Evidence, EvidenceBinding{Name: name, Digest: bundle.Sum(encoded), SizeBytes: uint64(len(encoded))})
		}
		f.witnesses = append(f.witnesses, SignedWitness{Statement: statement})
	}
	f.sign(t)
	return f
}

func (f *fixture) sign(t *testing.T) {
	t.Helper()
	for index := range f.witnesses {
		f.witnesses[index].Signatures = nil
		for i, role := range []string{CollectorRole, ReviewerRole} {
			preimage, err := f.witnesses[index].Statement.SigningBytes(role)
			if err != nil {
				t.Fatal(err)
			}
			f.witnesses[index].Signatures = append(f.witnesses[index].Signatures, WitnessSignature{KeyID: role, Role: role, Signature: hex.EncodeToString(ed25519.Sign(f.private[i], preimage))})
		}
	}
}

func (f *fixture) validate() (Report, error) {
	return Validate(f.expectation, f.session, 1300, f.policy, f.result, f.raw, f.witnesses, f.supporting, &f.admission)
}

func TestReviewedAcceptanceCoversAll33RunsAnd37Claims(t *testing.T) {
	claims := 0
	for index := uint16(1); index <= 33; index++ {
		f := newFixture(t, index)
		report, err := f.validate()
		if err != nil {
			t.Fatalf("run %d: %v", index, err)
		}
		claims += len(report.value.ReviewedClaims)
		if f.admission.count != 1 || report.value.ProductionReady || report.value.EnrollmentReady {
			t.Fatal("invalid admission or readiness assertion")
		}
	}
	if claims != 37 {
		t.Fatalf("got %d reviewed claims, want 37", claims)
	}
}

func TestRejectsDetachedIncompleteAndUnauthenticatedEvidenceBeforeAdmission(t *testing.T) {
	tests := map[string]func(*fixture){
		"missing raw": func(f *fixture) { delete(f.raw, stablecampaign.RawRoleUARTCapture) },
		"truncated raw": func(f *fixture) {
			f.raw[stablecampaign.RawRoleUARTCapture] = f.raw[stablecampaign.RawRoleUARTCapture][:10]
		},
		"altered raw":       func(f *fixture) { f.raw[stablecampaign.RawRoleUARTCapture][0] ^= 1 },
		"missing witness":   func(f *fixture) { f.witnesses = f.witnesses[1:] },
		"duplicate witness": func(f *fixture) { f.witnesses[1] = f.witnesses[0] },
		"wrong run":         func(f *fixture) { f.session.Context.RunIndex = 2 },
		"wrong capture": func(f *fixture) {
			f.session.Context.CaptureID = stablecampaign.CaptureID("capture:" + strings.Repeat("b", 64))
		},
		"wrong board":                     func(f *fixture) { f.session.DeviceFingerprint = digest("other-board") },
		"wrong profile":                   func(f *fixture) { f.session.ProfileDigest = digest("other-profile") },
		"wrong expectation":               func(f *fixture) { f.session.ExpectationDigest = digest("other-expectation") },
		"expired":                         func(f *fixture) { f.session.Deadline = 1250 },
		"unsigned":                        func(f *fixture) { f.witnesses[0].Signatures = nil },
		"unknown reviewer":                func(f *fixture) { f.witnesses[0].Signatures[1].KeyID = "attacker" },
		"forged signature":                func(f *fixture) { f.witnesses[0].Signatures[1].Signature = strings.Repeat("0", 128) },
		"signature role reuse":            func(f *fixture) { f.witnesses[0].Signatures[1] = f.witnesses[0].Signatures[0] },
		"key role reuse":                  func(f *fixture) { f.policy.Keys[1].PublicKey = f.policy.Keys[0].PublicKey },
		"capability missing":              func(f *fixture) { f.policy.Keys[1].Kinds = f.policy.Keys[1].Kinds[1:] },
		"changed witness body":            func(f *fixture) { f.witnesses[0].Statement.CollectedAt++ },
		"support missing":                 func(f *fixture) { delete(f.supporting, "artifact-review") },
		"support truncated":               func(f *fixture) { f.supporting["artifact-review"] = []byte("x") },
		"unused support":                  func(f *fixture) { f.supporting["unbound"] = []byte("x") },
		"out-of-window collection signed": func(f *fixture) { f.witnesses[0].Statement.CollectedAt = 900; f.sign(t) },
		"future review signed":            func(f *fixture) { f.witnesses[0].Statement.ReviewedAt = 1400; f.sign(t) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, 1)
			mutate(f)
			if _, err := f.validate(); err == nil {
				t.Fatal("invalid evidence accepted")
			}
			if f.admission.count != 0 {
				t.Fatal("invalid evidence consumed admission")
			}
		})
	}
}

func TestSignedWrongCommandLineAndNonidenticalReplayFail(t *testing.T) {
	for _, name := range []string{"observed-command-line", "one-boot-replay", "bootstrap-replay", "post-handoff-fdt"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, 1)
			f.supporting[name] = []byte("different bytes")
			for index := range f.witnesses {
				for j := range f.witnesses[index].Statement.Evidence {
					binding := &f.witnesses[index].Statement.Evidence[j]
					if binding.Name == name {
						binding.Digest = bundle.Sum(f.supporting[name])
						binding.SizeBytes = uint64(len(f.supporting[name]))
					}
				}
			}
			f.sign(t)
			if _, err := f.validate(); err == nil {
				t.Fatal("signed semantic mismatch accepted")
			}
		})
	}
}

func TestLegacyClaimClosureRemainsUnavailable(t *testing.T) {
	f := newFixture(t, 2)
	v := f.expectation.value
	declared := stablecampaign.DeclaredEvidenceContext{CampaignID: v.CampaignID, PlanDigest: v.PlanDigest, RunIndex: v.RunIndex, RunID: v.RunID, ArtifactSetContentDigest: v.ArtifactSetContentDigest, MediaPartitions: v.MediaPartitions}
	report, err := f.result.CheckEvidenceConsistency(f.expectation.plan, f.raw, declared)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.result.RequirePlannedClaimClosure(f.expectation.plan, report); err == nil {
		t.Fatal("legacy consistency became claim closure")
	}
}

func TestWitnessParserRejectsAmbiguity(t *testing.T) {
	f := newFixture(t, 2)
	encoded, _ := f.witnesses[0].CanonicalJSON()
	if _, err := ParseWitness(append(bytes.Clone(encoded), '\n')); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range [][]byte{append([]byte(" "), encoded...), append(bytes.Clone(encoded), []byte("{}")...), bytes.Replace(encoded, []byte(`"conclusion":`), []byte(`"extra":false,"conclusion":`), 1), bytes.Replace(encoded, []byte(`"collected_at":1100`), []byte(`"collected_at":1100,"collected_at":1100`), 1), bytes.Replace(encoded, []byte(`"collected_at":1100`), []byte(`"collected_at":null`), 1)} {
		if _, err := ParseWitness(invalid); err == nil {
			t.Fatal("ambiguous witness accepted")
		}
	}
}
