package livestation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/authorityhttp"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaign"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/controlplane"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/releasebinding"
)

type observationReaderFunc func(context.Context, string) (controlplane.Transaction, error)

func (read observationReaderFunc) GetTransaction(ctx context.Context, id string) (controlplane.Transaction, error) {
	return read(ctx, id)
}

func observerConfig(t *testing.T) ObservationConfig {
	t.Helper()
	directory := t.TempDir()
	return ObservationConfig{StationID: "station-1", LaneID: "lane-1", TransactionID: "transaction-1", USBPath: filepath.Join(directory, "usb"), UARTPath: filepath.Join(directory, "uart")}
}

func readObservation(t *testing.T, observer *Observer) ObservationState {
	t.Helper()
	state, err := observer.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func TestObserverConfiguration(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*ObservationConfig)
	}{
		{"station", func(c *ObservationConfig) { c.StationID = "" }},
		{"lane", func(c *ObservationConfig) { c.LaneID = "bad/lane" }},
		{"transaction", func(c *ObservationConfig) { c.TransactionID = "../other" }},
		{"USB", func(c *ObservationConfig) { c.USBPath = "relative" }},
		{"UART", func(c *ObservationConfig) { c.UARTPath = "" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := observerConfig(t)
			test.mutate(&config)
			if _, err := NewObserver(config, &controlplane.Service{}); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
	if _, err := NewObserver(observerConfig(t), nil); err == nil {
		t.Fatal("missing reader accepted")
	}
}

func TestObserverProjectsRecordedProgressWithoutHardwareClaims(t *testing.T) {
	f := newObservationFixture(t)
	f.claim()
	f.bind()
	f.approve()
	f.intent()
	f.evidence(controlplane.EvidenceSucceeded)
	observer, err := NewObserver(observerConfig(t), f.service)
	if err != nil {
		t.Fatal(err)
	}
	state := readObservation(t, observer)
	if state.ReadStatus != "current" || state.Stale || state.LastSuccessfulRead == nil || state.Snapshot == nil {
		t.Fatalf("state = %#v", state)
	}
	snapshot := state.Snapshot
	if snapshot.Status != f.transaction.Status || snapshot.ResourceVersion != f.transaction.ResourceVersion || !snapshot.UpdatedAt.Equal(f.transaction.UpdatedAt) {
		t.Fatal("authoritative transaction metadata was changed")
	}
	if snapshot.RecordedPrestate.CustomerKeyHash != controlplane.UnownedCustomerKeyHash || snapshot.Expected.CustomerKeyHash != f.transaction.ExpectedCustomerKeyHash || snapshot.Expected.Release.ExpectedBootImageDigest != observationDigest("e") {
		t.Fatal("recorded prestate and expected values were conflated")
	}
	if snapshot.Hardware != (HardwareUnknowns{"unknown", "unknown", "unknown", "unknown"}) || snapshot.EvidenceBasis != "coordinator_recorded" || snapshot.FleetAdmission != "unevaluated" {
		t.Fatal("unsupported hardware or admission claim")
	}
	if len(snapshot.Operations) != 7 || snapshot.Operations[0].Status != "succeeded" || snapshot.Operations[0].EvidenceAuditReceiptID != observationDigest("b") {
		t.Fatal("operation evidence omitted")
	}
	for _, operation := range snapshot.Operations[1:] {
		if operation.Status != "not_recorded" || operation.StatusLabel != "Not recorded" || operation.IntentAt != nil || operation.EvidenceAuditReceiptID != "" {
			t.Fatal("missing operation manufactured evidence")
		}
	}
	// Callers cannot edit a future stale view by mutating their returned result.
	snapshot.Operations[0].Status = "tampered"
	snapshot.RecordedPrestate.CustomerKeyHash = "tampered"
	if observer.snapshot.Operations[0].Status != "succeeded" || observer.snapshot.RecordedPrestate.CustomerKeyHash != controlplane.UnownedCustomerKeyHash {
		t.Fatal("returned projection aliases retained state")
	}
}

func TestObserverOutageClearAndRestart(t *testing.T) {
	f := newObservationFixture(t)
	f.claim()
	for _, test := range []struct {
		name   string
		err    error
		status string
		retain bool
	}{
		{"network", errors.New("connection refused"), "unavailable", true},
		{"timeout", context.DeadlineExceeded, "unavailable", true},
		{"server", &authorityhttp.HTTPStatusError{StatusCode: 503}, "unavailable", true},
		{"unauthenticated", &authorityhttp.HTTPStatusError{StatusCode: 401}, "denied", false},
		{"denied", &authorityhttp.HTTPStatusError{StatusCode: 403}, "denied", false},
		{"missing", &authorityhttp.HTTPStatusError{StatusCode: 404}, "not_found", false},
		{"redirect", &authorityhttp.HTTPStatusError{StatusCode: 302}, "invalid_response", false},
		{"bad response", &authorityhttp.InvalidResponseError{Err: errors.New("bad JSON")}, "invalid_response", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var readErr error
			reader := observationReaderFunc(func(context.Context, string) (controlplane.Transaction, error) { return f.transaction, readErr })
			config := observerConfig(t)
			observer, err := NewObserver(config, reader)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
			observer.clock = func() time.Time { return now }
			initial := readObservation(t, observer)
			readErr = fmt.Errorf("wrapped error: %w", test.err)
			now = now.Add(time.Minute)
			failed := readObservation(t, observer)
			if failed.ReadStatus != test.status || failed.Stale != test.retain || (failed.Snapshot != nil) != test.retain || (failed.LastSuccessfulRead != nil) != test.retain {
				t.Fatalf("failed view = %#v", failed)
			}
			if !failed.LastAttemptedRead.Equal(now) || !failed.LocalPorts.ObservedAt.Equal(now) {
				t.Fatal("timestamps not independently refreshed")
			}
			if test.retain && !failed.LastSuccessfulRead.Equal(*initial.LastSuccessfulRead) {
				t.Fatal("failed read changed last success time")
			}
			restarted, err := NewObserver(config, reader)
			if err != nil {
				t.Fatal(err)
			}
			if state := readObservation(t, restarted); state.Snapshot != nil || state.LastSuccessfulRead != nil || state.Stale {
				t.Fatal("restart restored an unverified snapshot")
			}
			readErr = nil
			now = now.Add(time.Minute)
			recovered := readObservation(t, observer)
			if recovered.ReadStatus != "current" || recovered.Stale || recovered.Snapshot == nil || !recovered.LastSuccessfulRead.Equal(now) {
				t.Fatal("recovery failed")
			}
		})
	}
}

func TestObserverRejectsInvalidProjectionAndClearsEvidence(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*controlplane.Transaction)
	}{
		{"different transaction", func(tx *controlplane.Transaction) { tx.ID = "another-transaction" }},
		{"schema", func(tx *controlplane.Transaction) { tx.SchemaVersion = "unknown" }},
		{"status", func(tx *controlplane.Transaction) { tx.Status = "unknown" }},
		{"zero version", func(tx *controlplane.Transaction) { tx.ResourceVersion = 0 }},
		{"wrong owner", func(tx *controlplane.Transaction) { tx.ActiveClaim.LaneID = "other-lane" }},
		{"unknown operation", func(tx *controlplane.Transaction) { tx.Operations[0].Operation = "enroll" }},
		{"reordered operations", func(tx *controlplane.Transaction) {
			tx.Operations[0].Operation = string(campaign.OperationOwnedReadback)
		}},
		{"bad digest", func(tx *controlplane.Transaction) { tx.BundleDigest = observationDigest("f") }},
		{"missing evidence", func(tx *controlplane.Transaction) { tx.Operations[0].EvidenceAuditReceiptID = "" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newObservationFixture(t)
			f.claim()
			f.bind()
			f.approve()
			f.intent()
			f.evidence(controlplane.EvidenceSucceeded)
			observer, err := NewObserver(observerConfig(t), observationReaderFunc(func(context.Context, string) (controlplane.Transaction, error) { return f.transaction, nil }))
			if err != nil {
				t.Fatal(err)
			}
			if readObservation(t, observer).Snapshot == nil {
				t.Fatal("valid transaction rejected")
			}
			test.mutate(&f.transaction)
			state := readObservation(t, observer)
			if state.ReadStatus != "invalid_response" || state.Snapshot != nil || state.LastSuccessfulRead != nil || state.Stale {
				t.Fatalf("invalid projection retained: %#v", state)
			}
		})
	}
}

func TestObserverSerializesReadsAndAllowsCanceledWaiters(t *testing.T) {
	f := newObservationFixture(t)
	f.claim()
	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	reader := observationReaderFunc(func(context.Context, string) (controlplane.Transaction, error) {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
			return f.transaction, nil
		}
		return controlplane.Transaction{}, &authorityhttp.HTTPStatusError{StatusCode: 403}
	})
	observer, err := NewObserver(observerConfig(t), reader)
	if err != nil {
		t.Fatal(err)
	}
	first := make(chan ObservationState, 1)
	go func() { state, _ := observer.Current(context.Background()); first <- state }()
	<-entered
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := observer.Current(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("wait error = %v", err)
	}
	second := make(chan ObservationState, 1)
	go func() { state, _ := observer.Current(context.Background()); second <- state }()
	if calls.Load() != 1 {
		t.Fatal("reader overlapped")
	}
	close(release)
	if state := <-first; state.ReadStatus != "current" {
		t.Fatalf("first = %#v", state)
	}
	if state := <-second; state.ReadStatus != "denied" || state.Snapshot != nil {
		t.Fatalf("second = %#v", state)
	}
	if observer.snapshot != nil || calls.Load() != 2 {
		t.Fatal("old result replaced denial")
	}
}

func TestObserverOnlyObservesPortPresenceAndUSBIdentifiers(t *testing.T) {
	config := observerConfig(t)
	if err := os.Mkdir(config.USBPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(config.USBPath, "idVendor"), []byte("0A5C\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(config.USBPath, "idProduct"), []byte("2712\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/null", config.UARTPath); err != nil {
		t.Fatal(err)
	}
	ports := observePorts(config, time.Now())
	if ports.USB.Status != "present" || ports.USB.VendorID != "0a5c" || ports.USB.ProductID != "2712" || ports.UART.Status != "present" {
		t.Fatalf("ports = %#v", ports)
	}
	if err := os.Remove(config.UARTPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(config.USBPath, "idProduct"), []byte("invalid"), 0o600); err != nil {
		t.Fatal(err)
	}
	ports = observePorts(config, time.Now())
	if ports.USB.ProductID != "" || ports.UART.Status != "absent" || !strings.Contains(ports.Detail, "does not authenticate") {
		t.Fatalf("invalid observation: %#v", ports)
	}
}

func TestObserverPreservesEveryRecordedStatusAndGuidance(t *testing.T) {
	for _, scenario := range []string{"claimed", "target_bound", "commit_approved", "intent_recorded", "succeeded", "failed", "uncertain", "confirmed_applied", "confirmed_not_applied", "security_applied", "aborted", "quarantined"} {
		t.Run(scenario, func(t *testing.T) {
			f := newObservationFixture(t)
			f.prepare(scenario)
			observer, err := NewObserver(observerConfig(t), f.service)
			if err != nil {
				t.Fatal(err)
			}
			before, _ := f.store.Load()
			state := readObservation(t, observer)
			after, _ := f.store.Load()
			if !bytes.Equal(before, after) {
				t.Fatal("viewer changed authority storage")
			}
			if state.ReadStatus != "current" || state.Snapshot == nil || state.Snapshot.Status != f.transaction.Status || state.Snapshot.StatusLabel == "" {
				t.Fatalf("projection = %#v", state)
			}
			for index, record := range f.transaction.Operations {
				if row := state.Snapshot.Operations[index]; row.Status != string(record.Status) || row.StatusLabel == "" {
					t.Fatalf("operation = %#v", row)
				}
			}
			if scenario == "intent_recorded" || scenario == "uncertain" {
				if !strings.Contains(state.NextAction, "reconcile") || !strings.Contains(state.NextAction, "do not repeat") {
					t.Fatal("pending operation lacks reconciliation guidance")
				}
			}
			if scenario == "quarantined" || scenario == "failed" {
				if !strings.Contains(state.NextAction, "quarantined") {
					t.Fatal("quarantine guidance absent")
				}
			}
			if scenario == "security_applied" && (!strings.Contains(state.NextAction, "development") || state.Snapshot.FleetAdmission != "unevaluated") {
				t.Fatal("development completion misrepresented")
			}
		})
	}
}

// Fixtures advance the real service through its public operations. No observer
// code participates in setup, and no synthetic workflow state is inferred.
type observationFixture struct {
	t           *testing.T
	service     *controlplane.Service
	store       *controlplane.MemoryStore
	transaction controlplane.Transaction
	now         time.Time
	operations  []string
}

func newObservationFixture(t *testing.T) *observationFixture {
	t.Helper()
	f := &observationFixture{t: t, store: &controlplane.MemoryStore{}, now: time.Now().UTC()}
	var err error
	f.service, err = controlplane.NewService(f.store, controlplane.WithClock(func() time.Time { return f.now }))
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range campaign.DevelopmentOperations() {
		f.operations = append(f.operations, string(operation))
	}
	f.accept(f.service.CreateTransaction(context.Background(), controlplane.CreateTransactionRequest{
		SchemaVersion: controlplane.CreateTransactionRequestSchemaVersion, IdempotencyKey: "create", TransactionID: "transaction-1",
		AssetID: "asset-1", IntendedLogicalID: "device-1", ProfileID: "rpi5-v1", BundleDigest: observationDigest("0"), PolicyDigest: observationDigest("1"),
		ExpectedPrestateCustomerKeyHash: controlplane.UnownedCustomerKeyHash, ExpectedCustomerKeyHash: observationDigest("2"),
	}))
	return f
}

func (f *observationFixture) accept(transaction controlplane.Transaction, err error) {
	f.t.Helper()
	if err != nil {
		f.t.Fatal(err)
	}
	f.transaction = transaction
}

func (f *observationFixture) mutation() controlplane.MutationContext {
	return controlplane.MutationContext{TransactionID: f.transaction.ID, ExpectedResourceVersion: f.transaction.ResourceVersion, ClaimID: f.transaction.ActiveClaim.ID, FenceEpoch: f.transaction.FenceEpoch}
}

func (f *observationFixture) claim() {
	f.t.Helper()
	f.accept(f.service.AcquireClaim(context.Background(), controlplane.AcquireClaimRequest{
		SchemaVersion: controlplane.AcquireClaimRequestSchemaVersion, IdempotencyKey: "claim", TransactionID: f.transaction.ID,
		ExpectedResourceVersion: f.transaction.ResourceVersion, StationID: "station-1", LaneID: "lane-1", Mode: controlplane.ClaimModeMutation,
		AllowedStages: f.operations, LeaseDurationSeconds: 300,
	}))
}

func (f *observationFixture) bind() {
	f.t.Helper()
	f.accept(f.service.BindTarget(context.Background(), controlplane.BindTargetRequest{
		SchemaVersion: controlplane.BindTargetRequestSchemaVersion, IdempotencyKey: "bind", MutationContext: f.mutation(),
		TargetFingerprint: observationDigest("3"), ObservationDigest: observationDigest("4"), CustomerKeyHash: controlplane.UnownedCustomerKeyHash,
	}))
}

func (f *observationFixture) approve() {
	f.t.Helper()
	f.accept(f.service.RecordApproval(context.Background(), controlplane.RecordApprovalRequest{
		SchemaVersion: controlplane.RecordApprovalRequestSchemaVersion, IdempotencyKey: "approve", MutationContext: f.mutation(),
		ApprovalID: "approval-1", ApproverID: "approver-1", TransactionDigest: f.transaction.TransactionDigest, PlanDigest: observationDigest("5"),
		TargetFingerprint: f.transaction.Target.Fingerprint, AllowedOperations: f.operations, AuditReceiptID: observationDigest("a"), ExpiresAt: f.now.Add(30 * time.Minute),
		Release: releasebinding.Binding{SignedReleaseManifestDigest: f.transaction.BundleDigest, LaneGuardPackageDigest: observationDigest("b"),
			CompiledArtifactSetDigest: observationDigest("c"), ExpectedCustomerKeyHash: f.transaction.ExpectedCustomerKeyHash,
			ExpectedEEPROMDigest: observationDigest("d"), ExpectedBootImageDigest: observationDigest("e")},
	}))
}

func (f *observationFixture) intent() {
	f.t.Helper()
	index := len(f.transaction.Operations)
	f.accept(f.service.RecordIntent(context.Background(), controlplane.RecordIntentRequest{
		SchemaVersion: controlplane.RecordIntentRequestSchemaVersion, IdempotencyKey: fmt.Sprintf("intent-%d", index), MutationContext: f.mutation(),
		ApprovalID: f.transaction.Approval.ID, OperationID: fmt.Sprintf("operation-%d", index), Operation: f.operations[index],
		PlanDigest: f.transaction.Approval.PlanDigest, InputDigest: observationDigest("6"), PrestateDigest: observationDigest("7"), AuditReceiptID: observationDigest("8"),
	}))
}

func (f *observationFixture) evidence(result controlplane.EvidenceResult) {
	f.t.Helper()
	index := len(f.transaction.Operations) - 1
	f.accept(f.service.RecordEvidence(context.Background(), controlplane.RecordEvidenceRequest{
		SchemaVersion: controlplane.RecordEvidenceRequestSchemaVersion, IdempotencyKey: fmt.Sprintf("evidence-%d", index), MutationContext: f.mutation(),
		OperationID: f.transaction.Operations[index].ID, Result: result,
		OutputDigest: observationDigest("9"), ObservationDigest: observationDigest("a"), AuditReceiptID: observationDigest("b"),
	}))
}

func (f *observationFixture) reconcile(resolution controlplane.ReconciliationResolution) {
	f.t.Helper()
	f.accept(f.service.TransferClaim(context.Background(), controlplane.TransferClaimRequest{
		SchemaVersion: controlplane.TransferClaimRequestSchemaVersion, IdempotencyKey: "transfer", TransactionID: f.transaction.ID,
		ExpectedResourceVersion: f.transaction.ResourceVersion, ClaimID: f.transaction.ActiveClaim.ID, FenceEpoch: f.transaction.FenceEpoch,
		NewStationID: "station-1", NewLaneID: "lane-1", Mode: controlplane.ClaimModeReconciliation, AllowedStages: f.operations, LeaseDurationSeconds: 300,
	}))
	f.accept(f.service.RecordReconciliation(context.Background(), controlplane.RecordReconciliationRequest{
		SchemaVersion: controlplane.RecordReconciliationRequestSchemaVersion, IdempotencyKey: "reconcile", MutationContext: f.mutation(),
		OperationID: f.transaction.Operations[0].ID, Resolution: resolution, OutputDigest: observationDigest("9"), ObservationDigest: observationDigest("c"), AuditReceiptID: observationDigest("d"),
	}))
}

func (f *observationFixture) prepare(scenario string) {
	f.t.Helper()
	if scenario == "created" {
		return
	}
	f.claim()
	if scenario == "claimed" {
		return
	}
	if scenario == "aborted" {
		f.accept(f.service.AbortTransaction(context.Background(), controlplane.AbortRequest{
			SchemaVersion: controlplane.AbortRequestSchemaVersion, IdempotencyKey: "abort", MutationContext: f.mutation(),
			ReusableBaselineDigest: observationDigest("a"), AuditReceiptID: observationDigest("b"),
		}))
		return
	}
	if scenario == "quarantined" {
		f.accept(f.service.QuarantineDevice(context.Background(), controlplane.QuarantineRequest{
			SchemaVersion: controlplane.QuarantineRequestSchemaVersion, IdempotencyKey: "quarantine", MutationContext: f.mutation(),
			ReasonCode: "unknown_state", ObservationDigest: observationDigest("a"), AuditReceiptID: observationDigest("b"),
		}))
		return
	}
	f.bind()
	if scenario == "target_bound" {
		return
	}
	f.approve()
	if scenario == "commit_approved" {
		return
	}
	f.intent()
	if scenario == "intent_recorded" {
		return
	}
	switch scenario {
	case "failed":
		f.evidence(controlplane.EvidenceFailed)
	case "uncertain":
		f.evidence(controlplane.EvidenceUncertain)
	case "confirmed_applied", "confirmed_not_applied":
		f.evidence(controlplane.EvidenceUncertain)
		f.reconcile(controlplane.ReconciliationResolution(scenario))
	default:
		f.evidence(controlplane.EvidenceSucceeded)
	}
	if scenario == "security_applied" {
		for len(f.transaction.Operations) < len(f.operations) {
			f.intent()
			f.evidence(controlplane.EvidenceSucceeded)
		}
		f.accept(f.service.MarkSecurityApplied(context.Background(), controlplane.SecurityAppliedRequest{
			SchemaVersion: controlplane.SecurityAppliedRequestSchemaVersion, IdempotencyKey: "security-applied", MutationContext: f.mutation(),
			PlanDigest: f.transaction.Approval.PlanDigest, EvidenceDigest: observationDigest("c"), AuditReceiptID: observationDigest("d"),
			RollbackStatus: "rollback_unimplemented", ReleaseClassification: "development_asset",
		}))
	}
}

func observationDigest(value string) string { return "sha256:" + strings.Repeat(value, 64) }
