package fleetexport

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/auditlog"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/controlplane"
)

type changingReader struct {
	tx    controlplane.Transaction
	calls int
}

func (r *changingReader) GetTransaction(context.Context, string) (controlplane.Transaction, error) {
	r.calls++
	tx := r.tx
	if r.calls > 1 {
		tx.ResourceVersion++
	}
	return tx, nil
}

type staticReader struct{ tx controlplane.Transaction }

func (r staticReader) GetTransaction(context.Context, string) (controlplane.Transaction, error) {
	return r.tx, nil
}
func fixture(t *testing.T) (*controlplane.Service, *auditlog.Service, controlplane.Transaction, Policy) {
	t.Helper()
	control, err := controlplane.NewService(&controlplane.MemoryStore{}, controlplane.WithClock(func() time.Time { return time.Date(2026, 9, 11, 12, 0, 0, 123456789, time.UTC) }))
	if err != nil {
		t.Fatal(err)
	}
	audit, err := auditlog.NewService(&auditlog.MemoryStore{})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := control.CreateTransaction(context.Background(), controlplane.CreateTransactionRequest{
		SchemaVersion: controlplane.CreateTransactionRequestSchemaVersion, IdempotencyKey: "create-1", TransactionID: "tx-1", AssetID: "asset-1", IntendedLogicalID: "not-a-device-binding", ProfileID: "profile-1",
		BundleDigest: Digest([]byte("bundle")), PolicyDigest: Digest([]byte("policy")), ExpectedPrestateCustomerKeyHash: controlplane.UnownedCustomerKeyHash, ExpectedCustomerKeyHash: Digest([]byte("customer")),
	})
	if err != nil {
		t.Fatal(err)
	}
	ref := Reference([]byte("evidence"))
	p := Policy{"authority-1", "tenant-1", "development", strings.Repeat("a", 40), tx.ProfileID, tx.BundleDigest, tx.PolicyDigest, ref, ref, ref}
	return control, audit, tx, p
}
func TestCreatedObservationAndReadOnlyStore(t *testing.T) {
	control, audit, tx, p := fixture(t)
	b, err := Build(context.Background(), control, audit, tx.ID, p)
	if err != nil {
		t.Fatal(err)
	}
	if b.Record.Revision != tx.ResourceVersion || b.Record.IssuedAt != "2026-09-11T12:00:00.123456Z" || b.Record.Readiness.Reasons[2] != "source_state:created" {
		t.Fatalf("bad observation: %#v", b.Record)
	}
	if string(b.AuditBytes) != "[]" {
		t.Fatal("invented audit evidence")
	}
	path := filepath.Join(t.TempDir(), "missing.json")
	if _, err := FromStores(context.Background(), path, path, tx.ID, p); err == nil {
		t.Fatal("missing authority treated as empty")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("source store was initialized")
	}
	if err := (ReadOnlyStore{path}).Save([]byte("changed")); err == nil {
		t.Fatal("read-only store allowed write")
	}
}
func TestChangedSourceMissingAuditAndPolicyDriftFailClosed(t *testing.T) {
	_, audit, tx, p := fixture(t)
	if _, err := Build(context.Background(), &changingReader{tx: tx}, audit, tx.ID, p); err == nil {
		t.Fatal("unstable snapshot accepted")
	}
	tx.Quarantine = &controlplane.QuarantineRecord{AuditReceiptID: Digest([]byte("missing"))}
	if _, err := Build(context.Background(), staticReader{tx}, audit, tx.ID, p); err == nil {
		t.Fatal("missing audit accepted")
	}
	tx.Quarantine = nil
	p.ProfileID = "different"
	if _, err := Build(context.Background(), staticReader{tx}, audit, tx.ID, p); err == nil {
		t.Fatal("unapproved profile accepted")
	}
}
func TestUnknownStateRemainsVisibleAndNotReady(t *testing.T) {
	_, audit, tx, p := fixture(t)
	tx.Status = "future_source_state"
	b, err := Build(context.Background(), staticReader{tx}, audit, tx.ID, p)
	if err != nil {
		t.Fatal(err)
	}
	if b.Record.Source.State != "future_source_state" || b.Record.Readiness.ProductionReady || b.Record.Readiness.EnrollmentReady {
		t.Fatal("unknown state strengthened")
	}
}
