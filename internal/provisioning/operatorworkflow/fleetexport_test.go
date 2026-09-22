package operatorworkflow

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/fleetexport"
)

// This rehearsal uses the real control/audit workflow with simulated operation
// evidence. It invokes no physical adapter and proves no hardware qualification.
func TestFleetExportDevelopmentHandoff(t *testing.T) {
	f := newWorkflowFixture(t)
	snapshot, tx := completedCampaign(t, &f)
	proposal, err := NewSecurityAppliedProposal(snapshot, tx, f.now)
	if err != nil {
		t.Fatal(err)
	}
	tx, err = ApplySecurityApplied(context.Background(), proposal, f.control, f.audit, f.control)
	if err != nil {
		t.Fatal(err)
	}
	p := fleetexport.Policy{
		AuthorityID: "provisioning-rehearsal", TenantID: "kaiba-lab", SecurityDomainID: "development",
		SourceCommit: "8d0ed51a8177f1431f4e6ff992df811fc134344d", ProfileID: tx.ProfileID, BundleDigest: tx.BundleDigest, PolicyDigest: tx.PolicyDigest,
		ProfileRef: fleetexport.Reference([]byte("synthetic development profile\n")),
		PostureRef: fleetexport.Reference([]byte("approved-development-only\n")),
		ReleaseRef: fleetexport.Reference([]byte("synthetic development release\n")),
	}
	first, err := fleetexport.Build(context.Background(), f.control, f.audit.service, tx.ID, p)
	if err != nil {
		t.Fatal(err)
	}
	second, err := fleetexport.Build(context.Background(), f.control, f.audit.service, tx.ID, p)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := first.JSON()
	b, _ := second.JSON()
	if !bytes.Equal(a, b) {
		t.Fatal("reexport changed immutable revision")
	}
	if first.Record.Source.State != "security_applied" || first.Record.Purpose != "candidate_evidence" || first.Record.Readiness.ProductionReady || first.Record.Readiness.EnrollmentReady {
		t.Fatal("development posture was strengthened")
	}
	if bytes.Contains(a, []byte("receipt_id")) || bytes.Contains(a, []byte("claim_id")) || bytes.Contains(a, []byte("intended_logical_id")) {
		t.Fatal("authority metadata leaked into fleet record")
	}
	out := t.TempDir()
	// Explicit opt-in writes reproducible, synthetic cross-repository fixtures.
	if requested := os.Getenv("KAIBA_FLEET_REHEARSAL_OUT"); requested != "" {
		out = requested
	}
	path, err := first.Save(out)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.Save(out); err != nil {
		t.Fatal(err)
	}
	first.Record.AssetRef = "different-asset"
	if _, err := first.Save(out); err == nil {
		t.Fatal("changed revision replaced immutable export")
	}
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, a) {
		t.Fatal("conflict changed durable bytes")
	}
	if os.Getenv("KAIBA_FLEET_REHEARSAL_OUT") != "" {
		data, _ := json.MarshalIndent(p, "", "  ")
		if err := os.WriteFile(filepath.Join(out, "policy.json"), append(data, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
		policyDir := filepath.Join(out, "evidence", "policy")
		if err := os.MkdirAll(policyDir, 0700); err != nil {
			t.Fatal(err)
		}
		for _, text := range []string{"synthetic development profile\n", "approved-development-only\n", "synthetic development release\n"} {
			if err := os.WriteFile(filepath.Join(policyDir, fleetexport.Digest([]byte(text))[7:]+".json"), []byte(text), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
}
