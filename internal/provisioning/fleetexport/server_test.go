package fleetexport

import (
	"context"
	"encoding/json"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/controlplane"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/handoff"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDurableRevisionAccountsForAuditAndPolicy(t *testing.T) {
	// Network errors are covered by the packaged cross-repository test. This server
	// exercises the real export store against changing source observations.
	tx := controlplane.Transaction{SchemaVersion: controlplane.TransactionSchemaVersion, ID: "tx", ResourceVersion: 1, Status: controlplane.StatusTargetBound, AssetID: "asset", ProfileID: "profile", BundleDigest: Digest([]byte("bundle")), PolicyDigest: Digest([]byte("policy")), UpdatedAt: time.Now()}
	audit := []byte(`[]`)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("audit") == "true" {
			w.Write(audit)
			return
		}
		json.NewEncoder(w).Encode(tx)
	})
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	// Use authenticated TLS transport here; the authority grant handler has separate tests.
	c := &handoff.Client{Base: server.URL, HTTP: server.Client()}
	a := &handoff.Client{Base: server.URL, HTTP: server.Client()}
	_ = a
	root := t.TempDir()
	s := &Server{Root: root, Control: c, Audit: &handoff.Client{Base: server.URL, HTTP: &http.Client{Transport: rewriteAudit{server.Client().Transport}}}, Config: Config{Policy: Policy{AuthorityID: "authority", TenantID: "tenant", SecurityDomainID: "development", SourceCommit: "0000000000000000000000000000000000000000", ProfileID: tx.ProfileID, BundleDigest: tx.BundleDigest, PolicyDigest: tx.PolicyDigest, ProfileRef: Reference([]byte("profile")), PostureRef: Reference([]byte("posture")), ReleaseRef: Reference([]byte("release"))}}}
	one, e := s.Export(context.Background(), "tx")
	if e != nil {
		t.Fatal(e)
	}
	two, e := s.Export(context.Background(), "tx")
	if e != nil || string(one) != string(two) {
		t.Fatal("unstable retry", e)
	}
	s.Config.Policy.SourceCommit = "1111111111111111111111111111111111111111"
	three, e := s.Export(context.Background(), "tx")
	if e != nil {
		t.Fatal(e)
	}
	var r Record
	json.Unmarshal(three, &r)
	if r.Revision != 2 {
		t.Fatal("policy change must advance export revision")
	}
	s2 := &Server{Root: root, Control: s.Control, Audit: s.Audit, Config: s.Config}
	again, e := s2.Export(context.Background(), "tx")
	if e != nil || string(again) != string(three) {
		t.Fatal("restart retry changed bytes", e)
	}
	// Malformed source fails without publishing a third revision.
	audit = []byte(`{}`)
	if _, e = s.Export(context.Background(), "tx"); e == nil {
		t.Fatal("malformed audit accepted")
	}
	if _, e = os.Stat(filepath.Join(root, "revisions", "tx", "3")); !os.IsNotExist(e) {
		t.Fatal("failed export committed")
	}
}

type rewriteAudit struct{ http.RoundTripper }

func (r rewriteAudit) RoundTrip(req *http.Request) (*http.Response, error) {
	q := req.Clone(req.Context())
	u := *q.URL
	u.RawQuery = "audit=true"
	q.URL = &u
	return r.RoundTripper.RoundTrip(q)
}
