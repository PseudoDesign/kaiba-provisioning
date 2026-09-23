package pilotexport

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/handoff"
)

func fixture(t *testing.T) (Config, Record) {
	t.Helper()
	raw, e := os.ReadFile("testdata/adoption.json")
	if e != nil {
		t.Fatal(e)
	}
	r, _, e := Parse(raw)
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	data := []byte("synthetic retained evidence, no device data")
	ref := Ref{"urn:fixture:evidence", handoff.Digest(data)}
	r.Target.Identity = ref
	r.Target.Storage = ref
	r.Source.Inventory = ref
	r.Source.Custody = ref
	r.Source.Workload = ref
	r.Baseline = ref
	path := filepath.Join(dir, "record")
	ep := filepath.Join(dir, "evidence")
	if e = os.WriteFile(ep, data, 0600); e != nil {
		t.Fatal(e)
	}
	c := Config{Authority: r.Authority, Tenant: r.Tenant, Domain: r.Domain, Access: handoff.Policy{Grants: []handoff.Grant{{Principal: "spiffe://fixture/reader", Transactions: []string{"device-a"}}}}, Records: map[string]Selection{"device-a": {Path: path, Evidence: map[string]string{ref.Digest: ep}}}}
	return save(t, c, r), r
}
func save(t *testing.T, c Config, r Record) Config {
	t.Helper()
	raw, _ := json.Marshal(r)
	_, canon, e := Parse(raw)
	if e != nil {
		t.Fatal(e)
	}
	sel := c.Records["device-a"]
	if e = os.WriteFile(sel.Path, canon, 0600); e != nil {
		t.Fatal(e)
	}
	sel.Digest = handoff.Digest(canon)
	c.Records["device-a"] = sel
	return c
}
func request(h http.Handler, path, principal string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", path, nil)
	if principal != "" {
		u, _ := url.Parse(principal)
		req.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{URIs: []*url.URL{u}}}}}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}
func TestRetentionAndAccess(t *testing.T) {
	c, r := fixture(t)
	root := t.TempDir()
	s, e := New(c, root)
	if e != nil {
		t.Fatal(e)
	}
	h := s.Handler()
	path := "/api/v1/pilot/records/device-a/current"
	first := request(h, path, "spiffe://fixture/reader")
	if first.Code != 200 {
		t.Fatal(first.Code, first.Body.String())
	}
	for _, p := range []string{"", "spiffe://fixture/other"} {
		if w := request(h, path, p); w.Code != 403 {
			t.Fatal(w.Code)
		}
	}
	if _, e = New(c, root); e == nil {
		t.Fatal("concurrent writer accepted")
	}
	s.Close()
	s, e = New(c, root)
	if e != nil {
		t.Fatal(e)
	}
	if got := request(s.Handler(), path, "spiffe://fixture/reader"); got.Body.String() != first.Body.String() {
		t.Fatal("restart changed revision")
	}
	s.Close()
	r.Conditions.Custody = false
	c = save(t, c, r)
	if _, e = New(c, root); e == nil {
		t.Fatal("rewrote immutable revision")
	}
	r.Revision++
	c = save(t, c, r)
	s, e = New(c, root)
	if e != nil {
		t.Fatal(e)
	}
	if w := request(s.Handler(), "/api/v1/pilot/records/device-a/revisions/1", "spiffe://fixture/reader"); w.Code != 200 || w.Body.String() != first.Body.String() {
		t.Fatal("history lost")
	}
	s.Close()
	r.Revision--
	c = save(t, c, r)
	if _, e = New(c, root); e == nil {
		t.Fatal("rollback accepted")
	}
}
func TestMissingAndTamperedEvidence(t *testing.T) {
	for _, which := range []string{"missing", "tampered", "wrong-digest", "wrong-scope"} {
		t.Run(which, func(t *testing.T) {
			c, _ := fixture(t)
			sel := c.Records["device-a"]
			switch which {
			case "missing":
				sel.Evidence = map[string]string{}
			case "tampered":
				for _, path := range sel.Evidence {
					os.WriteFile(path, []byte("changed"), 0600)
				}
			case "wrong-digest":
				sel.Digest = handoff.Digest([]byte("other"))
			case "wrong-scope":
				c.Authority = "other"
			}
			c.Records["device-a"] = sel
			if s, e := New(c, t.TempDir()); e == nil {
				s.Close()
				t.Fatal("accepted invalid input")
			}
		})
	}
}
func TestRequiredFalseAndUnknownFields(t *testing.T) {
	raw, _ := os.ReadFile("testdata/adoption.json")
	var v map[string]any
	json.Unmarshal(raw, &v)
	delete(v["conditions"].(map[string]any), "known_key_exposure")
	b, _ := json.Marshal(v)
	if _, _, e := Parse(b); e == nil {
		t.Fatal("missing false condition accepted")
	}
	json.Unmarshal(raw, &v)
	v["full_qualification"] = true
	b, _ = json.Marshal(v)
	if _, _, e := Parse(b); e == nil {
		t.Fatal("full qualification accepted")
	}
	json.Unmarshal(raw, &v)
	v["unknown"] = false
	b, _ = json.Marshal(v)
	if _, _, e := Parse(b); e == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestUnchangedObservationCannotRefreshItsAge(t *testing.T) {
	c, r := fixture(t)
	root := t.TempDir()
	s, e := New(c, root)
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	r.Revision++
	r.Issued = "2026-09-23T12:01:00Z"
	c = save(t, c, r)
	if s, e = New(c, root); e == nil {
		s.Close()
		t.Fatal("unchanged inputs minted a new revision")
	}
}
