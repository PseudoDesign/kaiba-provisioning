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
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/handoff"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/recordpublication"
)

func TestPublicationAppearsWithoutReaderRestartAndKeepsRoleBoundary(t *testing.T) {
	c, r := fixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	dir := t.TempDir()
	os.Chmod(dir, 0750)
	c.Publications = &recordpublication.Config{Directory: dir, PublisherUID: uint32(os.Geteuid()), ReaderGID: uint32(os.Getegid()), Delegation: handoff.Digest([]byte("synthetic delegation")), From: now.Add(-time.Hour).Format(time.RFC3339), Expires: now.Add(30*24*time.Hour - time.Hour).Format(time.RFC3339), Grants: []recordpublication.Grant{{Principal: "spiffe://fixture/reader", Enrollments: []string{"retained-a"}}}}
	s, e := New(c, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	handler := s.Handler()
	observation := handoff.Digest([]byte("new authenticated measurement"))
	id := "refresh-" + observation[7:]
	r.ID = id + "-adoption"
	r.Revision = 1
	raw, _ := json.Marshal(r)
	_, raw, e = Parse(raw)
	if e != nil {
		t.Fatal(e)
	}
	evidence := map[string][]byte{}
	for hash, path := range c.Records["device-a"].Evidence {
		evidence[hash], e = os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
	}
	batch := recordpublication.Batch{Schema: "kaiba.renewal-record-publication/v1alpha1", Delegation: c.Publications.Delegation, Enrollment: "retained-a", Operation: "synthetic-renewal", Observation: observation, From: c.Publications.From, Expires: c.Publications.Expires, Records: map[string]recordpublication.Record{r.ID: {Body: raw, Digest: handoff.Digest(raw), Evidence: evidence}}}
	for _, role := range []string{"policy", "decision"} {
		body, _ := json.Marshal(map[string]any{"record_id": id + "-" + role, "revision": 1})
		body, _ = handoff.Canonical(body)
		batch.Records[id+"-"+role] = recordpublication.Record{Body: body, Digest: handoff.Digest(body), Evidence: map[string][]byte{}}
	}
	call := func(path, principal string, expired bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/pilot/records/"+path, nil)
		uri, _ := url.Parse(principal)
		cert := &x509.Certificate{URIs: []*url.URL{uri}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
		if expired {
			cert.NotAfter = now.Add(-time.Second)
		}
		req.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{cert}}}
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		return out
	}
	if got := call(r.ID+"/current", "spiffe://fixture/reader", false); got.Code != 403 {
		t.Fatal("unpublished batch visible")
	}
	data, _ := json.Marshal(batch)
	data, _ = handoff.Canonical(data)
	path := filepath.Join(dir, observation[7:]+".json")
	if e = os.WriteFile(path, data, 0640); e != nil {
		t.Fatal(e)
	}
	os.Chmod(path, 0640)
	for _, route := range []string{r.ID + "/current", r.ID + "/revisions/1"} {
		got := call(route, "spiffe://fixture/reader", false)
		if got.Code != 200 || got.Body.String() != string(raw) {
			t.Fatalf("new batch unavailable: %d %s", got.Code, got.Body)
		}
	}
	for hash, expected := range evidence {
		got := call(r.ID+"/evidence/"+hash[7:], "spiffe://fixture/reader", false)
		if got.Code != 200 || got.Body.String() != string(expected) {
			t.Fatal("evidence unavailable")
		}
	}
	for _, route := range []string{id + "-policy/current", id + "-decision/current"} {
		if got := call(route, "spiffe://fixture/reader", false); got.Code != 403 {
			t.Fatal("observation service served another role")
		}
	}
	if got := call(r.ID+"/current", "spiffe://fixture/operator", false); got.Code != 403 {
		t.Fatal("operator acquired reader grant")
	}
	if got := call(r.ID+"/current", "spiffe://fixture/reader", true); got.Code != 403 {
		t.Fatal("expired retained TLS principal accepted")
	}
	if got := request(handler, "/api/v1/pilot/records/device-a/current", "spiffe://fixture/reader"); got.Code != 200 {
		t.Fatal("original selection lost")
	}
}
