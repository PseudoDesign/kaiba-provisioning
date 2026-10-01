package recordpublication

import (
	"encoding/json"
	"fmt"
	wire "github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/handoff"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) (Config, Batch, time.Time) {
	t.Helper()
	dir := t.TempDir()
	if e := os.Chmod(dir, 0750); e != nil {
		t.Fatal(e)
	}
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	c := Config{Directory: dir, PublisherUID: uint32(os.Geteuid()), ReaderGID: uint32(os.Getegid()), Delegation: wire.Digest([]byte("owner term")), From: now.Add(-time.Hour).Format(time.RFC3339), Expires: now.Add(30*24*time.Hour - time.Hour).Format(time.RFC3339), Grants: []Grant{{"spiffe://pilot/reader", []string{"ace"}}}}
	b := Batch{Schema: "kaiba.renewal-record-publication/v1alpha1", Delegation: c.Delegation, Enrollment: "ace", Operation: "renew-ace", Observation: wire.Digest([]byte("measurement")), From: c.From, Expires: c.Expires, Records: map[string]Record{}}
	for _, role := range []string{"adoption", "policy", "decision"} {
		handle := "refresh-" + b.Observation[7:] + "-" + role
		body, _ := json.Marshal(map[string]any{"record_id": handle, "revision": 1})
		body, _ = wire.Canonical(body)
		b.Records[handle] = Record{body, wire.Digest(body), map[string][]byte{wire.Digest([]byte(role)): []byte(role)}}
	}
	return c, b, now
}
func TestPublishedBatchReaders(t *testing.T) {
	c, b, now := fixture(t)
	if _, e := publishFixture(c, b, now); e != nil {
		t.Fatal(e)
	}
	for handle, want := range b.Records {
		got, e := Read(c, handle, "spiffe://pilot/reader", now)
		if e != nil || got.Digest != want.Digest {
			t.Fatalf("unavailable committed record: %v", e)
		}
		if _, e = Read(c, handle, "spiffe://pilot/operator", now); e == nil {
			t.Fatal("general operator inherited a publication grant")
		}
		if _, e = Read(c, handle, "spiffe://pilot/reader", moment(c.Expires)); e == nil {
			t.Fatal("expired term readable")
		}
		altered := c
		altered.Grants = []Grant{{"spiffe://pilot/reader", []string{"mako"}}}
		if _, e = Read(altered, handle, "spiffe://pilot/reader", now); e == nil {
			t.Fatal("replacement member accepted")
		}
	}
	entries, e := os.ReadDir(c.Directory)
	if e != nil || len(entries) != 1 {
		t.Fatal("duplicate publication or staging file remains")
	}
}
func TestPublicationRejectsConflictsIncompleteAndCorruptFiles(t *testing.T) {
	c, b, now := fixture(t)
	if _, e := publishFixture(c, b, now); e != nil {
		t.Fatal(e)
	}
	handle := "refresh-" + b.Observation[7:] + "-adoption"
	b.Operation = "different-operation"
	if _, e := publishFixture(c, b, now); e == nil {
		t.Fatal("published batch overwritten")
	}
	b.Operation = "renew-ace"
	delete(b.Records, handle)
	if _, e := publishFixture(c, b, now); e == nil {
		t.Fatal("partial batch accepted")
	}
	path := filepath.Join(c.Directory, b.Observation[7:]+".json")
	if e := os.Chmod(path, 0660); e != nil {
		t.Fatal(e)
	}
	if _, e := Read(c, handle, "spiffe://pilot/reader", now); e == nil {
		t.Fatal("group-writable records trusted")
	}
	if e := os.Chmod(path, 0640); e != nil {
		t.Fatal(e)
	}
	if e := os.Link(path, path+".alias"); e != nil {
		t.Fatal(e)
	}
	if _, e := Read(c, handle, "spiffe://pilot/reader", now); e == nil {
		t.Fatal("multiply linked records trusted")
	}
	os.Remove(path + ".alias")
	if e := os.WriteFile(path, []byte(`{"schema_version":"corrupt"}`), 0640); e != nil {
		t.Fatal(e)
	}
	if _, e := Read(c, handle, "spiffe://pilot/reader", now); e == nil {
		t.Fatal("corrupt records trusted")
	}
}
func TestPublicationRejectsEscapesAndPartialStaging(t *testing.T) {
	c, b, now := fixture(t)
	raw, _ := json.Marshal(b)
	if e := os.WriteFile(filepath.Join(c.Directory, ".publication-incomplete"), raw, 0640); e != nil {
		t.Fatal(e)
	}
	handle := "refresh-" + b.Observation[7:] + "-adoption"
	if _, e := Read(c, handle, "spiffe://pilot/reader", now); e == nil {
		t.Fatal("incomplete publication exposed")
	}
	for _, h := range []string{"../escape", "refresh-" + strings.Repeat("a", 64) + "/../x-adoption", handle + "/current"} {
		if _, e := Read(c, h, "spiffe://pilot/reader", now); e == nil {
			t.Fatal("invalid handle accepted")
		}
	}
	if e := os.Symlink(filepath.Join(c.Directory, ".publication-incomplete"), filepath.Join(c.Directory, b.Observation[7:]+".json")); e != nil {
		t.Fatal(e)
	}
	if _, e := Read(c, handle, "spiffe://pilot/reader", now); e == nil {
		t.Fatal("symlink publication trusted")
	}
}

// Only Fleet writes publications. This helper emits the interoperable format
// solely for the observation consumer's read-side tests.
func publishFixture(c Config, b Batch, now time.Time) (string, error) {
	if e := validateBatch(c, b, now); e != nil {
		return "", e
	}
	raw, _ := json.Marshal(b)
	raw, _ = wire.Canonical(raw)
	path := filepath.Join(c.Directory, b.Observation[7:]+".json")
	if old, e := os.ReadFile(path); e == nil {
		if string(old) != string(raw) {
			return "", fmt.Errorf("fixture conflict")
		}
		return wire.Digest(raw), nil
	}
	return wire.Digest(raw), os.WriteFile(path, raw, 0640)
}
