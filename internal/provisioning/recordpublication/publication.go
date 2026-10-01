// Package recordpublication reads immutable renewal batches from a confined
// local publisher. It grants no write API, signing authority or owner role.
package recordpublication

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	wire "github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/handoff"
)

type Grant struct {
	Principal   string   `json:"principal"`
	Enrollments []string `json:"enrollments"`
}
type Config struct {
	Directory    string  `json:"directory"`
	PublisherUID uint32  `json:"publisher_uid"`
	ReaderGID    uint32  `json:"reader_gid"`
	Delegation   string  `json:"delegation_digest"`
	From         string  `json:"not_before"`
	Expires      string  `json:"expires_at"`
	Grants       []Grant `json:"grants"`
}
type Record struct {
	Body     json.RawMessage   `json:"record"`
	Digest   string            `json:"digest"`
	Evidence map[string][]byte `json:"evidence"`
}
type Batch struct {
	Schema      string            `json:"schema_version"`
	Delegation  string            `json:"delegation_digest"`
	Enrollment  string            `json:"enrollment_id"`
	Operation   string            `json:"operation_id"`
	Observation string            `json:"observation_digest"`
	From        string            `json:"not_before"`
	Expires     string            `json:"expires_at"`
	Records     map[string]Record `json:"records"`
}

func validDigest(s string) bool {
	return strings.HasPrefix(s, "sha256:") && wire.Hex.MatchString(strings.TrimPrefix(s, "sha256:"))
}
func moment(s string) time.Time { t, _ := time.Parse(time.RFC3339Nano, s); return t }
func ValidateConfig(c Config) error {
	if !filepath.IsAbs(c.Directory) || filepath.Clean(c.Directory) != c.Directory || !validDigest(c.Delegation) || moment(c.From).IsZero() || moment(c.Expires).Sub(moment(c.From)) != 30*24*time.Hour || len(c.Grants) == 0 {
		return errors.New("invalid publication reader scope")
	}
	seen := map[string]bool{}
	for _, g := range c.Grants {
		u, err := url.Parse(g.Principal)
		if err != nil || u.Scheme != "spiffe" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || seen[g.Principal] || len(g.Enrollments) == 0 {
			return errors.New("invalid publication grant")
		}
		seen[g.Principal] = true
		members := map[string]bool{}
		for _, id := range g.Enrollments {
			if !wire.ID.MatchString(id) || members[id] {
				return errors.New("invalid publication enrollment")
			}
			members[id] = true
		}
	}
	return nil
}
func Handle(handle string) (string, bool) {
	for _, role := range []string{"adoption", "policy", "decision"} {
		suffix := "-" + role
		if strings.HasPrefix(handle, "refresh-") && strings.HasSuffix(handle, suffix) {
			id := strings.TrimSuffix(strings.TrimPrefix(handle, "refresh-"), suffix)
			return id, wire.Hex.MatchString(id)
		}
	}
	return "", false
}
func validateBatch(c Config, b Batch, now time.Time) error {
	if ValidateConfig(c) != nil || b.Schema != "kaiba.renewal-record-publication/v1alpha1" || b.Delegation != c.Delegation || b.From != c.From || b.Expires != c.Expires || now.Before(moment(c.From)) || !now.Before(moment(c.Expires)) || !wire.ID.MatchString(b.Enrollment) || !wire.ID.MatchString(b.Operation) || !validDigest(b.Observation) || len(b.Records) != 3 {
		return errors.New("publication outside approved term")
	}
	found := false
	for _, g := range c.Grants {
		for _, id := range g.Enrollments {
			found = found || id == b.Enrollment
		}
	}
	if !found {
		return errors.New("publication enrollment not permitted")
	}
	for _, role := range []string{"adoption", "policy", "decision"} {
		handle := "refresh-" + b.Observation[7:] + "-" + role
		r, ok := b.Records[handle]
		if !ok {
			return errors.New("incomplete publication")
		}
		canonical, e := wire.Canonical(r.Body)
		if e != nil || !bytes.Equal(canonical, r.Body) || wire.Digest(canonical) != r.Digest || r.Evidence == nil {
			return errors.New("corrupt publication record")
		}
		var meta struct {
			ID       string `json:"record_id"`
			Revision uint64 `json:"revision"`
		}
		if json.Unmarshal(canonical, &meta) != nil || meta.ID != handle || meta.Revision != 1 {
			return errors.New("publication identity mismatch")
		}
		for hash, data := range r.Evidence {
			if !validDigest(hash) || wire.Digest(data) != hash {
				return errors.New("corrupt publication evidence")
			}
		}
	}
	return nil
}
func directory(c Config) (*os.Root, error) {
	resolved, e := filepath.EvalSymlinks(c.Directory)
	if e != nil || resolved != c.Directory {
		return nil, errors.New("publication directory must not contain symlinks")
	}
	r, e := os.OpenRoot(c.Directory)
	if e != nil {
		return nil, e
	}
	st, e := r.Stat(".")
	if e != nil {
		r.Close()
		return nil, e
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.IsDir() || st.Mode().Perm() != 0750 || sys.Uid != c.PublisherUID || sys.Gid != c.ReaderGID {
		r.Close()
		return nil, errors.New("confined publication directory required")
	}
	return r, nil
}
func readFile(root *os.Root, name string, c Config) ([]byte, error) {
	st, e := root.Lstat(name)
	if e != nil {
		return nil, e
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.Mode().IsRegular() || st.Mode().Perm() != 0640 || sys.Uid != c.PublisherUID || sys.Gid != c.ReaderGID || sys.Nlink != 1 || st.Size() > wire.MaxBytes {
		return nil, errors.New("invalid publication file metadata")
	}
	f, e := root.Open(name)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	actual, e := f.Stat()
	if e != nil || !os.SameFile(st, actual) {
		return nil, errors.New("publication changed during read")
	}
	raw, e := io.ReadAll(io.LimitReader(f, wire.MaxBytes+1))
	if e != nil || len(raw) > wire.MaxBytes {
		return nil, errors.New("publication unavailable")
	}
	return raw, nil
}

// Read authenticates the request's principal separately from the publisher's
// filesystem identity. Each record server still validates its own role/schema.
func Read(c Config, handle, principal string, now time.Time) (Record, error) {
	var empty Record
	id, ok := Handle(handle)
	if !ok || ValidateConfig(c) != nil {
		return empty, errors.New("invalid publication handle")
	}
	root, e := directory(c)
	if e != nil {
		return empty, e
	}
	defer root.Close()
	raw, e := readFile(root, id+".json", c)
	if e != nil {
		return empty, e
	}
	var b Batch
	if wire.Decode(raw, &b) != nil || validateBatch(c, b, now) != nil || b.Observation != "sha256:"+id {
		return empty, errors.New("invalid publication batch")
	}
	for _, g := range c.Grants {
		if g.Principal == principal {
			for _, en := range g.Enrollments {
				if en == b.Enrollment {
					return b.Records[handle], nil
				}
			}
		}
	}
	return empty, errors.New("publication reader not authorized")
}
