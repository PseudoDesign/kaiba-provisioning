package pilotexport

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/handoff"
)

type Selection struct {
	Path     string            `json:"path"`
	Digest   string            `json:"digest"`
	Evidence map[string]string `json:"evidence"`
}
type Config struct {
	Authority string               `json:"authority_id"`
	Tenant    string               `json:"tenant_id"`
	Domain    string               `json:"security_domain_id"`
	Access    handoff.Policy       `json:"access"`
	Records   map[string]Selection `json:"records"`
}
type retained struct {
	Record   json.RawMessage `json:"record"`
	Evidence []string        `json:"evidence"`
}
type Server struct {
	config  Config
	root    string
	current map[string]uint64
	lock    *os.File
}

func read(path string) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, handoff.MaxBytes+1))
	if e != nil {
		return nil, e
	}
	if len(b) > handoff.MaxBytes {
		return nil, errors.New("input too large")
	}
	return b, nil
}
func New(c Config, root string) (*Server, error) {
	if root == "" || !idPattern.MatchString(c.Authority) || !idPattern.MatchString(c.Tenant) || !idPattern.MatchString(c.Domain) || len(c.Records) == 0 || len(c.Access.Grants) == 0 {
		return nil, errors.New("incomplete pilot export configuration")
	}
	if e := os.MkdirAll(root, 0700); e != nil {
		return nil, e
	}
	lock, e := os.OpenFile(filepath.Join(root, ".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		lock.Close()
		return nil, e
	}
	s := &Server{c, root, map[string]uint64{}, lock}
	ok := false
	defer func() {
		if !ok {
			s.Close()
		}
	}()
	ids := map[string]bool{}
	for handle, selection := range c.Records {
		if !handoff.ID.MatchString(handle) {
			return nil, errors.New("invalid record handle")
		}
		b, e := read(selection.Path)
		if e != nil {
			return nil, e
		}
		r, canon, e := Parse(b)
		if e != nil {
			return nil, e
		}
		if handoff.Digest(canon) != selection.Digest || r.Authority != c.Authority || r.Tenant != c.Tenant || r.Domain != c.Domain || ids[r.ID] {
			return nil, errors.New("record scope or digest mismatch")
		}
		ids[r.ID] = true
		// Bind each stable transport handle permanently to one record identity.
		if e = handoff.Retain(filepath.Join(root, handle, "identity"), []byte(r.ID)); e != nil {
			return nil, e
		}
		// Refuse rollback even across restarts; old revisions remain historical only.
		entries, e := os.ReadDir(filepath.Join(root, handle, "revisions"))
		if e != nil && !os.IsNotExist(e) {
			return nil, e
		}
		var latest uint64
		for _, entry := range entries {
			if len(entry.Name()) > 0 && entry.Name()[0] == '.' {
				continue
			}
			n, er := strconv.ParseUint(entry.Name(), 10, 64)
			if n > latest {
				latest = n
			}
			if er != nil || n > r.Revision {
				return nil, errors.New("revision rollback or corrupt store")
			}
		}
		if latest > 0 && r.Revision > latest {
			priorBytes, err := read(filepath.Join(root, handle, "revisions", strconv.FormatUint(latest, 10)))
			var saved retained
			if err != nil || handoff.Decode(priorBytes, &saved) != nil {
				return nil, errors.New("corrupt previous revision")
			}
			prior, _, err := Parse(saved.Record)
			if err != nil {
				return nil, err
			}
			oldIssued, _ := validTime(prior.Issued)
			newIssued, _ := validTime(r.Issued)
			if newIssued.Before(oldIssued) {
				return nil, errors.New("issuance time regressed")
			}
			if observationInput(prior) == observationInput(r) {
				return nil, errors.New("unchanged observation must retain its revision and issuance time")
			}
		}
		out := retained{Record: canon, Evidence: []string{}}
		for _, ref := range r.Evidence() {
			path, found := selection.Evidence[ref.Digest]
			if !found {
				return nil, errors.New("missing retained evidence")
			}
			data, e := read(path)
			if e != nil || handoff.Digest(data) != ref.Digest {
				return nil, errors.New("evidence digest mismatch")
			}
			if e = handoff.Retain(filepath.Join(root, handle, "evidence", ref.Digest[7:]), data); e != nil {
				return nil, e
			}
			out.Evidence = append(out.Evidence, ref.Digest)
		}
		// Evidence iteration order must not affect immutable revision identity.
		data, e := stableRetained(out)
		if e != nil {
			return nil, e
		}
		if e = handoff.Retain(filepath.Join(root, handle, "revisions", strconv.FormatUint(r.Revision, 10)), data); e != nil {
			return nil, e
		}
		s.current[handle] = r.Revision
	}
	ok = true
	return s, nil
}
func (s *Server) Close() {
	if s.lock != nil {
		s.lock.Close()
	}
}
func (s *Server) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /api/v1/pilot/records/{id}/current", func(w http.ResponseWriter, r *http.Request) { s.record(w, r, s.current[r.PathValue("id")]) })
	m.HandleFunc("GET /api/v1/pilot/records/{id}/revisions/{revision}", func(w http.ResponseWriter, r *http.Request) {
		v, e := strconv.ParseUint(r.PathValue("revision"), 10, 64)
		if e != nil || strconv.FormatUint(v, 10) != r.PathValue("revision") {
			handoff.Fail(w, 400, "invalid_revision")
			return
		}
		s.record(w, r, v)
	})
	m.HandleFunc("GET /api/v1/pilot/records/{id}/evidence/{hash}", func(w http.ResponseWriter, r *http.Request) {
		id, h := r.PathValue("id"), r.PathValue("hash")
		if !s.authorized(r, id) || !handoff.Hex.MatchString(h) {
			handoff.Fail(w, 403, "scope_mismatch")
			return
		}
		data, e := read(filepath.Join(s.root, id, "evidence", h))
		if e != nil || handoff.Digest(data) != "sha256:"+h {
			handoff.Fail(w, 404, "not_found")
			return
		}
		handoff.Write(w, 200, data)
	})
	return m
}
func (s *Server) authorized(r *http.Request, id string) bool {
	return s.current[id] > 0 && s.config.Access.Authorize(r, id)
}
func (s *Server) record(w http.ResponseWriter, r *http.Request, revision uint64) {
	id := r.PathValue("id")
	if !s.authorized(r, id) {
		handoff.Fail(w, 403, "scope_mismatch")
		return
	}
	data, e := read(filepath.Join(s.root, id, "revisions", strconv.FormatUint(revision, 10)))
	var out retained
	if e != nil || handoff.Decode(data, &out) != nil {
		handoff.Fail(w, 404, "not_found")
		return
	}
	_, canon, e := Parse(out.Record)
	if e != nil || (revision == s.current[id] && handoff.Digest(canon) != s.config.Records[id].Digest) {
		handoff.Fail(w, 503, "corrupt_record")
		return
	}
	handoff.Write(w, 200, canon)
}

func observationInput(r Record) string {
	r.Revision = 0
	r.Issued = ""
	b, _ := json.Marshal(r)
	b, _ = handoff.Canonical(b)
	return string(b)
}
