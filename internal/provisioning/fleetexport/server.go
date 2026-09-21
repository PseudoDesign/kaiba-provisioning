package fleetexport

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/auditlog"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/controlplane"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/handoff"
)

type Authority struct {
	URL string `json:"url"`
	CA  string `json:"ca"`
}
type Config struct {
	Policy     Policy            `json:"policy"`
	Grants     handoff.Policy    `json:"access"`
	Control    Authority         `json:"control"`
	Audit      Authority         `json:"audit"`
	ClientCert string            `json:"client_cert"`
	ClientKey  string            `json:"client_key"`
	Artifacts  map[string]string `json:"artifacts"`
}
type Server struct {
	Config         Config
	Control, Audit *handoff.Client
	Root           string
	mu             sync.Mutex
	lock           *os.File
}
type saved struct {
	Input  string          `json:"input"`
	Data   json.RawMessage `json:"data"`
	Digest string          `json:"digest"`
}
type fixedControl struct{ tx controlplane.Transaction }

func (c fixedControl) GetTransaction(context.Context, string) (controlplane.Transaction, error) {
	return c.tx, nil
}

type fixedAudit []auditlog.Record

func (a fixedAudit) Records(string) []auditlog.Record { return []auditlog.Record(a) }
func NewServer(c Config, root string) (*Server, error) {
	control, e := handoff.NewClient(c.Control.URL, c.ClientCert, c.ClientKey, c.Control.CA)
	if e != nil {
		return nil, e
	}
	audit, e := handoff.NewClient(c.Audit.URL, c.ClientCert, c.ClientKey, c.Audit.CA)
	if e != nil {
		return nil, e
	}
	if e = os.MkdirAll(root, 0700); e != nil {
		return nil, e
	}
	lock, e := os.OpenFile(filepath.Join(root, ".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		lock.Close()
		return nil, errors.New("export store already in use")
	}
	s := &Server{Config: c, Control: control, Audit: audit, Root: root, lock: lock}
	for _, ref := range []EvidenceRef{c.Policy.ProfileRef, c.Policy.PostureRef, c.Policy.ReleaseRef} {
		path, ok := c.Artifacts[ref.Digest]
		if !ok {
			s.Close()
			return nil, errors.New("missing artifact")
		}
		b, e := os.ReadFile(path)
		if e != nil || Digest(b) != ref.Digest {
			s.Close()
			return nil, errors.New("artifact digest mismatch")
		}
		if e = handoff.Retain(filepath.Join(root, "artifacts", ref.Digest[7:]), b); e != nil {
			s.Close()
			return nil, e
		}
	}
	return s, nil
}
func (s *Server) Close() {
	if s.lock != nil {
		s.lock.Close()
	}
}
func (s *Server) Export(ctx context.Context, id string) (json.RawMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !handoff.ID.MatchString(id) {
		return nil, errors.New("invalid_record")
	}
	before, e := s.Control.Get(ctx, "/api/v1/handoff/"+id+"/current")
	if e != nil {
		return nil, errors.New("dependency_unavailable")
	}
	audit, e := s.Audit.Get(ctx, "/api/v1/handoff/"+id+"/current")
	if e != nil {
		return nil, errors.New("dependency_unavailable")
	}
	after, e := s.Control.Get(ctx, "/api/v1/handoff/"+id+"/current")
	if e != nil {
		return nil, errors.New("dependency_unavailable")
	}
	if string(before) != string(after) {
		return nil, errors.New("stale_state")
	}
	var tx controlplane.Transaction
	var records []auditlog.Record
	if handoff.Decode(before, &tx) != nil || handoff.Decode(audit, &records) != nil {
		return nil, errors.New("invalid_record")
	}
	b, e := Build(ctx, fixedControl{tx}, fixedAudit(records), id, s.Config.Policy)
	if e != nil {
		return nil, errors.New("evidence_binding_failed")
	}
	b.Record.Evidence = Evidence{Reference(before), Reference(audit)}
	// The observation identity covers every exported input, including policy and audit.
	b.Record.Revision = 1
	b.Record.IssuedAt = ""
	material, _ := json.Marshal(b.Record)
	input := Digest(material)
	dir := filepath.Join(s.Root, "revisions", id)
	entries, e := os.ReadDir(dir)
	if e != nil && !os.IsNotExist(e) {
		return nil, e
	}
	var latest uint64
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".handoff-") {
			continue
		}
		n, er := strconv.ParseUint(entry.Name(), 10, 64)
		if er != nil {
			return nil, errors.New("corrupt export store")
		}
		if n > latest {
			latest = n
		}
	}
	if latest > 0 {
		raw, e := os.ReadFile(filepath.Join(dir, strconv.FormatUint(latest, 10)))
		if e != nil {
			return nil, e
		}
		var prior saved
		if handoff.Decode(raw, &prior) != nil || prior.Digest != Digest(prior.Data) {
			return nil, errors.New("corrupt export store")
		}
		if prior.Input == input {
			return prior.Data, nil
		}
	}
	if latest >= 9007199254740991 {
		return nil, errors.New("revision exhausted")
	}
	b.Record.Revision = latest + 1
	b.Record.IssuedAt = time.Now().UTC().Truncate(time.Microsecond).Format("2006-01-02T15:04:05.999999Z")
	raw, _ := json.Marshal(b.Record)
	data, e := handoff.Canonical(raw)
	if e != nil {
		return nil, e
	}
	out, _ := json.Marshal(saved{input, data, Digest(data)})
	if e = handoff.Retain(filepath.Join(dir, strconv.FormatUint(latest+1, 10)), out); e != nil {
		return nil, e
	}
	return data, nil
}
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/exports/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !s.Config.Grants.Authorize(r, id) {
			handoff.Fail(w, 403, "scope_mismatch")
			return
		}
		b, e := s.Export(r.Context(), id)
		if e != nil {
			code := e.Error()
			switch code {
			case "invalid_record", "dependency_unavailable", "stale_state", "evidence_binding_failed":
			default:
				code = "export_unavailable"
			}
			handoff.Fail(w, 409, code)
			return
		}
		handoff.Write(w, 200, b)
	})
	mux.HandleFunc("GET /api/v1/exports/{id}/{revision}", func(w http.ResponseWriter, r *http.Request) {
		id, n := r.PathValue("id"), r.PathValue("revision")
		v, e := strconv.ParseUint(n, 10, 64)
		if e != nil || v == 0 || strconv.FormatUint(v, 10) != n || !s.Config.Grants.Authorize(r, id) {
			handoff.Fail(w, 403, "scope_mismatch")
			return
		}
		b, e := os.ReadFile(filepath.Join(s.Root, "revisions", id, n))
		var out saved
		if e != nil || handoff.Decode(b, &out) != nil {
			handoff.Fail(w, 404, "not_found")
			return
		}
		handoff.Write(w, 200, out.Data)
	})
	mux.HandleFunc("GET /api/v1/exports/{id}/artifacts/{hash}", func(w http.ResponseWriter, r *http.Request) {
		if !s.Config.Grants.Authorize(r, r.PathValue("id")) || !handoff.Hex.MatchString(r.PathValue("hash")) {
			handoff.Fail(w, 403, "scope_mismatch")
			return
		}
		b, e := os.ReadFile(filepath.Join(s.Root, "artifacts", r.PathValue("hash")))
		if e != nil {
			handoff.Fail(w, 404, "not_found")
			return
		}
		handoff.Write(w, 200, b)
	})
	return mux
}
