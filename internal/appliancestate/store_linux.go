//go:build linux

package appliancestate

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/appliancewire"
	"io"
	"os"
	"strings"
	"syscall"
)

// The state directory must already be private, owned by this service and on
// the deployment's protected filesystem. This client cannot qualify LUKS.
// Relative openat operations keep all files on the pinned directory inode.
var ErrState = errors.New("private state requires reconciliation")

type Store struct{ dir, lock *os.File }

func secureFile(f *os.File, dir bool) error {
	info, e := f.Stat()
	if e != nil {
		return ErrState
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	mode := os.FileMode(0600)
	if dir {
		mode = 0700
	}
	if !ok || st.Uid != uint32(os.Geteuid()) || info.Mode().Perm() != mode || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.IsDir() != dir || (!dir && (!info.Mode().IsRegular() || st.Nlink != 1)) {
		return ErrState
	}
	return nil
}
func Open(path string) (*Store, error) {
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrState
	}
	s := &Store{dir: os.NewFile(uintptr(fd), "private-state-directory")}
	if e = secureFile(s.dir, true); e != nil {
		s.Close()
		return nil, e
	}
	f, e := s.open(".lock", syscall.O_RDWR|syscall.O_CREAT)
	if e != nil {
		s.Close()
		return nil, e
	}
	s.lock = f
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		s.Close()
		return nil, ErrState
	}
	// A leftover temporary record could contain an unpublished generated key.
	// Preserve it and require reconciliation rather than silently generating again.
	entries, e := s.dir.ReadDir(-1)
	if e != nil {
		s.Close()
		return nil, ErrState
	}
	pending := ""
	for _, entry := range entries {
		if entry.Name() == ".lock" || entry.Name() == "state.json" {
			continue
		}
		if !strings.HasPrefix(entry.Name(), ".pending-") || len(entry.Name()) != 41 || pending != "" {
			s.Close()
			return nil, ErrState
		}
		pending = entry.Name()
	}
	if pending != "" {
		// Adopt a complete durable intent; semantic validation occurs in the caller.
		// Incomplete or ambiguous intents remain preserved reconciliation outcomes.
		f, e := s.open(pending, syscall.O_RDONLY)
		if e != nil {
			s.Close()
			return nil, ErrState
		}
		b, e := io.ReadAll(io.LimitReader(f, 1<<20+1))
		f.Close()
		_, valid := unpack(b)
		clear(b)
		if e != nil || !valid {
			s.Close()
			return nil, ErrState
		}
		if e = syscall.Renameat(int(s.dir.Fd()), pending, int(s.dir.Fd()), "state.json"); e != nil {
			s.Close()
			return nil, ErrState
		}
		if s.dir.Sync() != nil {
			s.Close()
			return nil, ErrState
		}
	}
	return s, nil
}
func (s *Store) open(name string, flags int) (*os.File, error) {
	fd, e := syscall.Openat(int(s.dir.Fd()), name, flags|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0600)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), name)
	if e = secureFile(f, false); e != nil {
		f.Close()
		return nil, e
	}
	return f, nil
}
func (s *Store) Load(value any) error {
	f, e := s.open("state.json", syscall.O_RDONLY)
	if e != nil {
		return e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if e != nil || len(b) > 1<<20 {
		return ErrState
	}
	defer clear(b)
	payload, ok := unpack(b)
	if !ok {
		return ErrState
	}
	defer clear(payload)
	return appliancewire.Decode(payload, value)
}
func (s *Store) Save(value any) error {
	payload, e := appliancewire.Encode(value)
	if e != nil || len(payload) > (1<<20)-512 {
		return ErrState
	}
	defer clear(payload)
	b, e := json.Marshal(envelope{Version: "kaiba.private-state/v1", Digest: appliancewire.Digest(payload), Payload: payload})
	if e != nil || len(b) > 1<<20 {
		return ErrState
	}
	defer clear(b)
	var nonce [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return ErrState
	}
	name := ".pending-" + hex.EncodeToString(nonce[:])
	f, e := s.open(name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL)
	if e != nil {
		return ErrState
	}
	if _, e = f.Write(b); e != nil {
		f.Close()
		return ErrState
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return ErrState
	}
	if e = f.Close(); e != nil {
		return ErrState
	}
	if e = syscall.Renameat(int(s.dir.Fd()), name, int(s.dir.Fd()), "state.json"); e != nil {
		return ErrState
	}
	return s.dir.Sync()
}
func (s *Store) Directory() *os.File { return s.dir }
func (s *Store) Close() {
	if s.lock != nil {
		s.lock.Close()
	}
	if s.dir != nil {
		s.dir.Close()
	}
}

// The checksum detects storage corruption. It is not an authenticity proof.
type envelope struct {
	Version string          `json:"version"`
	Digest  string          `json:"digest"`
	Payload json.RawMessage `json:"payload"`
}

func unpack(b []byte) ([]byte, bool) {
	var v envelope
	if appliancewire.Decode(b, &v) != nil || v.Version != "kaiba.private-state/v1" {
		return nil, false
	}
	p, e := appliancewire.Canonical(v.Payload)
	if e != nil || appliancewire.Digest(p) != v.Digest {
		return nil, false
	}
	return p, true
}
