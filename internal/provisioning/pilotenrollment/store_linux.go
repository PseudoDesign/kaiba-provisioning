//go:build linux

package pilotenrollment

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"syscall"
)

// The state directory must already be private, owned by this service and on
// the deployment's protected filesystem. This client cannot qualify LUKS.
// Relative openat operations keep all files on the pinned directory inode.
type store struct{ dir, lock *os.File }

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
func openStore(path string) (*store, error) {
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrState
	}
	s := &store{dir: os.NewFile(uintptr(fd), "credential-directory")}
	if e = secureFile(s.dir, true); e != nil {
		s.close()
		return nil, e
	}
	f, e := s.open(".lock", syscall.O_RDWR|syscall.O_CREAT)
	if e != nil {
		s.close()
		return nil, e
	}
	s.lock = f
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		s.close()
		return nil, ErrState
	}
	// A leftover temporary record could contain an unpublished generated key.
	// Preserve it and require reconciliation rather than silently generating again.
	entries, e := s.dir.ReadDir(-1)
	if e != nil {
		s.close()
		return nil, ErrState
	}
	for _, entry := range entries {
		if entry.Name() != ".lock" && entry.Name() != "state.json" {
			s.close()
			return nil, ErrState
		}
	}
	return s, nil
}
func (s *store) open(name string, flags int) (*os.File, error) {
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
func (s *store) load() (state, error) {
	var value state
	f, e := s.open("state.json", syscall.O_RDONLY)
	if e != nil {
		return value, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if e != nil {
		return value, ErrState
	}
	defer clear(b)
	if e = decode(b, &value); e != nil {
		return value, ErrState
	}
	return value, value.validate()
}
func (s *store) save(value state) error {
	if value.validate() != nil {
		return ErrState
	}
	b, e := canonical(value)
	if e != nil || len(b) > maxBytes {
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
	// On a failed write retain the temporary file, making later operations stop.
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
	if e = s.dir.Sync(); e != nil {
		return ErrState
	}
	return nil
}
func (s *store) close() {
	if s.lock != nil {
		s.lock.Close()
	}
	if s.dir != nil {
		s.dir.Close()
	}
}
