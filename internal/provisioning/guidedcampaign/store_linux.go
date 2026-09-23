package guidedcampaign

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"syscall"
)

type journal struct {
	dir, lock *os.File
	fresh     bool
}

func privateFile(f *os.File, directory bool) bool {
	i, e := f.Stat()
	if e != nil {
		return false
	}
	s, ok := i.Sys().(*syscall.Stat_t)
	want := os.FileMode(0600)
	if directory {
		want = 0700
	}
	return ok && s.Uid == uint32(os.Geteuid()) && i.Mode().Perm() == want && i.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0 && i.IsDir() == directory && (directory || (i.Mode().IsRegular() && s.Nlink == 1))
}
func openJournal(path string) (*journal, error) {
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrStore
	}
	j := &journal{dir: os.NewFile(uintptr(fd), "campaign-directory")}
	if !privateFile(j.dir, true) {
		j.close()
		return nil, ErrStore
	}
	j.lock, e = j.open(".lock", syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL)
	j.fresh = e == nil
	if errors.Is(e, os.ErrExist) {
		j.lock, e = j.open(".lock", syscall.O_RDWR)
	}
	if e != nil || syscall.Flock(int(j.lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		j.close()
		return nil, ErrStore
	}
	entries, e := j.dir.ReadDir(-1)
	if e != nil {
		j.close()
		return nil, ErrStore
	}
	for _, entry := range entries {
		if entry.Name() != ".lock" && entry.Name() != "state.json" {
			j.close()
			return nil, ErrStore
		}
	}
	return j, nil
}
func (j *journal) open(name string, flags int) (*os.File, error) {
	fd, e := syscall.Openat(int(j.dir.Fd()), name, flags|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0600)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), name)
	if !privateFile(f, false) {
		f.Close()
		return nil, ErrStore
	}
	return f, nil
}
func (j *journal) load(v any) error {
	f, e := j.open("state.json", syscall.O_RDONLY)
	if e != nil {
		return e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, MaxBytes+1))
	if e != nil {
		return ErrStore
	}
	return Decode(b, v)
}
func (j *journal) save(v any) error {
	b := encoded(v)
	if len(b) > MaxBytes {
		return ErrStore
	}
	var nonce [16]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		return ErrStore
	}
	name := ".pending-" + hex.EncodeToString(nonce[:])
	f, e := j.open(name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL)
	if e != nil {
		return ErrStore
	}
	// Failed temporaries remain for review; a restart must never discard intent.
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil {
		return ErrStore
	}
	if syscall.Renameat(int(j.dir.Fd()), name, int(j.dir.Fd()), "state.json") != nil || j.dir.Sync() != nil {
		return ErrStore
	}
	return nil
}
func (j *journal) close() {
	if j.lock != nil {
		j.lock.Close()
	}
	if j.dir != nil {
		j.dir.Close()
	}
}
