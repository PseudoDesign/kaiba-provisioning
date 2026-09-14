//go:build linux

package campaignstaging

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
)

// Every path component must be a real trusted directory. Sticky directories
// owned by root/current uid (such as /tmp) may contain the private 0700 child.
func openDirectory(path string) (*os.File, error) {
	if !canonicalPath(path) {
		return nil, errors.New("directory path must be canonical and absolute")
	}
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	check := func(fd int) error {
		var s syscall.Stat_t
		if err := syscall.Fstat(fd, &s); err != nil {
			return err
		}
		if s.Uid != 0 && s.Uid != uint32(os.Geteuid()) {
			return errors.New("directory ancestor has an untrusted owner")
		}
		if s.Mode&0022 != 0 && s.Mode&syscall.S_ISVTX == 0 {
			return errors.New("directory ancestor is writable by another user")
		}
		return nil
	}
	if err := check(fd); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if part == "" {
			continue
		}
		next, e := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		syscall.Close(fd)
		if e != nil {
			return nil, e
		}
		fd = next
		if e := check(fd); e != nil {
			syscall.Close(fd)
			return nil, fmt.Errorf("directory component %q in %s: %w", part, path, e)
		}
	}
	return os.NewFile(uintptr(fd), path), nil
}

func ownedDirectory(path string) (*os.File, error) {
	d, err := openDirectory(path)
	if err != nil {
		return nil, err
	}
	s, err := d.Stat()
	if err != nil {
		d.Close()
		return nil, err
	}
	stat := s.Sys().(*syscall.Stat_t)
	if stat.Uid != uint32(os.Geteuid()) || s.Mode().Perm() != 0700 {
		d.Close()
		return nil, errors.New("evidence directory must be owned by the current operator with mode 0700")
	}
	return d, nil
}

func createDirectory(path string) (*os.File, error) {
	if !canonicalPath(path) || path == "/" {
		return nil, errors.New("new evidence directory must be canonical and absolute")
	}
	p, err := openDirectory(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer p.Close()
	if err := syscall.Mkdirat(int(p.Fd()), filepath.Base(path), 0700); err != nil {
		return nil, err
	}
	if err := p.Sync(); err != nil {
		return nil, err
	}
	return ownedDirectory(path)
}

func directoryIdentity(d *os.File) (FileIdentity, error) {
	s, err := d.Stat()
	if err != nil {
		return FileIdentity{}, err
	}
	st := s.Sys().(*syscall.Stat_t)
	return FileIdentity{Device: uint64(st.Dev), Inode: st.Ino}, nil
}
func revalidateDirectory(path string, d *os.File, expected FileIdentity) error {
	actual, err := directoryIdentity(d)
	if err != nil {
		return err
	}
	if actual != expected {
		return errors.New("opened evidence directory changed")
	}
	fresh, err := ownedDirectory(path)
	if err != nil {
		return err
	}
	defer fresh.Close()
	actual, err = directoryIdentity(fresh)
	if err != nil {
		return err
	}
	if actual != expected {
		return errors.New("evidence directory path changed")
	}
	return nil
}

func fileIdentity(f *os.File, evidence bool) (FileIdentity, error) {
	s, err := f.Stat()
	if err != nil {
		return FileIdentity{}, err
	}
	st := s.Sys().(*syscall.Stat_t)
	if !s.Mode().IsRegular() || s.Size() < 0 || st.Nlink == 0 {
		return FileIdentity{}, errors.New("only pinned regular files are accepted")
	}
	if evidence && (st.Nlink != 1 || st.Uid != uint32(os.Geteuid())) {
		return FileIdentity{}, errors.New("evidence must be an owned single-link regular file")
	}
	return FileIdentity{Device: uint64(st.Dev), Inode: st.Ino, Size: uint64(s.Size())}, nil
}

func openAt(d *os.File, name string, create bool) (*os.File, error) {
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name || strings.ContainsRune(name, 0) {
		return nil, errors.New("invalid evidence filename")
	}
	if create {
		fd, err := syscall.Openat(int(d.Fd()), name, syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
		if err != nil {
			return nil, err
		}
		return os.NewFile(uintptr(fd), name), nil
	}
	return openPinned(d, name, true)
}

func openPinned(d *os.File, name string, evidence bool) (*os.File, error) {
	const oPath = 0x200000
	fd, err := syscall.Openat(int(d.Fd()), name, oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	pin := os.NewFile(uintptr(fd), name)
	defer pin.Close()
	want, err := fileIdentity(pin, evidence)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(fmt.Sprintf("/proc/self/fd/%d", fd), os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	actual, err := fileIdentity(f, evidence)
	if err != nil || actual != want {
		f.Close()
		return nil, errors.New("regular-file identity changed while opening")
	}
	if evidence {
		s, err := f.Stat()
		if err != nil || s.Mode().Perm() != 0400 {
			f.Close()
			return nil, errors.New("evidence file must have mode 0400")
		}
	}
	return f, nil
}

func openSource(path string) (*os.File, error) {
	if !canonicalPath(path) {
		return nil, errors.New("source path must be canonical and absolute")
	}
	d, err := openDirectory(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer d.Close()
	return openPinned(d, filepath.Base(path), false)
}

func revalidateFile(d *os.File, r Range, f *os.File) error {
	a, err := fileIdentity(f, true)
	if err != nil {
		return err
	}
	if a != r.File {
		return errors.New("opened evidence inode changed")
	}
	fresh, err := openAt(d, r.Name, false)
	if err != nil {
		return err
	}
	defer fresh.Close()
	a, err = fileIdentity(fresh, true)
	if err != nil {
		return err
	}
	if a != r.File {
		return errors.New("evidence path attachment changed")
	}
	return nil
}

func hashRange(ctx context.Context, r io.ReaderAt, offset, size uint64) (bundle.Digest, error) {
	if err := checkedRange(offset, size); err != nil {
		return "", err
	}
	h := sha256.New()
	buf := make([]byte, 1024*1024)
	for pos := uint64(0); pos < size; {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		n := min(uint64(len(buf)), size-pos)
		got, err := r.ReadAt(buf[:n], int64(offset+pos))
		if err != nil {
			return "", err
		}
		if got != int(n) {
			return "", io.ErrUnexpectedEOF
		}
		h.Write(buf[:n])
		pos += n
	}
	return bundle.Digest("sha256:" + hex.EncodeToString(h.Sum(nil))), nil
}
func verifyRange(ctx context.Context, r io.ReaderAt, offset, size uint64, want bundle.Digest) error {
	got, err := hashRange(ctx, r, offset, size)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("readback digest differs at offset %d size %d", offset, size)
	}
	return nil
}

// sparse is admitted only for exclusive newly created regular evidence files.
// Device writes always pass false, so every zero byte overwrites old contents.
func copyRange(ctx context.Context, dst io.WriterAt, offset uint64, src io.ReaderAt, sourceOffset, size uint64, sparse bool, after func() error) (bundle.Digest, error) {
	if err := checkedRange(offset, size); err != nil {
		return "", err
	}
	if err := checkedRange(sourceOffset, size); err != nil {
		return "", err
	}
	h := sha256.New()
	buf := make([]byte, 1024*1024)
	zero := make([]byte, len(buf))
	for pos := uint64(0); pos < size; {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		n := min(uint64(len(buf)), size-pos)
		got, err := src.ReadAt(buf[:n], int64(sourceOffset+pos))
		if err != nil {
			return "", err
		}
		if got != int(n) {
			return "", io.ErrUnexpectedEOF
		}
		if !sparse || !bytes.Equal(buf[:n], zero[:n]) {
			written, err := dst.WriteAt(buf[:n], int64(offset+pos))
			if err != nil {
				return "", err
			}
			if written != int(n) {
				return "", io.ErrShortWrite
			}
		}
		h.Write(buf[:n])
		pos += n
		if after != nil {
			if err := after(); err != nil {
				return "", err
			}
		}
	}
	return bundle.Digest("sha256:" + hex.EncodeToString(h.Sum(nil))), nil
}

type paddedReader struct {
	source io.ReaderAt
	size   uint64
}

func (p paddedReader) ReadAt(b []byte, offset int64) (int, error) {
	if offset < 0 {
		return 0, errors.New("negative source offset")
	}
	clear(b)
	if uint64(offset) >= p.size {
		return len(b), nil
	}
	n := min(uint64(len(b)), p.size-uint64(offset))
	got, err := p.source.ReadAt(b[:n], offset)
	if err != nil {
		return got, err
	}
	if got != int(n) {
		return got, io.ErrUnexpectedEOF
	}
	return len(b), nil
}

func createSnapshot(ctx context.Context, d *os.File, r Range, src io.ReaderAt, sourceOffset uint64, after func() error) (Range, error) {
	f, err := openAt(d, r.Name, true)
	if err != nil {
		return r, err
	}
	closed := false
	defer func() {
		if !closed {
			f.Close()
		}
	}()
	if err := f.Truncate(int64(r.Size)); err != nil {
		return r, err
	}
	actual, err := copyRange(ctx, f, 0, src, sourceOffset, r.Size, true, after)
	if err != nil {
		return r, err
	}
	if actual != r.SHA256 {
		return r, errors.New("snapshot bytes differ from expected source digest")
	}
	if err := f.Chmod(0400); err != nil {
		return r, err
	}
	if err := f.Sync(); err != nil {
		return r, err
	}
	r.File, err = fileIdentity(f, true)
	if err != nil {
		return r, err
	}
	if err := f.Close(); err != nil {
		return r, err
	}
	closed = true
	if err := d.Sync(); err != nil {
		return r, err
	}
	if err := verifySnapshot(ctx, d, r); err != nil {
		return r, err
	}
	return r, nil
}

func verifySnapshot(ctx context.Context, d *os.File, r Range) error {
	f, err := openAt(d, r.Name, false)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := revalidateFile(d, r, f); err != nil {
		return err
	}
	if err := verifyRange(ctx, f, 0, r.Size, r.SHA256); err != nil {
		return err
	}
	return revalidateFile(d, r, f)
}

func createBytes(d *os.File, name string, b []byte) error {
	f, err := openAt(d, name, true)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			f.Close()
		}
	}()
	n, err := f.Write(b)
	if err != nil {
		return err
	}
	if n != len(b) {
		return io.ErrShortWrite
	}
	if err := f.Chmod(0400); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	closed = true
	return d.Sync()
}
func readBytes(d *os.File, name string) ([]byte, error) {
	f, err := openAt(d, name, false)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maximumRecordBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maximumRecordBytes {
		return nil, errors.New("evidence record exceeds fixed limit")
	}
	return b, nil
}

// O_PATH observes any marker type without opening special device drivers or
// blocking on FIFOs. A malformed marker consumes the attempt just like a valid one.
func requireUnused(d *os.File) error {
	const oPath = 0x200000
	fd, err := syscall.Openat(int(d.Fd()), "execution-started.json", oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err == nil {
		syscall.Close(fd)
		return errors.New("attempt already consumed; preserve evidence and do not retry")
	}
	if !errors.Is(err, syscall.ENOENT) {
		return err
	}
	return nil
}
