//go:build linux

package campaignsandbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
)

// Traverse every directory with O_NOFOLLOW. A symlink in a parent component
// is rejected too, and the returned descriptor pins the selected directory.
func openDirectory(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("directory must be a canonical absolute path")
	}
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for _, component := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if component == "" {
			continue
		}
		next, openErr := syscall.Openat(fd, component, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		syscall.Close(fd)
		if openErr != nil {
			return nil, openErr
		}
		fd = next
	}
	return os.NewFile(uintptr(fd), path), nil
}

func ownedDirectory(path string) (*os.File, error) {
	d, err := openDirectory(path)
	if err != nil {
		return nil, err
	}
	st, err := d.Stat()
	if err != nil {
		d.Close()
		return nil, err
	}
	s := st.Sys().(*syscall.Stat_t)
	if s.Uid != uint32(os.Geteuid()) || st.Mode().Perm() != 0700 {
		d.Close()
		return nil, errors.New("sandbox directory must be owned by this user with mode 0700")
	}
	return d, nil
}

func createDirectory(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, errors.New("new sandbox directory must be a canonical absolute path")
	}
	parent, err := openDirectory(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	if err := syscall.Mkdirat(int(parent.Fd()), filepath.Base(path), 0700); err != nil {
		return nil, err
	}
	if err := parent.Sync(); err != nil {
		return nil, err
	}
	d, err := ownedDirectory(path)
	if err != nil {
		return nil, err
	}
	return d, nil
}

func simpleName(name string) bool {
	return name != "" && name != "." && name != ".." && filepath.Base(name) == name && !strings.ContainsRune(name, 0)
}

func openAt(dir *os.File, name string, flags int) (*os.File, error) {
	if !simpleName(name) {
		return nil, errors.New("sandbox filename must be one path component")
	}
	if flags&syscall.O_CREAT == 0 {
		// O_PATH obtains identity without opening a device driver, FIFO or
		// other special file. Reopen only a validated regular inode.
		const oPath = 0x200000
		fd, err := syscall.Openat(int(dir.Fd()), name, oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		pin := os.NewFile(uintptr(fd), name)
		defer pin.Close()
		if _, err := attachment(pin); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(fmt.Sprintf("/proc/self/fd/%d", fd), flags|syscall.O_NONBLOCK, 0)
		if err != nil {
			return nil, err
		}
		if _, err := attachment(f); err != nil {
			f.Close()
			return nil, err
		}
		return f, nil
	}
	if flags&syscall.O_EXCL == 0 {
		return nil, errors.New("file creation must be exclusive")
	}
	fd, err := syscall.Openat(int(dir.Fd()), name, flags|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	if _, err := attachment(f); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func openInput(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("fixture path must be canonical and absolute")
	}
	dir, err := openDirectory(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	return openAt(dir, filepath.Base(path), syscall.O_RDONLY)
}

func attachment(f *os.File) (Attachment, error) {
	st, err := f.Stat()
	if err != nil {
		return Attachment{}, err
	}
	s := st.Sys().(*syscall.Stat_t)
	if !st.Mode().IsRegular() || s.Nlink != 1 || st.Size() < 0 {
		return Attachment{}, errors.New("only single-link regular files are accepted; devices, symlinks and aliases are forbidden")
	}
	return Attachment{Device: uint64(s.Dev), Inode: s.Ino, Size: uint64(st.Size())}, nil
}

func dirAttachment(f *os.File) (Attachment, error) {
	st, err := f.Stat()
	if err != nil {
		return Attachment{}, err
	}
	s := st.Sys().(*syscall.Stat_t)
	return Attachment{Device: uint64(s.Dev), Inode: s.Ino}, nil
}

func revalidate(dir *os.File, name string, f *os.File, expected Attachment) error {
	actual, err := attachment(f)
	if err != nil {
		return err
	}
	if actual != expected {
		return errors.New("opened attachment changed")
	}
	fresh, err := openAt(dir, name, syscall.O_RDONLY)
	if err != nil {
		return err
	}
	defer fresh.Close()
	actual, err = attachment(fresh)
	if err != nil {
		return err
	}
	if actual != expected {
		return errors.New("path attachment changed")
	}
	return nil
}

func checkedRange(offset, size uint64) error {
	if size == 0 || offset > math.MaxInt64 || size > math.MaxInt64-offset {
		return errors.New("invalid bounded byte range")
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
		if _, err := r.ReadAt(buf[:n], int64(offset+pos)); err != nil {
			return "", err
		}
		h.Write(buf[:n])
		pos += n
	}
	return bundle.Digest("sha256:" + hex.EncodeToString(h.Sum(nil))), nil
}

func verifyRange(ctx context.Context, r io.ReaderAt, offset, size uint64, expected bundle.Digest) error {
	actual, err := hashRange(ctx, r, offset, size)
	if err != nil {
		return err
	}
	if actual != expected {
		return fmt.Errorf("byte readback digest differs at offset %d, size %d", offset, size)
	}
	return nil
}

// Sparse mode is used only for newly created zero-filled files. Staging
// explicitly clears zero buffers with hole punching, erasing old contents.
func copyRange(ctx context.Context, dst *os.File, targetOffset uint64, src io.ReaderAt, sourceOffset, size uint64, sparse bool, afterChunk func() error) error {
	if err := checkedRange(targetOffset, size); err != nil {
		return err
	}
	if err := checkedRange(sourceOffset, size); err != nil {
		return err
	}
	buf := make([]byte, 1024*1024)
	zero := make([]byte, len(buf))
	for pos := uint64(0); pos < size; {
		if err := ctx.Err(); err != nil {
			return err
		}
		n := min(uint64(len(buf)), size-pos)
		if _, err := src.ReadAt(buf[:n], int64(sourceOffset+pos)); err != nil {
			return err
		}
		if bytes.Equal(buf[:n], zero[:n]) {
			if !sparse {
				// A punched hole reads as zero, including over old nonzero
				// contents. This is only used on our synthetic regular files,
				// and avoids allocating the fixed 8 GiB fixture partition.
				// Unsupported filesystems fail closed instead of silently
				// pretending a zero tail was written.
				if err := syscall.Fallocate(int(dst.Fd()), 3 /* KEEP_SIZE | PUNCH_HOLE */, int64(targetOffset+pos), int64(n)); err != nil {
					return err
				}
			}
		} else {
			written, err := dst.WriteAt(buf[:n], int64(targetOffset+pos))
			if err != nil {
				return err
			}
			if written != int(n) {
				return io.ErrShortWrite
			}
		}
		pos += n
		if afterChunk != nil {
			if err := afterChunk(); err != nil {
				return err
			}
		}
	}
	return nil
}

func createBytes(dir *os.File, name string, data []byte, readonly bool) error {
	f, err := openAt(dir, name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if readonly {
		if err := f.Chmod(0400); err != nil {
			return err
		}
	}
	if err := f.Sync(); err != nil {
		return err
	}
	return dir.Sync()
}

func readBytes(dir *os.File, name string) ([]byte, error) {
	f, err := openAt(dir, name, syscall.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 4*1024*1024+1))
	if err != nil {
		return nil, err
	}
	if len(b) > 4*1024*1024 {
		return nil, errors.New("sandbox record exceeds limit")
	}
	return b, nil
}
