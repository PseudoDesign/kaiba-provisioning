package appliance

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/appliancewire"
)

// FileMedia is a non-production regular-file driver. It cannot open a block
// device, resize a target or choose a target from an offer. Physical qualification
// and a reviewed native boot driver are required before providing real media.
type FileMedia struct {
	dir     *os.File
	targets map[string]map[string]*os.File
	paths   map[string]map[string]string
	sizes   map[string]map[string]uint64
	Fault   func(string) error
}

func regular(f *os.File, size uint64) error {
	var st syscall.Stat_t
	if syscall.Fstat(int(f.Fd()), &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) || st.Mode&0022 != 0 || st.Size < 0 || uint64(st.Size) != size {
		return ErrDenied
	}
	return nil
}
func openFile(path string, flags int, size uint64) (*os.File, error) {
	fd, e := syscall.Open(path, flags|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, ErrDenied
	}
	f := os.NewFile(uintptr(fd), "appliance-media")
	if regular(f, size) != nil {
		f.Close()
		return nil, ErrDenied
	}
	return f, nil
}
func OpenFileMedia(blobs string, paths map[string]map[string]string, sizes map[string]map[string]uint64) (*FileMedia, error) {
	fd, e := syscall.Open(blobs, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrDenied
	}
	dir := os.NewFile(uintptr(fd), "artifact-directory")
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || st.Uid != uint32(os.Geteuid()) || st.Mode&0777 != 0700 {
		dir.Close()
		return nil, ErrDenied
	}
	m := &FileMedia{dir: dir, targets: map[string]map[string]*os.File{}, paths: paths, sizes: sizes}
	seen := map[[2]uint64]bool{}
	for _, slot := range []string{"A", "B"} {
		m.targets[slot] = map[string]*os.File{}
		for _, role := range []string{"boot", "root", "hash", "metadata"} {
			size := sizes[slot][role]
			if size == 0 || size > 9007199254740991 {
				m.Close()
				return nil, ErrDenied
			}
			f, e := openFile(paths[slot][role], syscall.O_RDWR, size)
			if e != nil {
				m.Close()
				return nil, e
			}
			var st syscall.Stat_t
			syscall.Fstat(int(f.Fd()), &st)
			identity := [2]uint64{uint64(st.Dev), st.Ino}
			if seen[identity] {
				f.Close()
				m.Close()
				return nil, ErrDenied
			}
			seen[identity] = true
			m.targets[slot][role] = f
		}
	}
	return m, nil
}
func (m *FileMedia) Close() {
	if m.dir != nil {
		m.dir.Close()
	}
	for _, slot := range m.targets {
		for _, f := range slot {
			f.Close()
		}
	}
}
func (m *FileMedia) fault(point string) error {
	if m.Fault != nil {
		return m.Fault(point)
	}
	return nil
}
func (m *FileMedia) source(a appliancewire.Artifact) (*os.File, error) {
	if !appliancewire.IsDigest(a.Digest) {
		return nil, ErrDenied
	}
	fd, e := syscall.Openat(int(m.dir.Fd()), strings.TrimPrefix(a.Digest, "sha256:"), syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, ErrDenied
	}
	f := os.NewFile(uintptr(fd), "artifact")
	if regular(f, a.Bytes) != nil {
		f.Close()
		return nil, ErrDenied
	}
	var st syscall.Stat_t
	syscall.Fstat(fd, &st)
	for _, slot := range m.targets {
		for _, target := range slot {
			var other syscall.Stat_t
			syscall.Fstat(int(target.Fd()), &other)
			if st.Dev == other.Dev && st.Ino == other.Ino {
				f.Close()
				return nil, ErrDenied
			}
		}
	}
	h := sha256.New()
	if _, e = io.Copy(h, io.NewSectionReader(f, 0, int64(a.Bytes))); e != nil || "sha256:"+hex.EncodeToString(h.Sum(nil)) != a.Digest {
		f.Close()
		return nil, ErrDenied
	}
	return f, nil
}
func (m *FileMedia) validate(image appliancewire.SlotImage) error {
	if image.Slot != "A" && image.Slot != "B" || len(image.Artifacts) != 4 {
		return ErrDenied
	}
	for i, a := range image.Artifacts {
		if a.Role != []string{"boot", "root", "hash", "metadata"}[i] || a.Bytes != m.sizes[image.Slot][a.Role] || !appliancewire.IsDigest(a.Digest) {
			return ErrDenied
		}
	}
	return nil
}
func (m *FileMedia) Install(image appliancewire.SlotImage) ([]appliancewire.Artifact, error) {
	if m.validate(image) != nil {
		return nil, ErrDenied
	}
	sources := []*os.File{}
	defer func() {
		for _, f := range sources {
			f.Close()
		}
	}()
	// Authenticate every complete artifact before touching any range.
	for _, a := range image.Artifacts {
		f, e := m.source(a)
		if e != nil {
			return nil, e
		}
		sources = append(sources, f)
	}
	for i, a := range image.Artifacts {
		if e := m.fault("before-" + a.Role); e != nil {
			return nil, e
		}
		target := m.targets[image.Slot][a.Role]
		if regular(target, a.Bytes) != nil {
			return nil, ErrDenied
		}
		if _, e := target.Seek(0, 0); e != nil {
			return nil, ErrDenied
		}
		copied, e := io.CopyN(target, io.NewSectionReader(sources[i], 0, int64(a.Bytes)), int64(a.Bytes))
		if e != nil || copied != int64(a.Bytes) {
			return nil, ErrReconcile
		}
		if e = target.Sync(); e != nil {
			return nil, ErrReconcile
		}
		if e = m.fault("after-" + a.Role); e != nil {
			return nil, e
		}
	}
	return m.Readback(image)
}
func (m *FileMedia) Readback(image appliancewire.SlotImage) ([]appliancewire.Artifact, error) {
	if m.validate(image) != nil {
		return nil, ErrDenied
	}
	out := []appliancewire.Artifact{}
	for _, a := range image.Artifacts {
		// Reopen independently and reject replacement of a pinned target inode.
		f, e := openFile(m.paths[image.Slot][a.Role], syscall.O_RDONLY, a.Bytes)
		if e != nil {
			return nil, e
		}
		original, _ := m.targets[image.Slot][a.Role].Stat()
		observed, _ := f.Stat()
		if original == nil || observed == nil || !os.SameFile(original, observed) {
			f.Close()
			return nil, ErrReconcile
		}
		h := sha256.New()
		n, e := io.Copy(h, f)
		f.Close()
		if e != nil || uint64(n) != a.Bytes {
			return nil, ErrReconcile
		}
		digest := "sha256:" + hex.EncodeToString(h.Sum(nil))
		if digest != a.Digest {
			return nil, ErrReconcile
		}
		out = append(out, appliancewire.Artifact{Role: a.Role, Bytes: a.Bytes, Digest: digest})
	}
	return out, nil
}
