package appliance

import (
	"crypto/sha256"
	"encoding/hex"
	w "github.com/ams-tech/nixos-kaiba-network/provisioning/internal/appliancewire"
	"io"
	"os"
	"strings"
	"syscall"
	"time"
)

type BlobSource interface {
	Artifact(string) (io.ReadCloser, error)
}
type Cache struct {
	dir    *os.File
	config Config
	max    map[string]uint64
	source BlobSource
}

// OpenCache pins a private directory. Maximum complete ranges come from the
// reviewed layout, never from an offer or remotely supplied path.
func OpenCache(path string, c Config, max map[string]uint64, source BlobSource) (*Cache, error) {
	if source == nil || len(max) != 4 {
		return nil, ErrDenied
	}
	for _, r := range []string{"boot", "root", "hash", "metadata"} {
		if max[r] == 0 {
			return nil, ErrDenied
		}
	}
	fd, e := syscall.Open(path, syscall.O_DIRECTORY|syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), path)
	st, e := f.Stat()
	if e != nil || st.Mode().Perm() != 0700 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		f.Close()
		return nil, ErrDenied
	}
	sizes := map[string]uint64{}
	for k, v := range max {
		sizes[k] = v
	}
	return &Cache{dir: f, config: c, max: sizes, source: source}, nil
}
func (c *Cache) Close() { c.dir.Close() }
func (c *Cache) open(name string, flags int) (*os.File, error) {
	fd, e := syscall.Openat(int(c.dir.Fd()), name, flags|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), name)
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Sys().(*syscall.Stat_t).Nlink != 1 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		f.Close()
		return nil, ErrDenied
	}
	return f, nil
}
func (c *Cache) Download(a Assignment) error {
	var o w.Offer
	var r w.Release
	if w.Verify("offer", a.Offer, c.config.OfferKeys, &o) != nil || o.Validate(time.Time{}, false) != nil || o.Identity != c.config.Identity || o.Layout != c.config.Layout || w.Verify("release", a.Release, c.config.ReleaseKeys, &r) != nil || r.Validate() != nil || r.ID != o.Target || r.Layout != c.config.Layout || r.Profile != c.config.Identity.Profile {
		return ErrDenied
	}
	raw, _ := w.Encode(r)
	if w.Digest(raw) != o.ReleaseDigest {
		return ErrDenied
	}
	image, e := r.Image(o.Slot)
	if e != nil {
		return ErrDenied
	}
	for _, blob := range image.Artifacts {
		if blob.Bytes != c.max[blob.Role] {
			return ErrDenied
		}
	}
	for _, blob := range image.Artifacts {
		if e = c.download(blob); e != nil {
			return e
		}
	}
	return nil
}
func (c *Cache) verify(f *os.File, b w.Artifact) error {
	st, e := f.Stat()
	if e != nil || uint64(st.Size()) != b.Bytes {
		return ErrDenied
	}
	h := sha256.New()
	n, e := io.Copy(h, f)
	if e != nil || uint64(n) != b.Bytes || "sha256:"+hex.EncodeToString(h.Sum(nil)) != b.Digest {
		return ErrDenied
	}
	return nil
}
func (c *Cache) download(b w.Artifact) error {
	name := strings.TrimPrefix(b.Digest, "sha256:")
	existing, e := c.open(name, syscall.O_RDONLY)
	if e == nil {
		defer existing.Close()
		return c.verify(existing, b)
	}
	if !os.IsNotExist(e) {
		return ErrDenied
	}
	// An incomplete content-addressed download is preserved. It cannot be confused
	// with a completed blob and is reconciled by verifying its complete digest.
	pending := name + ".download"

	f, e := c.open(pending, syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL)
	complete := false
	if e != nil {
		if !os.IsExist(e) {
			return ErrDenied
		}
		f, e = c.open(pending, syscall.O_RDWR)
		if e != nil {
			return ErrDenied
		}
		st, e := f.Stat()
		if e != nil {
			f.Close()
			return ErrDenied
		}
		if uint64(st.Size()) == b.Bytes {
			if c.verify(f, b) != nil {
				f.Close()
				return ErrReconcile
			}
			complete = true
		} else if uint64(st.Size()) < b.Bytes {
			if f.Truncate(0) != nil {
				f.Close()
				return ErrReconcile
			}
		} else {
			f.Close()
			return ErrReconcile
		}
	}
	defer f.Close()
	if !complete {
		source, e := c.source.Artifact(b.Digest)
		if e != nil {
			return e
		}
		defer source.Close()
		h := sha256.New()
		n, e := io.Copy(io.MultiWriter(f, h), io.LimitReader(source, int64(b.Bytes)+1))
		if e != nil || uint64(n) != b.Bytes || "sha256:"+hex.EncodeToString(h.Sum(nil)) != b.Digest {
			return ErrReconcile
		}
		if f.Sync() != nil {
			return ErrReconcile
		}
	}

	if e = syscall.Renameat(int(c.dir.Fd()), pending, int(c.dir.Fd()), name); e != nil {
		return ErrReconcile
	}
	if c.dir.Sync() != nil {
		return ErrReconcile
	}
	return nil
}
