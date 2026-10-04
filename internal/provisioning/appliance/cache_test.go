package appliance

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type blobs struct {
	path  string
	short bool
	calls int
}

func (b *blobs) Artifact(d string) (io.ReadCloser, error) {
	b.calls++
	data, e := os.ReadFile(filepath.Join(b.path, strings.TrimPrefix(d, "sha256:")))
	if e != nil {
		return nil, e
	}
	if b.short {
		data = data[:len(data)/2]
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}
func TestCacheResumesInterruptedDownloadAndRejectsChangedCompleteBlob(t *testing.T) {
	f := newFixture(t)
	dir := filepath.Join(t.TempDir(), "cache")
	os.Mkdir(dir, 0700)
	source := &blobs{path: f.blobs}
	sizes := map[string]uint64{}
	for _, a := range f.release.Images[1].Artifacts {
		sizes[a.Role] = a.Bytes
	}
	cache, e := OpenCache(dir, f.config, sizes, source)
	if e != nil {
		t.Fatal(e)
	}
	defer cache.Close()
	assignment := Assignment{Offer: f.q.Offer, Release: f.q.Release}
	source.short = true
	if e = cache.Download(assignment); e != ErrReconcile {
		t.Fatal("truncated accepted", e)
	}
	source.short = false
	if e = cache.Download(assignment); e != nil {
		t.Fatal("partial cache did not retry", e)
	}
	calls := source.calls
	if e = cache.Download(assignment); e != nil || calls != source.calls {
		t.Fatal("verified cache downloaded again", e)
	}
	path := filepath.Join(dir, strings.TrimPrefix(f.release.Images[1].Artifacts[0].Digest, "sha256:"))
	data, _ := os.ReadFile(path)
	data[0] ^= 1
	os.WriteFile(path, data, 0600)
	if e = cache.Download(assignment); e == nil {
		t.Fatal("altered cache accepted")
	}
}
func TestCacheRejectsOversizedRangesAndSymlinks(t *testing.T) {
	f := newFixture(t)
	dir := filepath.Join(t.TempDir(), "cache")
	os.Mkdir(dir, 0700)
	source := &blobs{path: f.blobs}
	sizes := map[string]uint64{}
	for _, a := range f.release.Images[1].Artifacts {
		sizes[a.Role] = a.Bytes
	}
	sizes["root"]++
	cache, e := OpenCache(dir, f.config, sizes, source)
	if e != nil {
		t.Fatal(e)
	}
	defer cache.Close()
	if e = cache.Download(Assignment{Offer: f.q.Offer, Release: f.q.Release}); e == nil || source.calls != 0 {
		t.Fatal("layout range mismatch downloaded")
	}
	sizes["root"]--
	cache.max["root"]--
	a := f.release.Images[1].Artifacts[0]
	name := strings.TrimPrefix(a.Digest, "sha256:")
	os.Symlink(filepath.Join(f.blobs, name), filepath.Join(dir, name))
	if e = cache.Download(Assignment{Offer: f.q.Offer, Release: f.q.Release}); e == nil {
		t.Fatal("symlink accepted")
	}
}
