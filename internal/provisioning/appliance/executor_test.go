package appliance

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/appliancewire"
)

type fakeBoot struct {
	current                   Observation
	old                       Observation
	next                      Observation
	trials, commits, restarts int
	commitError               bool
}

func (b *fakeBoot) Observe() (Observation, error) { return b.current, nil }
func (b *fakeBoot) Trial(slot string) error {
	b.trials++
	b.current = b.next
	b.current.Trial = true
	b.current.BootID = "trial-boot"
	return nil
}
func (b *fakeBoot) Commit(slot string) error {
	b.commits++
	if b.commitError {
		return errors.New("selector fault")
	}
	return nil
}
func (b *fakeBoot) Restart() error {
	b.restarts++
	b.current.Trial = false
	b.current.BootID = "normal-boot"
	return nil
}

type fixture struct {
	blobs       string
	dir         string
	config      Config
	runtime     Runtime
	q           Request
	offer       appliancewire.Offer
	release     appliancewire.Release
	signer      *ecdsa.PrivateKey
	media       *FileMedia
	boot        *fakeBoot
	paths       map[string]map[string]string
	now         time.Time
	certificate string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "journal")
	blobs := filepath.Join(root, "blobs")
	os.Mkdir(dir, 0700)
	os.Mkdir(blobs, 0700)
	f := &fixture{blobs: blobs, dir: dir, now: time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC), certificate: "sha256:" + strings.Repeat("e", 64), paths: map[string]map[string]string{}}
	authority, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	releaseKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f.signer = authority
	identity := appliancewire.Identity{Authority: "authority", Tenant: "tenant", Device: "device", Instance: "instance", Profile: "shipping-rpi5", Storage: 1, Slot: "management", Generation: 1, SPKI: "sha256:" + strings.Repeat("a", 64)}
	f.release = appliancewire.Release{Header: appliancewire.NewHeader("ApplianceRelease"), ID: "release-2", Profile: identity.Profile, Layout: "sha256:" + strings.Repeat("b", 64), Source: strings.Repeat("c", 40), StateFormat: 1, ReadableFormats: []uint64{1}, Catalog: "sha256:" + strings.Repeat("d", 64)}
	sizes := map[string]map[string]uint64{}
	for _, slot := range []string{"A", "B"} {
		f.paths[slot] = map[string]string{}
		sizes[slot] = map[string]uint64{}
		image := appliancewire.SlotImage{Slot: slot, RootHash: "sha256:" + strings.Repeat(strings.ToLower(slot), 64)}
		for _, role := range []string{"boot", "root", "hash", "metadata"} {
			contents := []byte(strings.Repeat(slot+role+"-", 16))
			a := appliancewire.Artifact{Role: role, Bytes: uint64(len(contents)), Digest: appliancewire.Digest(contents)}
			image.Artifacts = append(image.Artifacts, a)
			if e := os.WriteFile(filepath.Join(blobs, strings.TrimPrefix(a.Digest, "sha256:")), contents, 0600); e != nil {
				t.Fatal(e)
			}
			target := filepath.Join(root, slot+"-"+role)
			os.WriteFile(target, make([]byte, len(contents)), 0600)
			f.paths[slot][role] = target
			sizes[slot][role] = a.Bytes
		}
		f.release.Images = append(f.release.Images, image)
	}
	media, e := OpenFileMedia(blobs, f.paths, sizes)
	if e != nil {
		t.Fatal(e)
	}
	f.media = media
	t.Cleanup(media.Close)
	raw, _ := appliancewire.Encode(f.release)
	f.offer = appliancewire.Offer{Header: appliancewire.NewHeader("ApplianceUpdateOffer"), Sequence: 1, Attempt: "attempt-1", Identity: identity, Current: "release-1", Target: "release-2", Slot: "B", ReleaseDigest: appliancewire.Digest(raw), Layout: f.release.Layout, Scope: "production", Issued: f.now.Format(time.RFC3339), Expires: f.now.Add(time.Hour).Format(time.RFC3339)}
	f.q.Offer, _ = appliancewire.Sign("offer", "authority", f.offer, authority)
	f.q.Release, _ = appliancewire.Sign("release", "release", f.release, releaseKey)
	old := Observation{Release: "release-1", Slot: "A", RootHash: "sha256:" + strings.Repeat("a", 64), Catalog: f.release.Catalog, BootID: "original-boot", StateFormat: 1, ProtectedVolume: "volume", SPKI: identity.SPKI, Healthy: true}
	f.boot = &fakeBoot{current: old, old: old, next: Observation{Release: "release-2", Slot: "B", RootHash: f.release.Images[1].RootHash, Catalog: f.release.Catalog, BootID: "candidate", StateFormat: 1, ProtectedVolume: "volume", SPKI: identity.SPKI, Healthy: true}}
	f.config = Config{Identity: identity, Layout: f.release.Layout, ProtectedVolume: "volume", Scope: "production", ReleaseKeys: map[string]*ecdsa.PublicKey{"release": &releaseKey.PublicKey}, OfferKeys: map[string]*ecdsa.PublicKey{"authority": &authority.PublicKey}}
	f.runtime = Runtime{Now: func() time.Time { return f.now }, CheckVolume: func(*os.File, string) error { return nil }, Certificate: func() (string, error) { return f.certificate, nil }, Quiesce: func(op string) (appliancewire.SandboxLifecycle, error) {
		return appliancewire.SandboxLifecycle{Header: appliancewire.NewHeader("SandboxLifecycle"), Catalog: f.release.Catalog, Instance: identity.Instance, Release: "release-1", StateFormat: 1, Quiesced: true, Operation: op}, nil
	}, Resume: func(string) error { return nil }, InWindow: func(time.Time) bool { return true }, Media: media, Boot: f.boot}
	f.q.Lease = f.lease(t, "install")
	return f
}
func (f *fixture) lease(t *testing.T, phase string) appliancewire.Signed {
	t.Helper()
	raw, _ := appliancewire.Encode(f.offer)
	l := appliancewire.Lease{Header: appliancewire.NewHeader("ApplianceUpdateLease"), ID: "lease-" + phase, Attempt: f.offer.Attempt, OfferDigest: appliancewire.Digest(raw), Phase: phase, Identity: f.config.Identity, Certificate: f.certificate, Issued: f.now.Format(time.RFC3339), Expires: f.now.Add(5 * time.Minute).Format(time.RFC3339)}
	s, e := appliancewire.Sign("lease", "authority", l, f.signer)
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func (f *fixture) open(t *testing.T) *Executor {
	t.Helper()
	x, e := OpenExecutor(f.dir, f.config, f.runtime)
	if e != nil {
		t.Fatal(e)
	}
	return x
}
func TestCompleteUpdateAndDuplicateDispatch(t *testing.T) {
	f := newFixture(t)
	x := f.open(t)
	activeBefore, _ := os.ReadFile(f.paths["A"]["root"])
	r, e := x.Begin(f.q)
	if e != nil || r.Phase != "staged" {
		t.Fatalf("stage: %v %s", e, r.Phase)
	}
	if _, e = x.Begin(f.q); e != nil {
		t.Fatal("duplicate install", e)
	}
	activeAfter, _ := os.ReadFile(f.paths["A"]["root"])
	if string(activeBefore) != string(activeAfter) {
		t.Fatal("active slot changed")
	}
	if _, e = x.Activate(f.lease(t, "activate")); e != nil {
		t.Fatal(e)
	}
	if _, e = x.Activate(f.lease(t, "activate")); e != nil || f.boot.trials != 1 {
		t.Fatal("trial replay")
	}
	f.now = f.now.Add(48 * time.Hour) // Commit healthy local boot despite network expiry.
	r, e = x.Confirm()
	if e != nil || r.Phase != "committed" {
		t.Fatalf("commit: %v %s", e, r.Phase)
	}
	x.Close()
	x = f.open(t)
	defer x.Close()
	r, e = x.Confirm()
	if e != nil || r.Outcome != "confirmed" {
		t.Fatalf("normal confirmation: %v %s", e, r.Phase)
	}
	if _, e = x.Confirm(); e != nil || f.boot.commits != 1 || f.boot.restarts != 1 {
		t.Fatal("commit replay")
	}
}
func TestWrongBindingsAndNoMediaMutation(t *testing.T) {
	for _, mutation := range []string{"instance", "profile", "layout", "scope", "release", "lease", "expiry"} {
		t.Run(mutation, func(t *testing.T) {
			f := newFixture(t)
			switch mutation {
			case "instance":
				f.offer.Identity.Instance = "other"
			case "profile":
				f.offer.Identity.Profile = "other"
			case "layout":
				f.offer.Layout = "sha256:" + strings.Repeat("f", 64)
			case "scope":
				f.offer.Scope = "qualification"
				f.offer.Campaign = "sha256:" + strings.Repeat("f", 64)
			case "release":
				f.offer.ReleaseDigest = "sha256:" + strings.Repeat("f", 64)
			case "expiry":
				f.now = f.now.Add(2 * time.Hour)
			case "lease":
				f.q.Lease = f.lease(t, "activate")
			}
			f.q.Offer, _ = appliancewire.Sign("offer", "authority", f.offer, f.signer)
			x := f.open(t)
			defer x.Close()
			before, _ := os.ReadFile(f.paths["B"]["root"])
			if _, e := x.Begin(f.q); e == nil {
				t.Fatal("bad offer accepted")
			}
			after, _ := os.ReadFile(f.paths["B"]["root"])
			if string(before) != string(after) {
				t.Fatal("bad offer wrote media")
			}
		})
	}
}
func TestPowerLossAndIndependentReadback(t *testing.T) {
	for _, point := range []string{"before-boot", "after-boot", "after-root", "after-hash", "after-metadata"} {
		t.Run(point, func(t *testing.T) {
			f := newFixture(t)
			f.media.Fault = func(p string) error {
				if p == point {
					return errors.New("power loss")
				}
				return nil
			}
			x := f.open(t)
			if _, e := x.Begin(f.q); !errors.Is(e, ErrReconcile) {
				t.Fatal("fault not reconciled", e)
			}
			x.Close()
			f.media.Fault = nil
			x = f.open(t)
			defer x.Close()
			r, e := x.Reconcile()
			if point == "after-metadata" {
				if e != nil || r.Phase != "staged" {
					t.Fatal("complete interrupted write did not reconcile", e)
				}
			} else if !errors.Is(e, ErrReconcile) {
				t.Fatal("partial write accepted", e)
			}
			if f.boot.trials != 0 {
				t.Fatal("failed write dispatched boot")
			}
		})
	}
}
func TestBusyWindowCorruptionAndAmbiguousCommit(t *testing.T) {
	t.Run("window", func(t *testing.T) {
		f := newFixture(t)
		f.runtime.InWindow = func(time.Time) bool { return false }
		x := f.open(t)
		defer x.Close()
		x.Begin(f.q)
		if _, e := x.Activate(f.lease(t, "activate")); !errors.Is(e, ErrDeferred) || f.boot.trials != 0 {
			t.Fatal("activation outside window")
		}
	})
	t.Run("busy", func(t *testing.T) {
		f := newFixture(t)
		f.runtime.Quiesce = func(string) (appliancewire.SandboxLifecycle, error) {
			return appliancewire.SandboxLifecycle{}, ErrDeferred
		}
		x := f.open(t)
		defer x.Close()
		x.Begin(f.q)
		if _, e := x.Activate(f.lease(t, "activate")); !errors.Is(e, ErrDeferred) || f.boot.trials != 0 {
			t.Fatal("busy application rebooted")
		}
	})
	t.Run("corruption", func(t *testing.T) {
		f := newFixture(t)
		x := f.open(t)
		defer x.Close()
		x.Begin(f.q)
		file, _ := os.OpenFile(f.paths["B"]["root"], os.O_WRONLY, 0)
		file.WriteAt([]byte("corrupt"), 0)
		file.Close()
		if _, e := x.Activate(f.lease(t, "activate")); !errors.Is(e, ErrReconcile) || f.boot.trials != 0 {
			t.Fatal("altered staged media booted")
		}
	})
	t.Run("commit", func(t *testing.T) {
		f := newFixture(t)
		f.boot.commitError = true
		x := f.open(t)
		x.Begin(f.q)
		x.Activate(f.lease(t, "activate"))
		if _, e := x.Confirm(); !errors.Is(e, ErrReconcile) {
			t.Fatal("ambiguous commit accepted")
		}
		x.Close()
		x = f.open(t)
		defer x.Close()
		x.Reconcile()
		if f.boot.commits != 1 {
			t.Fatal("ambiguous commit repeated")
		}
	})
}
func TestProtectedStateAndTargetAlias(t *testing.T) {
	f := newFixture(t)
	f.runtime.CheckVolume = func(*os.File, string) error { return ErrDenied }
	if _, e := OpenExecutor(f.dir, f.config, f.runtime); !errors.Is(e, ErrDenied) {
		t.Fatal("missing protected mount accepted")
	}
	f.runtime.CheckVolume = func(*os.File, string) error { return nil }
	if e := os.WriteFile(filepath.Join(f.dir, ".pending-unknown"), []byte("unknown"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := OpenExecutor(f.dir, f.config, f.runtime); e == nil {
		t.Fatal("uncertain journal discarded")
	}
}

type recoveryBoot struct {
	*fakeBoot
	defaultSlot   string
	restores      int
	changedCommit bool
}

func (b *recoveryBoot) Default() (string, error)  { return b.defaultSlot, nil }
func (b *recoveryBoot) Restore(slot string) error { b.restores++; b.defaultSlot = slot; return nil }
func (b *recoveryBoot) Commit(slot string) error {
	b.commits++
	b.defaultSlot = slot
	if b.changedCommit {
		return errors.New("response lost after commit")
	}
	return nil
}
func (b *recoveryBoot) Restart() error {
	b.restarts++
	if b.defaultSlot == b.old.Slot {
		b.current = b.old
		b.current.BootID = "fallback-boot"
	} else {
		b.current = b.next
		b.current.BootID = "normal-boot"
	}
	b.current.Trial = false
	return nil
}
func TestFailedTrialAutomaticallyFallsBack(t *testing.T) {
	f := newFixture(t)
	b := &recoveryBoot{fakeBoot: f.boot, defaultSlot: "A"}
	f.runtime.Boot = b
	x := f.open(t)
	defer x.Close()
	if _, e := x.Begin(f.q); e != nil {
		t.Fatal(e)
	}
	if _, e := x.Activate(f.lease(t, "activate")); e != nil {
		t.Fatal(e)
	}
	b.current.Healthy = false
	if _, e := x.Confirm(); e != nil {
		t.Fatal(e)
	}
	r, e := x.Confirm()
	if e != nil || r.Outcome != "fallback" || r.BootID != "fallback-boot" || b.restarts != 1 || b.commits != 0 {
		t.Fatal("failed trial did not recover", e, r)
	}
	x.Confirm()
	if b.restarts != 1 {
		t.Fatal("fallback repeated")
	}
}
func TestCommitResponseLossReconcilesWithoutRepeatingCommit(t *testing.T) {
	f := newFixture(t)
	b := &recoveryBoot{fakeBoot: f.boot, defaultSlot: "A", changedCommit: true}
	f.runtime.Boot = b
	x := f.open(t)
	x.Begin(f.q)
	x.Activate(f.lease(t, "activate"))
	if _, e := x.Confirm(); e != ErrReconcile {
		t.Fatal(e)
	}
	x.Close()
	x = f.open(t)
	defer x.Close()
	if _, e := x.Reconcile(); e != nil {
		t.Fatal("proven selector commit should restart once", e)
	}
	if b.restarts != 1 {
		t.Fatal("reconciled restart count")
	}
	r, e := x.Reconcile()
	if e != nil || r.Outcome != "confirmed" || b.commits != 1 {
		t.Fatal("commit was not independently reconciled", e, r)
	}
}
