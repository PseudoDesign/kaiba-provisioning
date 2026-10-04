package appliance

import (
	w "github.com/ams-tech/nixos-kaiba-network/provisioning/internal/appliancewire"
	"testing"
	"time"
)

type updateFixture struct {
	test      *testing.T
	f         *fixture
	reports   []w.Receipt
	offline   bool
	downloads int
}

func (u *updateFixture) Poll(w.Identity) (*Assignment, error) {
	if u.offline {
		return nil, ErrDeferred
	}
	return &Assignment{Offer: u.f.q.Offer, Release: u.f.q.Release}, nil
}
func (u *updateFixture) Lease(_ w.Identity, phase string) (w.Signed, error) {
	if u.offline {
		return w.Signed{}, ErrDeferred
	}
	return u.f.lease(u.test, phase), nil
}
func (u *updateFixture) Report(r w.Receipt) error {
	if u.offline {
		return ErrDeferred
	}
	u.reports = append(u.reports, r)
	return nil
}
func agentFixture(t *testing.T) (*Agent, *fixture, *updateFixture) {
	t.Helper()
	f := newFixture(t)
	c, credentialAPI, _, _ := credentialsFixture(t)
	t.Cleanup(c.Close)
	if e := c.Maintain(credentialAPI); e != nil {
		t.Fatal(e)
	}
	f.config.Identity = c.Identity()
	f.offer.Identity = c.Identity()
	f.release.Profile = c.Identity().Profile
	raw, _ := w.Encode(f.release)
	f.offer.ReleaseDigest = w.Digest(raw)
	f.q.Offer, _ = w.Sign("offer", "authority", f.offer, f.signer)
	// The independently signed release retains its original profile in this fixture.
	f.release.Profile = "shipping-rpi5"
	if c.Identity().Profile != "shipping-rpi5" {
		t.Fatal("fixture profile")
	}
	f.q.Lease = f.lease(t, "install")
	f.certificate, _ = c.CertificateDigest()
	f.q.Lease = f.lease(t, "install")
	f.runtime.Certificate = c.CertificateDigest
	f.boot.current.SPKI = c.Identity().SPKI
	f.boot.old.SPKI = c.Identity().SPKI
	f.boot.next.SPKI = c.Identity().SPKI
	f.runtime.Quiesce = func(op string) (w.SandboxLifecycle, error) {
		return w.SandboxLifecycle{Header: w.NewHeader("SandboxLifecycle"), Catalog: f.release.Catalog, Instance: c.Identity().Instance, Release: f.offer.Current, StateFormat: 1, Quiesced: true, Operation: op}, nil
	}
	x := f.open(t)
	t.Cleanup(x.Close)
	u := &updateFixture{f: f, test: t}
	a := &Agent{Config: f.config, Now: func() time.Time { return f.now }, Credentials: c, CredentialsAPI: credentialAPI, API: u, Executor: x, Download: func(Assignment) error { u.downloads++; return nil }}
	return a, f, u
}
func TestAgentOfflineConfirmationAndOnceOnlyDispatch(t *testing.T) {
	a, f, u := agentFixture(t)
	if e := a.Tick(); e != nil {
		t.Fatal(e)
	}
	if e := a.Tick(); e != nil {
		t.Fatal(e)
	}
	u.offline = true
	if e := a.Tick(); e != ErrDeferred {
		t.Fatal(e)
	}
	if e := a.Tick(); e != ErrDeferred {
		t.Fatal(e)
	}
	snapshot, e := a.Executor.Snapshot()
	if e != nil || snapshot.Receipt.Outcome != "confirmed" || f.boot.trials != 1 || f.boot.commits != 1 || u.downloads != 1 {
		t.Fatal("offline local confirmation", e)
	}
	u.offline = false
	if e = a.Tick(); e != nil {
		t.Fatal(e)
	}
	if f.boot.trials != 1 || f.boot.commits != 1 || u.downloads != 1 {
		t.Fatal("duplicate dispatch")
	}
}
func TestAgentReportsUncertainWriteWithoutRetry(t *testing.T) {
	a, f, u := agentFixture(t)
	f.media.Fault = func(point string) error {
		if point == "after-boot" {
			return ErrReconcile
		}
		return nil
	}
	if e := a.Tick(); e != ErrReconcile {
		t.Fatal(e)
	}
	if e := a.Tick(); e != ErrReconcile {
		t.Fatal(e)
	}
	if len(u.reports) != 1 || u.reports[0].Outcome != "reconciliation" || u.downloads != 1 || f.boot.trials != 0 {
		t.Fatal("uncertain write redispatched")
	}
}
