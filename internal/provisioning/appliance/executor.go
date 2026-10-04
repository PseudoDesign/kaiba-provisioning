// Package appliance implements bounded appliance update transactions.
package appliance

import (
	"crypto/ecdsa"
	"errors"
	"os"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/appliancestate"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/appliancewire"
)

var ErrDenied = errors.New("appliance transition denied")
var ErrReconcile = errors.New("appliance transition requires reconciliation")
var ErrDeferred = errors.New("appliance activation deferred")

type Observation struct {
	Release         string
	Slot            string
	RootHash        string
	Catalog         string
	BootID          string
	StateFormat     uint64
	ProtectedVolume string
	SPKI            string
	Healthy         bool
	Trial           bool
}
type Media interface {
	Install(appliancewire.SlotImage) ([]appliancewire.Artifact, error)
	Readback(appliancewire.SlotImage) ([]appliancewire.Artifact, error)
}

// Boot implementations must observe real boot identity and provide a reset path
// before userspace. File/VM drivers establish software behavior, not qualification.
type Boot interface {
	Observe() (Observation, error)
	Trial(string) error
	Commit(string) error
	Restart() error
}

// RecoveryBoot is implemented only by a qualified selector adapter. Default
// independently reopens the selector; Restore is bounded to a configured slot.
type RecoveryBoot interface {
	Default() (string, error)
	Restore(string) error
}
type Runtime struct {
	Now         func() time.Time
	CheckVolume func(*os.File, string) error
	Certificate func() (string, error)
	Quiesce     func(string) (appliancewire.SandboxLifecycle, error)
	Resume      func(string) error
	InWindow    func(time.Time) bool
	Media       Media
	Boot        Boot
}
type Config struct {
	Identity           appliancewire.Identity
	Layout             string
	ProtectedVolume    string
	Scope              string
	QualificationGrant string
	ReleaseKeys        map[string]*ecdsa.PublicKey
	OfferKeys          map[string]*ecdsa.PublicKey
}
type Request struct {
	Offer   appliancewire.Signed `json:"offer"`
	Release appliancewire.Signed `json:"release"`
	Lease   appliancewire.Signed `json:"lease"`
}
type attempt struct {
	Offer                 appliancewire.Offer      `json:"offer"`
	SignedOffer           appliancewire.Signed     `json:"signed_offer"`
	SignedRelease         appliancewire.Signed     `json:"signed_release"`
	InstallAuthorization  appliancewire.Signed     `json:"install_authorization"`
	ActivateAuthorization *appliancewire.Signed    `json:"activation_authorization,omitempty"`
	Release               appliancewire.Release    `json:"release"`
	OfferDigest           string                   `json:"offer_digest"`
	InstallLease          string                   `json:"install_lease_id"`
	ActivateLease         string                   `json:"activation_lease_id,omitempty"`
	Phase                 string                   `json:"phase"`
	Sequence              uint64                   `json:"journal_sequence"`
	BeforeBoot            string                   `json:"before_boot_id"`
	Before                Observation              `json:"before_boot"`
	Artifacts             []appliancewire.Artifact `json:"readback"`
	BootID                string                   `json:"observed_boot_id,omitempty"`
	FailurePhase          string                   `json:"failure_phase,omitempty"`
	RestartBoot           string                   `json:"restart_from_boot_id,omitempty"`
}
type executorState struct {
	Version  string                 `json:"version"`
	Identity appliancewire.Identity `json:"identity"`
	Layout   string                 `json:"layout_digest"`
	Highest  uint64                 `json:"highest_attempt_sequence"`
	Active   *attempt               `json:"active,omitempty"`
}
type Executor struct {
	store   *appliancestate.Store
	config  Config
	runtime Runtime
	state   executorState
}

func OpenExecutor(path string, c Config, r Runtime) (*Executor, error) {
	if c.Identity.Validate() != nil || !appliancewire.IsDigest(c.Layout) || c.ProtectedVolume == "" || len(c.ReleaseKeys) == 0 || len(c.OfferKeys) == 0 || r.Now == nil || r.Certificate == nil || r.Media == nil || r.Boot == nil || r.Quiesce == nil || r.Resume == nil || r.InWindow == nil {
		return nil, ErrDenied
	}
	if c.Scope != "production" && c.Scope != "qualification" {
		return nil, ErrDenied
	}
	if (c.QualificationGrant != "" && !appliancewire.IsDigest(c.QualificationGrant)) || (c.Scope == "qualification" && c.QualificationGrant == "") {
		return nil, ErrDenied
	}
	for _, a := range c.ReleaseKeys {
		for _, b := range c.OfferKeys {
			if a == nil || b == nil || a.Equal(b) {
				return nil, ErrDenied
			}
		}
	}
	s, e := appliancestate.Open(path)
	if e != nil {
		return nil, e
	}
	check := r.CheckVolume
	if check == nil {
		check = VerifyProtectedDirectory
	}
	if e = check(s.Directory(), c.ProtectedVolume); e != nil {
		s.Close()
		return nil, ErrDenied
	}
	x := &Executor{store: s, config: c, runtime: r}
	e = s.Load(&x.state)
	if os.IsNotExist(e) {
		x.state = executorState{Version: "kaiba.appliance-executor/v1", Identity: c.Identity, Layout: c.Layout}
		e = s.Save(x.state)
	}
	if e != nil || x.state.Version != "kaiba.appliance-executor/v1" || x.state.Identity != c.Identity || x.state.Layout != c.Layout {
		s.Close()
		return nil, ErrReconcile
	}
	if a := x.state.Active; a != nil {
		if x.verifyStored(a) != nil || a.Offer.Validate(time.Time{}, false) != nil || a.Release.Validate() != nil || a.Offer.Identity != c.Identity || a.Offer.Layout != c.Layout || !x.scope(a.Offer) || a.Release.ID != a.Offer.Target || a.Release.Profile != c.Identity.Profile || a.Release.Layout != c.Layout || a.Offer.Sequence != x.state.Highest || a.Sequence == 0 || !validPhase(a.Phase) {
			s.Close()
			return nil, ErrReconcile
		}
	}
	return x, nil
}
func (x *Executor) Close() { x.store.Close() }
func validPhase(p string) bool {
	switch p {
	case "writing", "staged", "trial_arming", "trial", "committing", "committed", "confirmed", "fallback", "fallback_pending", "reconciliation":
		return true
	}
	return false
}
func (x *Executor) protected() bool {
	check := x.runtime.CheckVolume
	if check == nil {
		check = VerifyProtectedDirectory
	}
	return check(x.store.Directory(), x.config.ProtectedVolume) == nil
}
func (x *Executor) scope(o appliancewire.Offer) bool {
	return (o.Scope == "production" && x.config.Scope == "production" && o.Campaign == "") || (o.Scope == "qualification" && x.config.QualificationGrant != "" && o.Campaign == x.config.QualificationGrant)
}
func (x *Executor) save(phase string) error {
	if !x.protected() {
		return ErrReconcile
	}
	x.state.Active.Phase = phase
	x.state.Active.Sequence++
	if e := x.store.Save(x.state); e != nil {
		return ErrReconcile
	}
	return nil
}
func sameArtifacts(a, b []appliancewire.Artifact) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func (x *Executor) lease(s appliancewire.Signed, phase string, a *attempt) (appliancewire.Lease, error) {
	var l appliancewire.Lease
	if appliancewire.Verify("lease", s, x.config.OfferKeys, &l) != nil || l.Validate(x.runtime.Now(), true) != nil || l.Identity != x.config.Identity || l.Attempt != a.Offer.Attempt || l.OfferDigest != a.OfferDigest || l.Phase != phase {
		return l, ErrDenied
	}
	cert, e := x.runtime.Certificate()
	if e != nil || cert != l.Certificate {
		return l, ErrDenied
	}
	return l, nil
}
func (x *Executor) prestate(o appliancewire.Offer) (Observation, error) {
	s, e := x.runtime.Boot.Observe()
	if e != nil || s.Release != o.Current || s.Slot == o.Slot || (s.Slot != "A" && s.Slot != "B") || s.ProtectedVolume != x.config.ProtectedVolume || s.SPKI != x.config.Identity.SPKI || s.BootID == "" || !appliancewire.IsDigest(s.RootHash) || !appliancewire.IsDigest(s.Catalog) || s.StateFormat == 0 || !s.Healthy || s.Trial {
		return s, ErrDenied
	}
	return s, nil
}
func (x *Executor) Begin(q Request) (appliancewire.Receipt, error) {
	var o appliancewire.Offer
	var release appliancewire.Release
	if appliancewire.Verify("offer", q.Offer, x.config.OfferKeys, &o) != nil || o.Validate(time.Time{}, false) != nil || o.Identity != x.config.Identity || o.Layout != x.config.Layout || !x.scope(o) || !x.protected() {
		return appliancewire.Receipt{}, ErrDenied
	}
	raw, e := appliancewire.Encode(o)
	if e != nil {
		return appliancewire.Receipt{}, ErrDenied
	}
	digest := appliancewire.Digest(raw)
	if a := x.state.Active; a != nil && a.Offer.Attempt == o.Attempt {
		if a.OfferDigest != digest {
			return appliancewire.Receipt{}, ErrDenied
		}
		return x.Status()
	}
	if o.Sequence <= x.state.Highest || (x.state.Active != nil && x.state.Active.Phase != "confirmed" && x.state.Active.Phase != "fallback") {
		return appliancewire.Receipt{}, ErrReconcile
	}
	if appliancewire.Verify("release", q.Release, x.config.ReleaseKeys, &release) != nil || release.Validate() != nil || release.ID != o.Target || release.Profile != o.Identity.Profile || release.Layout != o.Layout {
		return appliancewire.Receipt{}, ErrDenied
	}
	raw, e = appliancewire.Encode(release)
	if e != nil || appliancewire.Digest(raw) != o.ReleaseDigest {
		return appliancewire.Receipt{}, ErrDenied
	}
	observed, e := x.prestate(o)
	if e != nil {
		return appliancewire.Receipt{}, e
	}
	// No state migration in the updater. Both releases must read the same state.
	compatible := false
	for _, f := range release.ReadableFormats {
		if f == observed.StateFormat {
			compatible = true
		}
	}
	if !compatible || release.StateFormat != observed.StateFormat {
		return appliancewire.Receipt{}, ErrDenied
	}
	a := &attempt{Offer: o, Release: release, SignedOffer: q.Offer, SignedRelease: q.Release, InstallAuthorization: q.Lease, OfferDigest: digest, BeforeBoot: observed.BootID, Before: observed}
	l, e := x.lease(q.Lease, "install", a)
	if e != nil {
		return appliancewire.Receipt{}, e
	}
	a.InstallLease = l.ID
	x.state.Active = a
	x.state.Highest = o.Sequence
	if e = x.save("writing"); e != nil {
		return appliancewire.Receipt{}, e
	}
	image, _ := release.Image(o.Slot)
	written, e := x.runtime.Media.Install(image)
	if e != nil || !sameArtifacts(written, image.Artifacts) {
		return x.reconcileResult()
	}
	read, e := x.runtime.Media.Readback(image)
	if e != nil || !sameArtifacts(read, image.Artifacts) {
		return x.reconcileResult()
	}
	a.Artifacts = read
	if e = x.save("staged"); e != nil {
		return appliancewire.Receipt{}, e
	}
	return x.Status()
}
func (x *Executor) reconcileResult() (appliancewire.Receipt, error) {
	x.state.Active.FailurePhase = x.state.Active.Phase
	if e := x.save("reconciliation"); e != nil {
		return appliancewire.Receipt{}, e
	}
	r, _ := x.Status()
	return r, ErrReconcile
}
func (x *Executor) Activate(s appliancewire.Signed) (appliancewire.Receipt, error) {
	a := x.state.Active
	if a == nil || !x.protected() {
		return appliancewire.Receipt{}, ErrDenied
	}
	if a.Phase != "staged" {
		return x.Status()
	}
	if !x.runtime.InWindow(x.runtime.Now()) {
		return appliancewire.Receipt{}, ErrDeferred
	}
	observed, e := x.prestate(a.Offer)
	if e != nil {
		return appliancewire.Receipt{}, e
	}
	l, e := x.lease(s, "activate", a)
	if e != nil || l.ID == a.InstallLease {
		return appliancewire.Receipt{}, ErrDenied
	}
	health, e := x.runtime.Quiesce(a.Offer.Attempt)
	if e != nil || health.Validate() != nil || health.Instance != x.config.Identity.Instance || health.Release != a.Offer.Current || health.Operation != a.Offer.Attempt || health.Catalog != observed.Catalog || health.StateFormat != a.Release.StateFormat || !health.Quiesced {
		x.runtime.Resume(a.Offer.Attempt)
		return appliancewire.Receipt{}, ErrDeferred
	}
	// Recheck authorization after draining, before any boot-selection action.
	if _, e = x.lease(s, "activate", a); e != nil {
		x.runtime.Resume(a.Offer.Attempt)
		return appliancewire.Receipt{}, e
	}
	image, _ := a.Release.Image(a.Offer.Slot)
	read, e := x.runtime.Media.Readback(image)
	if e != nil || !sameArtifacts(read, image.Artifacts) {
		x.runtime.Resume(a.Offer.Attempt)
		return x.reconcileResult()
	}
	a.ActivateLease = l.ID
	a.ActivateAuthorization = &s
	if e = x.save("trial_arming"); e != nil {
		return appliancewire.Receipt{}, e
	}
	if e = x.runtime.Boot.Trial(a.Offer.Slot); e != nil {
		return x.reconcileResult()
	}
	if e = x.save("trial"); e != nil {
		return appliancewire.Receipt{}, e
	}
	return x.Status()
}

// Confirm is a local boot operation. An expired network certificate does not
// invalidate an already-dispatched trial or healthy offline operation.
func (x *Executor) Confirm() (appliancewire.Receipt, error) {
	a := x.state.Active
	if a == nil || !x.protected() {
		return appliancewire.Receipt{}, ErrDenied
	}
	s, e := x.runtime.Boot.Observe()
	if e == nil {
		a.BootID = s.BootID
	}
	if e != nil {
		return x.reconcileResult()
	}
	if a.Phase == "confirmed" || a.Phase == "fallback" {
		return x.Status()
	}
	if a.Phase != "trial" && a.Phase != "trial_arming" && a.Phase != "committing" && a.Phase != "committed" && a.Phase != "fallback_pending" {
		return appliancewire.Receipt{}, ErrReconcile
	}
	if s.Slot != a.Offer.Slot {
		if s.Slot == a.Before.Slot && s.RootHash == a.Before.RootHash && s.Catalog == a.Before.Catalog && s.StateFormat == a.Before.StateFormat && s.Release == a.Offer.Current && !s.Trial && s.BootID != "" && s.BootID != a.BeforeBoot && s.Healthy && s.ProtectedVolume == x.config.ProtectedVolume && s.SPKI == x.config.Identity.SPKI {
			if e = x.save("fallback"); e != nil {
				return appliancewire.Receipt{}, e
			}
			return x.Status()
		}
		return x.reconcileResult()
	}
	if a.Phase == "fallback_pending" {
		return x.fallback()
	}
	image, _ := a.Release.Image(s.Slot)
	if s.BootID == "" || s.BootID == a.BeforeBoot || s.Release != a.Offer.Target || s.RootHash != image.RootHash || s.Catalog != a.Release.Catalog || s.StateFormat != a.Release.StateFormat || s.ProtectedVolume != x.config.ProtectedVolume || s.SPKI != x.config.Identity.SPKI || !s.Healthy {
		return x.fallback()
	}
	read, e := x.runtime.Media.Readback(image)
	if e != nil || !sameArtifacts(read, image.Artifacts) {
		return x.reconcileResult()
	}
	if (a.Phase == "trial" || a.Phase == "trial_arming") && !s.Trial {
		return x.reconcileResult()
	}
	if a.Phase == "committed" && !s.Trial {
		if e = x.save("confirmed"); e != nil {
			return appliancewire.Receipt{}, e
		}
		return x.Status()
	}
	// Ambiguous selector commits require the boot driver's independently qualified
	// reconciliation behavior; this method never blindly repeats Commit.
	if a.Phase == "committing" {
		return x.reconcileResult()
	}
	if a.Phase == "committed" {
		if a.RestartBoot != "" {
			return appliancewire.Receipt{}, ErrReconcile
		}
		driver, ok := x.runtime.Boot.(RecoveryBoot)
		if !ok {
			return appliancewire.Receipt{}, ErrReconcile
		}
		selected, e := driver.Default()
		if e != nil || selected != a.Offer.Slot {
			return x.reconcileResult()
		}
		a.RestartBoot = s.BootID
		if e = x.save("committed"); e != nil {
			return appliancewire.Receipt{}, e
		}
		if e = x.runtime.Boot.Restart(); e != nil {
			return x.reconcileResult()
		}
		return x.Status()
	}
	if e = x.save("committing"); e != nil {
		return appliancewire.Receipt{}, e
	}
	if e = x.runtime.Boot.Commit(s.Slot); e != nil {
		return x.reconcileResult()
	}
	a.RestartBoot = s.BootID
	if e = x.save("committed"); e != nil {
		return appliancewire.Receipt{}, e
	}
	if e = x.runtime.Boot.Restart(); e != nil {
		return x.reconcileResult()
	}
	return x.Status()
}

// Reconcile verifies an interrupted inactive-slot write without repeating it.
func (x *Executor) Reconcile() (appliancewire.Receipt, error) {
	a := x.state.Active
	if a == nil || !x.protected() {
		return appliancewire.Receipt{}, ErrDenied
	}
	if a.Phase != "writing" && a.Phase != "reconciliation" {
		return x.Confirm()
	}
	if a.ActivateLease != "" {
		recovery, ok := x.runtime.Boot.(RecoveryBoot)
		if !ok {
			return appliancewire.Receipt{}, ErrReconcile
		}
		current, e := recovery.Default()
		if e != nil {
			return appliancewire.Receipt{}, ErrReconcile
		}
		if (a.FailurePhase == "committing" || a.FailurePhase == "committed") && current == a.Offer.Slot {
			if e = x.save("committed"); e != nil {
				return appliancewire.Receipt{}, e
			}
			return x.Confirm()
		}
		if a.FailurePhase == "fallback_pending" {
			return x.fallback()
		}
		return appliancewire.Receipt{}, ErrReconcile
	}
	if _, e := x.prestate(a.Offer); e != nil {
		return appliancewire.Receipt{}, ErrReconcile
	}
	image, _ := a.Release.Image(a.Offer.Slot)
	read, e := x.runtime.Media.Readback(image)
	if e != nil || !sameArtifacts(read, image.Artifacts) {
		return appliancewire.Receipt{}, ErrReconcile
	}
	a.Artifacts = read
	if e = x.save("staged"); e != nil {
		return appliancewire.Receipt{}, e
	}
	return x.Status()
}
func (x *Executor) Status() (appliancewire.Receipt, error) {
	a := x.state.Active
	if a == nil || !x.protected() {
		return appliancewire.Receipt{}, ErrDenied
	}
	if a.Phase == "confirmed" || a.Phase == "fallback" {
		observed, e := x.runtime.Boot.Observe()
		expected := a.Before
		if a.Phase == "confirmed" {
			image, _ := a.Release.Image(a.Offer.Slot)
			expected = Observation{Release: a.Offer.Target, Slot: a.Offer.Slot, RootHash: image.RootHash, Catalog: a.Release.Catalog, StateFormat: a.Release.StateFormat}
		}
		if e != nil || !observed.Healthy || observed.Trial || observed.BootID == "" || observed.Release != expected.Release || observed.Slot != expected.Slot || observed.RootHash != expected.RootHash || observed.Catalog != expected.Catalog || observed.StateFormat != expected.StateFormat || observed.ProtectedVolume != x.config.ProtectedVolume || observed.SPKI != x.config.Identity.SPKI {
			return appliancewire.Receipt{}, ErrReconcile
		}
		if a.BootID != observed.BootID {
			a.BootID = observed.BootID
			if x.save(a.Phase) != nil {
				return appliancewire.Receipt{}, ErrReconcile
			}
		}
	}
	raw, e := appliancewire.Encode(x.state)
	if e != nil {
		return appliancewire.Receipt{}, ErrReconcile
	}
	outcome := "pending"
	switch a.Phase {
	case "confirmed":
		outcome = "confirmed"
	case "fallback":
		outcome = "fallback"
	case "writing", "trial_arming", "committing", "reconciliation":
		outcome = "reconciliation"
	}
	r := appliancewire.Receipt{Header: appliancewire.NewHeader("ApplianceUpdateReceipt"), Identity: x.config.Identity, Attempt: a.Offer.Attempt, OfferDigest: a.OfferDigest, Current: a.Offer.Current, Target: a.Offer.Target, Slot: a.Offer.Slot, Phase: a.Phase, Sequence: a.Sequence, Journal: appliancewire.Digest(raw), Readback: a.Artifacts, BootID: a.BootID, Outcome: outcome}
	if e = r.Validate(); e != nil {
		return r, e
	}
	return r, nil
}

func (x *Executor) verifyStored(a *attempt) error {
	var offer appliancewire.Offer
	var release appliancewire.Release
	var lease appliancewire.Lease
	if appliancewire.Verify("offer", a.SignedOffer, x.config.OfferKeys, &offer) != nil || appliancewire.Verify("release", a.SignedRelease, x.config.ReleaseKeys, &release) != nil || appliancewire.Verify("lease", a.InstallAuthorization, x.config.OfferKeys, &lease) != nil {
		return ErrReconcile
	}
	ob, e := appliancewire.Encode(offer)
	if e != nil || appliancewire.Digest(ob) != a.OfferDigest {
		return ErrReconcile
	}
	saved, e := appliancewire.Encode(a.Offer)
	if e != nil || string(saved) != string(ob) {
		return ErrReconcile
	}
	rb, e := appliancewire.Encode(release)
	if e != nil || appliancewire.Digest(rb) != offer.ReleaseDigest {
		return ErrReconcile
	}
	saved, e = appliancewire.Encode(a.Release)
	if e != nil || string(saved) != string(rb) {
		return ErrReconcile
	}
	if lease.Validate(time.Time{}, false) != nil || lease.ID != a.InstallLease || lease.Attempt != offer.Attempt || lease.Identity != offer.Identity || lease.Phase != "install" || lease.OfferDigest != a.OfferDigest {
		return ErrReconcile
	}
	if a.ActivateAuthorization != nil {
		if appliancewire.Verify("lease", *a.ActivateAuthorization, x.config.OfferKeys, &lease) != nil || lease.Validate(time.Time{}, false) != nil || lease.ID != a.ActivateLease || lease.ID == a.InstallLease || lease.Attempt != offer.Attempt || lease.Identity != offer.Identity || lease.Phase != "activate" || lease.OfferDigest != a.OfferDigest {
			return ErrReconcile
		}
	} else if a.ActivateLease != "" || a.Phase == "trial" || a.Phase == "trial_arming" || a.Phase == "committing" || a.Phase == "committed" || a.Phase == "confirmed" || a.Phase == "fallback" {
		return ErrReconcile
	}
	return nil
}

func (x *Executor) fallback() (appliancewire.Receipt, error) {
	a := x.state.Active
	driver, ok := x.runtime.Boot.(RecoveryBoot)
	if !ok {
		return x.reconcileResult()
	}
	old := "A"
	if a.Offer.Slot == "A" {
		old = "B"
	}
	current, e := driver.Default()
	if e != nil {
		return x.reconcileResult()
	}
	if a.Phase != "fallback_pending" {
		if e = x.save("fallback_pending"); e != nil {
			return appliancewire.Receipt{}, e
		}
		if current != old {
			if e = driver.Restore(old); e != nil {
				return x.reconcileResult()
			}
		}
	}
	current, e = driver.Default()
	if e != nil || current != old {
		return x.reconcileResult()
	}
	if e = x.runtime.Boot.Restart(); e != nil {
		return x.reconcileResult()
	}
	return x.Status()
}
