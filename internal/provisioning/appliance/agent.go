package appliance

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	w "github.com/ams-tech/nixos-kaiba-network/provisioning/internal/appliancewire"
	"time"
)

type UpdateAPI interface {
	Poll(w.Identity) (*Assignment, error)
	Lease(w.Identity, string) (w.Signed, error)
	Report(w.Receipt) error
}

// Agent dispatches a fixed transaction vocabulary. Download verifies the release
// signature/profile/layout and every complete blob before filling the cache. It
// is supplied by the deployment adapter; it cannot select target device paths.
type Agent struct {
	Config         Config
	Now            func() time.Time
	Diagnostics    *DiagnosticLog
	Credentials    *Credentials
	CredentialsAPI CredentialAPI
	API            UpdateAPI
	Executor       LocalExecutor
	Download       func(Assignment) error
	failures       uint
}

// Tick does not gate local boot confirmation on authority availability. An
// already-started phase finishes locally, then its receipt is retried remotely.
func (a *Agent) Tick() error {
	if a.Credentials == nil || a.CredentialsAPI == nil || a.API == nil || a.Executor == nil || a.Download == nil || a.Now == nil || a.Config.Identity.Validate() != nil {
		return ErrDenied
	}
	var localError error
	snapshot, snapshotError := a.Executor.Snapshot()
	if snapshotError != nil && snapshotError != ErrReconcile {
		return snapshotError
	}
	if snapshot.Receipt != nil {
		phase := snapshot.Receipt.Phase
		switch phase {
		case "trial", "trial_arming", "committing", "committed", "fallback_pending":
			_, localError = a.Executor.Confirm()
		case "writing", "reconciliation":
			_, localError = a.Executor.Reconcile()
		}
	}
	if e := a.Credentials.Maintain(a.CredentialsAPI); e != nil {
		return e
	}
	i := a.Credentials.Identity()
	if i != a.Config.Identity {
		return ErrDenied
	}
	snapshot, e := a.Executor.Snapshot()
	if e != nil {
		return e
	}
	if snapshot.Offer != nil && (snapshot.Offer.Identity != i || snapshot.Offer.Layout != a.Config.Layout) {
		return ErrDenied
	}
	if snapshot.Receipt != nil {
		r := *snapshot.Receipt
		if e != nil {
			return e
		}
		if e = a.API.Report(r); e != nil {
			return e
		}
		if localError != nil {
			return localError
		}
		if r.Phase == "staged" {

			l, e := a.API.Lease(i, "activate")
			if e != nil {
				return e
			}
			_, e = a.Executor.Activate(l)
			return e
		}
	}
	assignment, e := a.API.Poll(i)
	if e != nil || assignment == nil {
		return e
	}
	var offer w.Offer
	if w.Verify("offer", assignment.Offer, a.Config.OfferKeys, &offer) != nil || offer.Validate(time.Time{}, false) != nil || offer.Identity != i || !agentScope(a.Config, offer) {
		return ErrDenied
	}
	if old := snapshot.Offer; old != nil && old.Attempt == offer.Attempt {
		return nil
	}
	if e = a.Download(*assignment); e != nil {
		return e
	}
	lease, e := a.API.Lease(i, "install")
	if e != nil {
		return e
	}
	r, e := a.Executor.Begin(Request{Offer: assignment.Offer, Release: assignment.Release, Lease: lease})
	if e != nil {
		return e
	}
	return a.API.Report(r)
}

// Next applies bounded exponential retry and cryptographic poll jitter. The
// ordinary interval is 15 minutes; failure retry grows from one minute to one hour.
func (a *Agent) Next(err error) time.Duration {
	base := 15 * time.Minute
	if err != nil && err != ErrDeferred {
		if a.failures < 7 {
			a.failures++
		}
		base = time.Minute * time.Duration(1<<(a.failures-1))
		if base > time.Hour {
			base = time.Hour
		}
	} else {
		a.failures = 0
	}
	var b [8]byte
	if _, e := rand.Read(b[:]); e != nil {
		return base
	}
	spread := uint64(base / 5)
	if spread == 0 {
		return base
	}
	delay := base - base/10 + time.Duration(binary.BigEndian.Uint64(b[:])%spread)
	if delay > time.Hour {
		return time.Hour
	}
	return delay
}

// Run has no inbound network listener or command-dispatch API.
func (a *Agent) Run(ctx context.Context) error {
	if ctx == nil || a.Executor == nil || a.Now == nil {
		return ErrDenied
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		err := a.Tick()
		if a.Diagnostics != nil {
			code := "poll-failed"
			attempt := ""
			if err == ErrReconcile {
				code = "reconciliation-required"
			}
			if err == ErrDeferred {
				code = "update-deferred"
			}
			snapshot, _ := a.Executor.Snapshot()
			if state := snapshot.Offer; state != nil {
				attempt = state.Attempt
				if err == nil {
					if snapshot.Receipt != nil {
						switch snapshot.Receipt.Phase {
						case "staged":
							code = "update-staged"
						case "trial":
							code = "trial-started"
						case "confirmed":
							code = "update-confirmed"
						case "fallback":
							code = "update-fallback"
						}
					}
				}
				issued, e := time.Parse(time.RFC3339, state.Issued)
				if err == ErrDeferred && e == nil && a.Now().Sub(issued) >= 7*24*time.Hour {
					code = "update-overdue"
				}
			}
			if err != nil || attempt != "" {
				if a.Diagnostics.Append(code, attempt, a.Now()) == nil {
					if api, ok := a.API.(interface{ Diagnostics(w.Diagnostics) error }); ok {
						_ = api.Diagnostics(a.Diagnostics.Snapshot())
					}
				}
			}
		}
		timer := time.NewTimer(a.Next(err))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func agentScope(c Config, o w.Offer) bool {
	return (o.Scope == "production" && c.Scope == "production" && o.Campaign == "") || (o.Scope == "qualification" && c.QualificationGrant != "" && o.Campaign == c.QualificationGrant)
}
