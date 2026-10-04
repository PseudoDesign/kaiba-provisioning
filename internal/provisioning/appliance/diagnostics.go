package appliance

import (
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/appliancestate"
	w "github.com/ams-tech/nixos-kaiba-network/provisioning/internal/appliancewire"
	"os"
	"time"
)

// DiagnosticLog is a durable bounded redacted view. Durable update status is
// obtained separately from the executor journal and its signed artifact bindings.
type DiagnosticLog struct {
	store    *appliancestate.Store
	check    func(*os.File, string) error
	volume   string
	identity w.Identity
	sequence uint64
	entries  []w.Diagnostic
}

func OpenDiagnosticLog(path string, i w.Identity, volume string, check func(*os.File, string) error) (*DiagnosticLog, error) {
	if i.Validate() != nil || volume == "" {
		return nil, ErrDenied
	}
	if check == nil {
		check = VerifyProtectedDirectory
	}
	s, e := appliancestate.Open(path)
	if e != nil {
		return nil, e
	}
	if check(s.Directory(), volume) != nil {
		s.Close()
		return nil, ErrDenied
	}
	d := &DiagnosticLog{store: s, identity: i, check: check, volume: volume}
	var saved w.Diagnostics
	e = s.Load(&saved)
	if os.IsNotExist(e) {
		return d, nil
	}
	if e != nil || saved.Validate() != nil || saved.Identity != i {
		s.Close()
		return nil, ErrReconcile
	}
	d.sequence = saved.Sequence
	d.entries = saved.Entries
	return d, nil
}
func (d *DiagnosticLog) Close() { d.store.Close() }
func (d *DiagnosticLog) Append(code, attempt string, now time.Time) error {
	entry := w.Diagnostic{Code: code, Attempt: attempt, At: now.UTC().Format(time.RFC3339)}
	q := w.Diagnostics{Header: w.NewHeader("ApplianceDiagnostics"), Identity: d.identity, Sequence: 1, Entries: []w.Diagnostic{entry}}
	if q.Validate() != nil {
		return ErrDenied
	}
	if d.check(d.store.Directory(), d.volume) != nil {
		return ErrReconcile
	}
	d.sequence++
	d.entries = append(d.entries, entry)
	if len(d.entries) > 128 {
		d.entries = d.entries[len(d.entries)-128:]
	}
	if d.store.Save(d.Snapshot()) != nil {
		return ErrReconcile
	}
	return nil
}
func (d *DiagnosticLog) Snapshot() w.Diagnostics {
	return w.Diagnostics{Header: w.NewHeader("ApplianceDiagnostics"), Identity: d.identity, Sequence: d.sequence, Entries: append([]w.Diagnostic{}, d.entries...)}
}
func (n *Network) Diagnostics(d w.Diagnostics) error {
	if d.Validate() != nil {
		return ErrDenied
	}
	var result struct {
		Recorded bool `json:"recorded"`
	}
	if e := n.post("/appliance/v1/diagnostics/report", d, &result, false); e != nil {
		return e
	}
	if !result.Recorded {
		return ErrDenied
	}
	return nil
}
