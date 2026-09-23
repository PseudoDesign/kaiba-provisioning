// Package pilotexport retains reviewed existing-device observations. It performs
// no hardware inspection, qualification, admission or credential operation.
package pilotexport

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/handoff"
)

const Version = "0.2.0-draft.1"

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$`)
var commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
var timePattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:[0-5]\d:[0-5]\d(?:\.\d{1,6})?Z$`)

type Ref struct {
	URI    string `json:"uri"`
	Digest string `json:"digest"`
}
type Target struct {
	Asset    string `json:"asset_ref"`
	Identity Ref    `json:"identity_ref"`
	Storage  Ref    `json:"storage_ref"`
}
type Source struct {
	Kind        string `json:"kind"`
	Repository  string `json:"repository"`
	Commit      string `json:"commit"`
	Observation string `json:"observation_id"`
	Observed    string `json:"observed_at"`
	Inventory   Ref    `json:"inventory_ref"`
	Custody     Ref    `json:"custody_review_ref"`
	Workload    Ref    `json:"workload_review_ref"`
}
type Conditions struct {
	Target    bool `json:"target_authenticated"`
	Storage   bool `json:"encrypted_persistence_observed"`
	Custody   bool `json:"custody_review_complete"`
	Workload  bool `json:"workloads_recorded"`
	Mutation  bool `json:"unresolved_mutation"`
	Ownership bool `json:"conflicting_ownership"`
	Exposure  bool `json:"known_key_exposure"`
}
type Outcome struct {
	Outcome  string `json:"outcome"`
	Reason   string `json:"reason"`
	Evidence []Ref  `json:"evidence_refs"`
}
type Record struct {
	Contract      string             `json:"contract"`
	Version       string             `json:"contract_version"`
	ID            string             `json:"record_id"`
	Revision      uint64             `json:"revision"`
	Issued        string             `json:"issued_at"`
	Authority     string             `json:"authority_id"`
	Tenant        string             `json:"tenant_id"`
	Domain        string             `json:"security_domain_id"`
	Correlation   string             `json:"correlation_id"`
	Purpose       string             `json:"purpose"`
	Target        Target             `json:"target"`
	Source        Source             `json:"source"`
	Conditions    Conditions         `json:"conditions"`
	Qualification map[string]Outcome `json:"qualification"`
	Full          bool               `json:"full_qualification"`
	Baseline      Ref                `json:"qualification_policy_ref"`
}

func validURI(s string) bool { u, e := url.Parse(s); return e == nil && u.IsAbs() && len(s) <= 2048 }
func validTime(s string) (time.Time, error) {
	if !timePattern.MatchString(s) {
		return time.Time{}, errors.New("invalid timestamp")
	}
	return time.Parse(time.RFC3339Nano, s)
}
func (r Record) Evidence() []Ref {
	refs := []Ref{r.Target.Identity, r.Target.Storage, r.Source.Inventory, r.Source.Custody, r.Source.Workload, r.Baseline}
	for _, v := range r.Qualification {
		refs = append(refs, v.Evidence...)
	}
	return refs
}

// Parse validates the closed producer wire shape, including explicitly present
// false conditions. Admission blockers remain exportable observations.
func Parse(b []byte) (Record, []byte, error) {
	var r Record
	fail := func() (Record, []byte, error) { return Record{}, nil, errors.New("invalid pilot observation") }
	if len(b) > handoff.MaxBytes {
		return fail()
	}
	canon, e := handoff.Canonical(b)
	if e != nil || handoff.Decode(canon, &r) != nil {
		return fail()
	}
	round, _ := json.Marshal(r)
	normalized, e := handoff.Canonical(round)
	if e != nil || string(normalized) != string(canon) {
		return fail()
	}
	if r.Contract != "PilotAdoptionRecord" || r.Version != Version || r.Purpose != "existing_device_adoption" || r.Source.Kind != r.Purpose || r.Full || r.Revision == 0 || r.Revision > 9007199254740991 {
		return fail()
	}
	for _, id := range []string{r.ID, r.Authority, r.Tenant, r.Domain, r.Correlation, r.Target.Asset, r.Source.Observation} {
		if !idPattern.MatchString(id) {
			return fail()
		}
	}
	if !validURI(r.Source.Repository) || !commitPattern.MatchString(r.Source.Commit) {
		return fail()
	}
	issued, e := validTime(r.Issued)
	if e != nil {
		return fail()
	}
	observed, e := validTime(r.Source.Observed)
	if e != nil || observed.After(issued) {
		return fail()
	}
	if len(r.Qualification) != 8 {
		return fail()
	}
	for n := 1; n <= 8; n++ {
		v, ok := r.Qualification[fmt.Sprintf("FA-%02d", n)]
		if !ok || len([]rune(v.Reason)) < 1 || len([]rune(v.Reason)) > 1024 || v.Evidence == nil || len(v.Evidence) > 64 {
			return fail()
		}
		seen := map[Ref]bool{}
		for _, ref := range v.Evidence {
			if seen[ref] {
				return fail()
			}
			seen[ref] = true
		}
		switch v.Outcome {
		case "passed":
			if len(v.Evidence) == 0 {
				return fail()
			}
		case "blocked", "not_evaluated":
		default:
			return fail()
		}
	}
	for _, ref := range r.Evidence() {
		if !validURI(ref.URI) || len(ref.Digest) != 71 || ref.Digest[:7] != "sha256:" || !handoff.Hex.MatchString(ref.Digest[7:]) {
			return fail()
		}
	}
	return r, canon, nil
}
