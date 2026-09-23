// Package guidedcampaign runs one fixed development execution packet. It is a
// station workflow journal, not a provisioning or fleet admission authority.
package guidedcampaign

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/handoff"
)

const (
	PlanSchema   = "kaiba.station-campaign-plan/v1alpha1"
	StateSchema  = "kaiba.station-campaign-state/v1alpha1"
	ReportSchema = "kaiba.station-campaign-report/v1alpha1"
	RunnerSchema = "kaiba.station-campaign-execution/v1alpha1"
	MaxBytes     = 1024 * 1024
)

var (
	ErrInput       = errors.New("invalid campaign input")
	ErrConflict    = errors.New("campaign action conflicts with recorded state")
	ErrStore       = errors.New("campaign journal requires review")
	ErrUnavailable = errors.New("campaign authority unavailable")
	ErrDenied      = errors.New("campaign authority denied access")
	ErrInvalid     = errors.New("campaign authority returned invalid state")
	ErrProgram     = errors.New("pinned executor preflight failed")
	ErrExecution   = errors.New("executor failed")
	ErrInterrupted = errors.New("executor interrupted or timed out")
	idPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	digestPattern  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type Program struct {
	Path    string `json:"path"`
	Digest  string `json:"sha256"`
	Timeout int    `json:"timeout_seconds"`
}
type Choice struct {
	Value string `json:"value"`
	Label string `json:"label"`
}
type Input struct {
	Label   string   `json:"label"`
	Choices []Choice `json:"choices"`
}
type Step struct {
	ID          string            `json:"id"`
	Title       string            `json:"title"`
	Instruction string            `json:"instruction"`
	Button      string            `json:"button"`
	Input       *Input            `json:"input,omitempty"`
	Execute     Program           `json:"execute"`
	Reconcile   *Program          `json:"reconcile,omitempty"`
	Outputs     map[string]string `json:"outputs"`
}
type Plan struct {
	Schema  string    `json:"schema_version"`
	ID      string    `json:"campaign_id"`
	Station string    `json:"station_id"`
	Lane    string    `json:"lane_id"`
	Mode    string    `json:"mode"`
	Device  string    `json:"device_label"`
	Target  string    `json:"target_reference"`
	Profile string    `json:"profile_label"`
	Packet  string    `json:"execution_packet_digest"`
	Expires time.Time `json:"expires_at"`
	Steps   []Step    `json:"steps"`
}
type Action struct {
	ID       string `json:"request_id"`
	Revision uint64 `json:"expected_revision"`
	Action   string `json:"action"`
	Input    string `json:"input"`
}
type Execution struct {
	Schema    string `json:"schema_version"`
	Campaign  string `json:"campaign_id"`
	Plan      string `json:"plan_digest"`
	Packet    string `json:"execution_packet_digest"`
	Step      string `json:"step_id"`
	Request   string `json:"request_id"`
	Input     string `json:"input"`
	Reconcile bool   `json:"reconcile"`
}

// Result deliberately has no free-form output/log/secret field. Human text is
// supplied by the reviewed plan; executors can return only its known codes.
type Result struct {
	Schema     string   `json:"schema_version"`
	Campaign   string   `json:"campaign_id"`
	Step       string   `json:"step_id"`
	Request    string   `json:"request_id"`
	Outcome    string   `json:"outcome"`
	Code       string   `json:"result_code"`
	References []string `json:"diagnostic_references"`
}
type Attempt struct {
	Execution  Execution  `json:"execution"`
	Started    time.Time  `json:"started_at"`
	Finished   *time.Time `json:"finished_at,omitempty"`
	Outcome    string     `json:"outcome"`
	Code       string     `json:"result_code"`
	Failure    string     `json:"failure_category"`
	References []string   `json:"diagnostic_references"`
}
type Screen struct {
	Schema      string    `json:"schema_version"`
	Campaign    string    `json:"campaign_id"`
	Plan        string    `json:"plan_digest"`
	Revision    uint64    `json:"revision"`
	Mode        string    `json:"mode"`
	Device      string    `json:"device_label"`
	Profile     string    `json:"profile_label"`
	Status      string    `json:"status"`
	Step        string    `json:"step_id"`
	Number      int       `json:"step_number"`
	Total       int       `json:"step_count"`
	Title       string    `json:"title"`
	Instruction string    `json:"instruction"`
	Output      string    `json:"output"`
	Input       *Input    `json:"input,omitempty"`
	Actions     []Choice  `json:"actions"`
	Updated     time.Time `json:"updated_at"`
	Production  bool      `json:"production_enrollment"`
	Qualified   bool      `json:"hardware_qualified"`
}
type Condition struct {
	ID          string `json:"id"`
	Status      string `json:"status"`
	Requirement string `json:"requirement"`
}
type Report struct {
	Schema        string      `json:"schema_version"`
	State         Screen      `json:"state"`
	Packet        string      `json:"execution_packet_digest"`
	Target        string      `json:"target_reference"`
	Attempts      []Attempt   `json:"attempts"`
	Conditions    []Condition `json:"remaining_admission_conditions"`
	EvidenceBasis string      `json:"evidence_basis"`
	Complete      bool        `json:"campaign_complete"`
}

func Decode(b []byte, out any) error {
	if len(b) == 0 || len(b) > MaxBytes {
		return ErrInput
	}
	if _, e := handoff.Canonical(b); e != nil {
		return ErrInput
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return ErrInput
	}
	if d.Decode(new(any)) != io.EOF {
		return ErrInput
	}
	return nil
}
func digest(b []byte) string { s := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(s[:]) }
func encoded(v any) []byte   { b, _ := json.Marshal(v); return b }
func label(s string) bool {
	return len(s) > 0 && len(s) <= 512 && !strings.ContainsAny(s, "\x00\r\n\t") && strings.TrimSpace(s) == s
}
func (p Program) valid() bool {
	return filepath.IsAbs(p.Path) && filepath.Clean(p.Path) == p.Path && strings.HasPrefix(p.Path, "/nix/store/") && digestPattern.MatchString(p.Digest) && p.Timeout >= 1 && p.Timeout <= 600
}
func (p Plan) Validate() error {
	if p.Schema != PlanSchema || !idPattern.MatchString(p.ID) || !idPattern.MatchString(p.Station) || !idPattern.MatchString(p.Lane) || !idPattern.MatchString(p.Target) || !label(p.Device) || !label(p.Profile) || !digestPattern.MatchString(p.Packet) || p.Expires.IsZero() || (p.Mode != "development" && p.Mode != "software_rehearsal") || len(p.Steps) < 1 || len(p.Steps) > 32 {
		return ErrInput
	}
	seen := map[string]bool{}
	for _, s := range p.Steps {
		if !idPattern.MatchString(s.ID) || seen[s.ID] || !label(s.Title) || !label(s.Instruction) || !label(s.Button) || !s.Execute.valid() || (s.Reconcile != nil && !s.Reconcile.valid()) || len(s.Outputs) == 0 || len(s.Outputs) > 16 {
			return ErrInput
		}
		seen[s.ID] = true
		for k, v := range s.Outputs {
			if !idPattern.MatchString(k) || !label(v) {
				return ErrInput
			}
		}
		if s.Input != nil {
			if !label(s.Input.Label) || len(s.Input.Choices) < 1 || len(s.Input.Choices) > 6 {
				return ErrInput
			}
			values := map[string]bool{}
			for _, c := range s.Input.Choices {
				if !idPattern.MatchString(c.Value) || !label(c.Label) || values[c.Value] {
					return ErrInput
				}
				values[c.Value] = true
			}
		}
	}
	return nil
}
func (p Plan) Digest() string { return digest(encoded(p)) }
func (r Result) valid(x Execution, step Step) bool {
	if r.Schema != RunnerSchema || r.Campaign != x.Campaign || r.Step != x.Step || r.Request != x.Request || step.Outputs[r.Code] == "" || len(r.References) > 16 {
		return false
	}
	if r.Outcome != "succeeded" && r.Outcome != "blocked" && r.Outcome != "uncertain" && r.Outcome != "quarantined" {
		return false
	}
	for _, d := range r.References {
		if !digestPattern.MatchString(d) {
			return false
		}
	}
	return r.References != nil
}
func conditions() []Condition {
	titles := []string{"Approved profile and eligible production boot root", "Authorized boot and immutable system code", "Offline boot and normal local operation", "Protected persistent data and credentials", "Unique identity and authenticated enrollment", "Final debug/access and firmware protections", "Recovery and replacement preserve protection", "Durable activation and current membership enforcement"}
	out := make([]Condition, 8)
	for i, title := range titles {
		out[i] = Condition{"FA-0" + string(rune('1'+i)), "not_evaluated", title}
	}
	return out
}
