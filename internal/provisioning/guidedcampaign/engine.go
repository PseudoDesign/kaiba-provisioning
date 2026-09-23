package guidedcampaign

import (
	"context"
	"errors"
	"os"
	"sync"
	"time"
)

type Executor interface {
	Run(context.Context, Program, Execution) (Result, error)
}
type recorded struct {
	Schema   string            `json:"schema_version"`
	Plan     string            `json:"plan_digest"`
	Revision uint64            `json:"revision"`
	Index    int               `json:"index"`
	Status   string            `json:"status"`
	Pause    bool              `json:"pause_requested"`
	Updated  time.Time         `json:"updated_at"`
	Attempts []Attempt         `json:"attempts"`
	Requests map[string]string `json:"requests"`
}
type Engine struct {
	mu       sync.Mutex
	plan     Plan
	state    recorded
	journal  *journal
	runner   Executor
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	poisoned bool
	closing  bool
	now      func() time.Time
}

func Open(ctx context.Context, path string, p Plan, runner Executor) (*Engine, error) {
	if p.Validate() != nil || runner == nil {
		return nil, ErrInput
	}
	var owned Plan
	if Decode(encoded(p), &owned) != nil {
		return nil, ErrInput
	}
	p = owned
	j, e := openJournal(path)
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithCancel(ctx)
	x := &Engine{plan: p, journal: j, runner: runner, ctx: ctx, cancel: cancel, now: time.Now}
	e = j.load(&x.state)
	if errors.Is(e, os.ErrNotExist) && j.fresh {
		x.state = recorded{Schema: StateSchema, Plan: p.Digest(), Revision: 1, Status: "ready", Updated: x.now().UTC(), Attempts: []Attempt{}, Requests: map[string]string{}}
		e = j.save(x.state)
	} else if e == nil {
		e = x.validateJournal()
	}
	if e != nil {
		cancel()
		j.close()
		return nil, ErrStore
	}
	// An interrupted command is not retried. Even a successful unrecorded return
	// requires the packet's separate read-only reconciliation operation.
	if x.state.Status == "running" {
		x.state.Status = "reconciliation_required"
		if !x.persist() {
			cancel()
			j.close()
			return nil, ErrStore
		}
	}
	return x, nil
}
func (e *Engine) validateJournal() error {
	s := e.state
	if s.Schema != StateSchema || s.Plan != e.plan.Digest() || s.Revision == 0 || s.Revision > 9007199254740000 || s.Index < 0 || s.Index > len(e.plan.Steps) || s.Attempts == nil || s.Requests == nil || len(s.Requests) > 256 || len(s.Attempts) > 128 || s.Updated.IsZero() {
		return ErrStore
	}
	switch s.Status {
	case "ready", "awaiting_input", "paused", "running", "reconciliation_required", "blocked", "quarantined", "completed":
	default:
		return ErrStore
	}
	if (s.Status == "completed") != (s.Index == len(e.plan.Steps)) {
		return ErrStore
	}
	if (s.Status == "running" || s.Status == "reconciliation_required") && len(s.Attempts) == 0 {
		return ErrStore
	}
	expectedIndex := 0
	for i, a := range s.Attempts {
		if a.Execution.Schema != RunnerSchema || a.Execution.Campaign != e.plan.ID || a.Execution.Plan != s.Plan || a.Execution.Packet != e.plan.Packet || !idPattern.MatchString(a.Execution.Request) || a.Started.IsZero() {
			return ErrStore
		}
		if expectedIndex >= len(e.plan.Steps) || a.Execution.Step != e.plan.Steps[expectedIndex].ID || len(a.References) > 16 || a.References == nil {
			return ErrStore
		}
		step := e.plan.Steps[expectedIndex]
		if a.Execution.Reconcile {
			if i == 0 || s.Attempts[i-1].Execution.Step != step.ID || s.Attempts[i-1].Execution.Request != a.Execution.Request || s.Attempts[i-1].Execution.Input != a.Execution.Input || step.Reconcile == nil {
				return ErrStore
			}
			if previous := s.Attempts[i-1].Outcome; previous != "uncertain" && previous != "running" {
				return ErrStore
			}
		} else if i > 0 && s.Attempts[i-1].Outcome != "succeeded" {
			return ErrStore
		}
		if step.Input == nil {
			if a.Execution.Input != "" {
				return ErrStore
			}
		} else {
			ok := false
			for _, c := range step.Input.Choices {
				if c.Value == a.Execution.Input {
					ok = true
				}
			}
			if !ok {
				return ErrStore
			}
		}
		for _, ref := range a.References {
			if !digestPattern.MatchString(ref) {
				return ErrStore
			}
		}
		if a.Code != "" && step.Outputs[a.Code] == "" {
			return ErrStore
		}
		if a.Finished != nil && a.Finished.Before(a.Started) {
			return ErrStore
		}
		switch a.Outcome {
		case "succeeded":
			if a.Code == "" || a.Failure != "" || a.Finished == nil {
				return ErrStore
			}
			expectedIndex++
		case "blocked", "quarantined":
			if a.Code == "" || a.Finished == nil || i != len(s.Attempts)-1 {
				return ErrStore
			}
		case "uncertain":
			if a.Finished == nil {
				return ErrStore
			}
		case "running":
			if a.Code != "" || a.Finished != nil {
				return ErrStore
			}
		default:
			return ErrStore
		}
		switch a.Failure {
		case "", "executor_preflight", "executor_failed", "interrupted", "invalid_result":
		default:
			return ErrStore
		}
	}
	if s.Index != expectedIndex {
		return ErrStore
	}
	if s.Status == "ready" && (s.Index != 0 || len(s.Attempts) != 0) {
		return ErrStore
	}
	if s.Status == "awaiting_input" && e.plan.Steps[s.Index].Input == nil {
		return ErrStore
	}
	if s.Status == "paused" || s.Status == "awaiting_input" {
		if len(s.Attempts) == 0 {
			if s.Status != "awaiting_input" {
				return ErrStore
			}
		} else if s.Attempts[len(s.Attempts)-1].Outcome != "succeeded" {
			return ErrStore
		}
	}
	if s.Status == "quarantined" || (s.Status == "blocked" && len(s.Attempts) < 128) {
		if len(s.Attempts) == 0 || s.Attempts[len(s.Attempts)-1].Outcome != s.Status {
			return ErrStore
		}
	}
	if s.Status == "running" && s.Attempts[len(s.Attempts)-1].Outcome != "running" {
		return ErrStore
	}
	if s.Status == "reconciliation_required" {
		outcome := s.Attempts[len(s.Attempts)-1].Outcome
		if outcome != "uncertain" && outcome != "running" {
			return ErrStore
		}
	}
	for id, hash := range s.Requests {
		if !idPattern.MatchString(id) || !digestPattern.MatchString(hash) {
			return ErrStore
		}
	}
	return nil
}
func (e *Engine) persist() bool {
	e.state.Revision++
	e.state.Updated = e.now().UTC()
	if e.journal.save(e.state) != nil {
		e.poisoned = true
		return false
	}
	return true
}
func (e *Engine) Close() {
	e.mu.Lock()
	e.closing = true
	e.cancel()
	e.mu.Unlock()
	e.wg.Wait()
	e.mu.Lock()
	defer e.mu.Unlock()
	e.journal.close()
	e.poisoned = true
}
func (e *Engine) Current(context.Context) (Screen, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.poisoned {
		return Screen{}, ErrStore
	}
	return e.screen(), nil
}
func (e *Engine) Report(context.Context) (Report, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.poisoned {
		return Report{}, ErrStore
	}
	// Marshal/unmarshal detaches slices while retaining the closed public shape.
	r := Report{ReportSchema, e.screen(), e.plan.Packet, e.plan.Target, e.state.Attempts, conditions(), "packet_executor_records_not_independent_audit", e.state.Status == "completed"}
	var copy Report
	_ = Decode(encoded(r), &copy)
	return copy, nil
}
func (e *Engine) screen() Screen {
	s := e.state
	p := e.plan
	v := Screen{Schema: StateSchema, Campaign: p.ID, Plan: s.Plan, Revision: s.Revision, Mode: p.Mode, Device: p.Device, Profile: p.Profile, Status: s.Status, Total: len(p.Steps), Updated: s.Updated, Actions: []Choice{}, Number: s.Index + 1}
	if s.Index < len(p.Steps) {
		step := p.Steps[s.Index]
		v.Step = step.ID
		v.Title = step.Title
		v.Instruction = step.Instruction
	}
	if len(s.Attempts) > 0 {
		a := s.Attempts[len(s.Attempts)-1]
		for _, step := range p.Steps {
			if step.ID == a.Execution.Step {
				v.Output = step.Outputs[a.Code]
			}
		}
		if a.Failure != "" {
			v.Output = map[string]string{"executor_preflight": "The pinned executor could not be verified; no operation was started.", "executor_failed": "The executor stopped before returning a verified result.", "interrupted": "The executor was interrupted or timed out. Its outcome needs checking.", "invalid_result": "The executor response could not be verified."}[a.Failure]
		}
	}
	if v.Output == "" {
		v.Output = "No result recorded for this step yet."
	}
	expired := !e.now().Before(p.Expires)
	switch s.Status {
	case "ready":
		v.Title = "Ready to begin"
		v.Instruction = "Begin the configured development campaign."
		if !expired {
			v.Actions = []Choice{{"begin", "Begin campaign"}}
		}
	case "running":
		v.Instruction = "The station is working. Progress is saved automatically."
		if !s.Pause {
			v.Actions = []Choice{{"pause", "Pause after this step"}}
		}
	case "awaiting_input":
		input := *p.Steps[s.Index].Input
		input.Choices = append([]Choice{}, input.Choices...)
		v.Input = &input
		if !expired {
			v.Actions = []Choice{{"submit", p.Steps[s.Index].Button}}
		}
	case "paused":
		v.Instruction = "The campaign is paused at a completed step."
		if !expired {
			v.Actions = []Choice{{"continue", "Continue campaign"}}
		}
	case "reconciliation_required":
		v.Title = "Check the previous operation"
		v.Instruction = "Its outcome is uncertain. Preserve the device state while the station checks the existing result."
		if !expired && p.Steps[s.Index].Reconcile != nil {
			v.Actions = []Choice{{"reconcile", "Check existing result"}}
		}
	case "blocked":
		v.Title = "Action needed before continuing"
		v.Instruction = "This campaign stopped. Export its report for review; the operation will not be repeated."
	case "quarantined":
		v.Title = "Device requires review"
		v.Instruction = "Keep this device out of service and export its report."
	case "completed":
		v.Number = len(p.Steps)
		v.Title = "Development campaign complete"
		v.Instruction = "Export the test report and remaining admission conditions. Production enrollment has not been established."
	}
	if expired && s.Status != "completed" && s.Status != "running" {
		v.Instruction = "The execution packet has expired. Export the report and have the packet reviewed before further work."
		v.Actions = []Choice{}
	}
	return v
}
func (e *Engine) Apply(_ context.Context, a Action) (Screen, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.poisoned || e.closing || e.ctx.Err() != nil {
		return Screen{}, ErrStore
	}
	if !idPattern.MatchString(a.ID) || a.Revision == 0 || len(a.Input) > 128 {
		return e.screen(), ErrInput
	}
	hash := digest(encoded(a))
	if old, ok := e.state.Requests[a.ID]; ok {
		if old != hash {
			return e.screen(), ErrConflict
		}
		return e.screen(), nil
	}
	if a.Revision != e.state.Revision || len(e.state.Requests) >= 256 {
		return e.screen(), ErrConflict
	}
	allowed := false
	for _, c := range e.screen().Actions {
		if c.Value == a.Action {
			allowed = true
		}
	}
	if !allowed {
		return e.screen(), ErrConflict
	}
	if a.Action == "submit" {
		valid := false
		for _, c := range e.plan.Steps[e.state.Index].Input.Choices {
			if c.Value == a.Input {
				valid = true
			}
		}
		if !valid {
			return e.screen(), ErrInput
		}
	} else if a.Input != "" {
		return e.screen(), ErrInput
	}
	e.state.Requests[a.ID] = hash
	if a.Action == "pause" {
		e.state.Pause = true
		if !e.persist() {
			return Screen{}, ErrStore
		}
		return e.screen(), nil
	}
	e.state.Pause = false
	if a.Action == "begin" || a.Action == "continue" {
		if e.plan.Steps[e.state.Index].Input != nil {
			e.state.Status = "awaiting_input"
			if !e.persist() {
				return Screen{}, ErrStore
			}
			return e.screen(), nil
		}
	}
	e.launch(a.ID, a.Input, a.Action == "reconcile")
	if e.poisoned {
		return Screen{}, ErrStore
	}
	return e.screen(), nil
}

// Caller holds mu. Work uses the service lifetime, never a browser request's
// cancellation; losing a response cannot cancel an operation in progress.
func (e *Engine) launch(request, input string, reconcile bool) {
	if len(e.state.Attempts) >= 128 {
		e.state.Status = "blocked"
		e.persist()
		return
	}
	step := e.plan.Steps[e.state.Index]
	program := step.Execute
	x := Execution{RunnerSchema, e.plan.ID, e.state.Plan, e.plan.Packet, step.ID, request, input, reconcile}
	if reconcile {
		program = *step.Reconcile
		previous := e.state.Attempts[len(e.state.Attempts)-1].Execution
		x.Request = previous.Request
		x.Input = previous.Input
	}
	e.state.Attempts = append(e.state.Attempts, Attempt{Execution: x, Started: e.now().UTC(), Outcome: "running", References: []string{}})
	e.state.Status = "running"
	if !e.persist() {
		return
	}
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		ctx, cancel := context.WithTimeout(e.ctx, time.Duration(program.Timeout)*time.Second)
		defer cancel()
		r, err := e.runner.Run(ctx, program, x)
		e.mu.Lock()
		defer e.mu.Unlock()
		if e.poisoned {
			return
		}
		a := &e.state.Attempts[len(e.state.Attempts)-1]
		now := e.now().UTC()
		a.Finished = &now
		if err != nil || !r.valid(x, step) {
			a.Outcome = "uncertain"
			a.Failure = "invalid_result"
			switch {
			case errors.Is(err, ErrProgram):
				a.Failure = "executor_preflight"
			case errors.Is(err, ErrExecution):
				a.Failure = "executor_failed"
			case errors.Is(err, ErrInterrupted):
				a.Failure = "interrupted"
			}
			e.state.Status = "reconciliation_required"
			e.persist()
			return
		}
		a.Outcome = r.Outcome
		a.Code = r.Code
		a.References = r.References
		switch r.Outcome {
		case "blocked", "quarantined":
			e.state.Status = r.Outcome
		case "uncertain":
			e.state.Status = "reconciliation_required"
		case "succeeded":
			e.state.Index++
			if e.state.Index == len(e.plan.Steps) {
				e.state.Status = "completed"
			} else if e.state.Pause || e.ctx.Err() != nil || !e.now().Before(e.plan.Expires) {
				e.state.Status = "paused"
			} else if e.plan.Steps[e.state.Index].Input != nil {
				e.state.Status = "awaiting_input"
			} else {
				e.state.Status = "paused"
			}
		}
		if !e.persist() {
			return
		}
		if r.Outcome == "succeeded" && e.state.Status == "paused" && !e.state.Pause && e.ctx.Err() == nil && e.now().Before(e.plan.Expires) {
			e.launch("automatic-"+digest([]byte(e.plan.Steps[e.state.Index].ID))[7:], "", false)
		}
	}()
}
