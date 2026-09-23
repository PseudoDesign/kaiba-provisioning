package guidedcampaign

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type runnerFunc func(context.Context, Program, Execution) (Result, error)

func (f runnerFunc) Run(c context.Context, p Program, x Execution) (Result, error) { return f(c, p, x) }
func fixturePlan() Plan {
	program := Program{"/nix/store/00000000000000000000000000000000-reviewed-wrapper/bin/run", "sha256:" + strings.Repeat("a", 64), 3}
	step := func(id string) Step {
		return Step{ID: id, Title: "Check " + id, Instruction: "Keep this test device connected.", Button: "Continue", Execute: program, Reconcile: &program, Outputs: map[string]string{"ok": "Recorded check passed.", "denied": "The required approval is unavailable.", "uncertain": "The previous result needs reconciliation."}}
	}
	p := Plan{PlanSchema, "campaign-1", "station-1", "lane-1", "software_rehearsal", "Test Pi", "target-1", "Isolated development profile", "sha256:" + strings.Repeat("b", 64), time.Now().Add(time.Hour), []Step{step("inspect"), step("reopen"), step("report")}}
	p.Steps[1].Input = &Input{"Has the requested physical action been completed?", []Choice{{"done", "The requested action is complete"}}}
	return p
}
func success(x Execution) Result {
	return Result{RunnerSchema, x.Campaign, x.Step, x.Request, "succeeded", "ok", []string{}}
}
func privateDir(t *testing.T) string {
	t.Helper()
	p := t.TempDir()
	if e := os.Chmod(p, 0700); e != nil {
		t.Fatal(e)
	}
	return p
}
func openTest(t *testing.T, path string, p Plan, r Executor) *Engine {
	t.Helper()
	e, x := Open(context.Background(), path, p, r)
	if x != nil {
		t.Fatal(x)
	}
	return e
}
func current(t *testing.T, e *Engine) Screen {
	t.Helper()
	s, x := e.Current(context.Background())
	if x != nil {
		t.Fatal(x)
	}
	return s
}
func awaitStatus(t *testing.T, e *Engine, want string) Screen {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		s := current(t, e)
		if s.Status == want {
			return s
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("want %s, got %#v", want, current(t, e))
	return Screen{}
}
func action(t *testing.T, e *Engine, id, name, input string) Screen {
	t.Helper()
	s := current(t, e)
	out, x := e.Apply(context.Background(), Action{id, s.Revision, name, input})
	if x != nil {
		t.Fatal(x)
	}
	return out
}

func TestAutomaticStepsBoundedInputAndRestart(t *testing.T) {
	var mu sync.Mutex
	var calls []Execution
	r := runnerFunc(func(_ context.Context, _ Program, x Execution) (Result, error) {
		mu.Lock()
		calls = append(calls, x)
		mu.Unlock()
		return success(x), nil
	})
	p := fixturePlan()
	dir := privateDir(t)
	e := openTest(t, dir, p, r)
	if _, x := Open(context.Background(), dir, p, r); x == nil {
		t.Fatal("second journal owner admitted")
	}
	action(t, e, "begin-1", "begin", "")
	s := awaitStatus(t, e, "awaiting_input")
	if s.Number != 2 || s.Output != "Recorded check passed." || s.Input == nil {
		t.Fatal(s)
	}
	if _, x := e.Apply(context.Background(), Action{"bad-input", s.Revision, "submit", "arbitrary command"}); !errors.Is(x, ErrInput) {
		t.Fatal(x)
	}
	e.Close()
	e = openTest(t, dir, p, r)
	defer e.Close()
	if current(t, e).Revision != s.Revision {
		t.Fatal("waiting checkpoint changed on restart")
	}
	action(t, e, "submit-1", "submit", "done")
	s = awaitStatus(t, e, "completed")
	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 3 || calls[1].Input != "done" || calls[2].Input != "" {
		t.Fatal(calls)
	}
	rpt, x := e.Report(context.Background())
	if x != nil || !rpt.Complete || len(rpt.Attempts) != 3 || len(rpt.Conditions) != 8 || s.Production || s.Qualified {
		t.Fatal(rpt, x)
	}
	for _, c := range rpt.Conditions {
		if c.Status != "not_evaluated" {
			t.Fatal(c)
		}
	}
	if strings.Contains(string(encoded(rpt)), p.Steps[0].Execute.Path) {
		t.Fatal("executable path leaked into public report")
	}
}
func TestDuplicateTapAndLostResponseDoNotRepeat(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var count int
	r := runnerFunc(func(context.Context, Program, Execution) (Result, error) {
		count++
		close(started)
		<-release
		return Result{}, errors.New("lost result")
	})
	e := openTest(t, privateDir(t), fixturePlan(), r)
	defer e.Close()
	a := Action{"same-tap", 1, "begin", ""}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, x := e.Apply(cancelled, a); x != nil {
		t.Fatal(x)
	}
	<-started
	for i := 0; i < 10; i++ {
		if _, x := e.Apply(context.Background(), a); x != nil {
			t.Fatal(x)
		}
	}
	if _, x := e.Apply(context.Background(), Action{"second-tap", 1, "begin", ""}); !errors.Is(x, ErrConflict) {
		t.Fatal(x)
	}
	changed := a
	changed.Action = "pause"
	if _, x := e.Apply(context.Background(), changed); !errors.Is(x, ErrConflict) {
		t.Fatal("request ID reused with different body", x)
	}
	close(release)
	awaitStatus(t, e, "reconciliation_required")
	if count != 1 {
		t.Fatal(count)
	}
}
func TestPauseAfterCurrentStepAndExpiry(t *testing.T) {
	p := fixturePlan()
	p.Steps[1].Input = nil
	release := make(chan struct{})
	started := make(chan struct{})
	n := 0
	r := runnerFunc(func(_ context.Context, _ Program, x Execution) (Result, error) {
		n++
		if n == 1 {
			close(started)
			<-release
		}
		return success(x), nil
	})
	e := openTest(t, privateDir(t), p, r)
	defer e.Close()
	action(t, e, "begin", "begin", "")
	<-started
	action(t, e, "pause", "pause", "")
	close(release)
	awaitStatus(t, e, "paused")
	if n != 1 {
		t.Fatal(n)
	}
	e.mu.Lock()
	e.now = func() time.Time { return p.Expires.Add(time.Second) }
	e.mu.Unlock()
	if len(current(t, e).Actions) != 0 {
		t.Fatal("expired packet still offers work")
	}
	if _, x := e.Apply(context.Background(), Action{"continue", current(t, e).Revision, "continue", ""}); !errors.Is(x, ErrConflict) {
		t.Fatal(x)
	}
}
func TestInterruptedIntentUsesSeparateReconciler(t *testing.T) {
	p := fixturePlan()
	dir := privateDir(t)
	r := runnerFunc(func(_ context.Context, _ Program, x Execution) (Result, error) {
		if !x.Reconcile {
			t.Error("interrupted operation repeated")
		}
		if x.Request != "original-request" {
			t.Error(x)
		}
		return success(x), nil
	})
	e := openTest(t, dir, p, r)
	x := Execution{RunnerSchema, p.ID, p.Digest(), p.Packet, p.Steps[0].ID, "original-request", "", false}
	e.state.Status = "running"
	e.state.Attempts = []Attempt{{Execution: x, Started: time.Now(), Outcome: "running", References: []string{}}}
	if !e.persist() {
		t.Fatal("save")
	}
	e.Close()
	e = openTest(t, dir, p, r)
	defer e.Close()
	if current(t, e).Status != "reconciliation_required" {
		t.Fatal(current(t, e))
	}
	action(t, e, "readback", "reconcile", "")
	awaitStatus(t, e, "awaiting_input")
	report, _ := e.Report(context.Background())
	if len(report.Attempts) != 2 || report.Attempts[0].Outcome != "running" || !report.Attempts[1].Execution.Reconcile {
		t.Fatal(report)
	}
}
func TestUncertainBlockedQuarantinedAndMalformedResults(t *testing.T) {
	for _, kind := range []string{"blocked", "quarantined", "uncertain", "wrong-request", "secret-field", "wrong-code"} {
		t.Run(kind, func(t *testing.T) {
			p := fixturePlan()
			r := runnerFunc(func(_ context.Context, _ Program, x Execution) (Result, error) {
				v := success(x)
				switch kind {
				case "wrong-request":
					v.Request = "other"
				case "wrong-code":
					v.Code = "unreviewed"
				case "secret-field":
					var v Result
					err := Decode([]byte(`{"private_key_pkcs8":"private"}`), &v)
					return v, err
				default:
					v.Outcome = kind
					v.Code = "denied"
				}
				return v, nil
			})
			e := openTest(t, privateDir(t), p, r)
			defer e.Close()
			action(t, e, "begin", "begin", "")
			want := kind
			if kind != "blocked" && kind != "quarantined" {
				want = "reconciliation_required"
			}
			s := awaitStatus(t, e, want)
			if s.Step != "inspect" {
				t.Fatal("advanced on failure")
			}
			if kind == "blocked" || kind == "quarantined" {
				if len(s.Actions) != 0 {
					t.Fatal(s)
				}
			}
			report, _ := e.Report(context.Background())
			if strings.Contains(string(encoded(report)), "private_key") {
				t.Fatal("secret exported")
			}
		})
	}
}
func TestJournalRejectsChangedPlanUncertainWriteAndUnsafeFiles(t *testing.T) {
	r := runnerFunc(func(_ context.Context, _ Program, x Execution) (Result, error) { return success(x), nil })
	p := fixturePlan()
	for _, mode := range []string{"changed-plan", "pending", "symlink", "permissions", "invalid", "missing", "false-advance"} {
		t.Run(mode, func(t *testing.T) {
			dir := privateDir(t)
			e := openTest(t, dir, p, r)
			e.Close()
			candidate := p
			switch mode {
			case "changed-plan":
				candidate.Profile = "Different policy"
			case "pending":
				os.WriteFile(filepath.Join(dir, ".pending-unknown"), []byte("uncertain"), 0600)
			case "symlink":
				os.Rename(filepath.Join(dir, "state.json"), filepath.Join(dir, "previous"))
				os.Symlink(filepath.Join(dir, "previous"), filepath.Join(dir, "state.json"))
			case "permissions":
				os.Chmod(filepath.Join(dir, "state.json"), 0644)
			case "invalid":
				os.WriteFile(filepath.Join(dir, "state.json"), []byte(`{"status":"completed"}`), 0600)
			case "missing":
				os.Remove(filepath.Join(dir, "state.json"))
			case "false-advance":
				b, err := os.ReadFile(filepath.Join(dir, "state.json"))
				if err != nil {
					t.Fatal(err)
				}
				var state recorded
				if Decode(b, &state) != nil {
					t.Fatal("fixture journal invalid")
				}
				state.Index, state.Status = len(p.Steps), "completed"
				if err := os.WriteFile(filepath.Join(dir, "state.json"), encoded(state), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if x, err := Open(context.Background(), dir, candidate, r); err == nil {
				x.Close()
				t.Fatal("unsafe journal accepted")
			}
		})
	}
}

func TestFailureCategoriesSurviveRestartWithoutRawErrors(t *testing.T) {
	for category, failure := range map[string]error{"executor_preflight": ErrProgram, "executor_failed": ErrExecution, "interrupted": ErrInterrupted, "invalid_result": errors.New("private_key=must-not-escape")} {
		t.Run(category, func(t *testing.T) {
			p, dir := fixturePlan(), privateDir(t)
			r := runnerFunc(func(context.Context, Program, Execution) (Result, error) { return Result{}, failure })
			e := openTest(t, dir, p, r)
			action(t, e, "begin", "begin", "")
			awaitStatus(t, e, "reconciliation_required")
			e.Close()
			e = openTest(t, dir, p, r)
			defer e.Close()
			report, err := e.Report(context.Background())
			if err != nil || len(report.Attempts) != 1 || report.Attempts[0].Failure != category || strings.Contains(string(encoded(report)), "private_key") {
				t.Fatal(report, err)
			}
		})
	}
}
func TestIntentPersistenceFailurePreventsExecution(t *testing.T) {
	r := runnerFunc(func(context.Context, Program, Execution) (Result, error) {
		t.Error("ran without durable intent")
		return Result{}, nil
	})
	e := openTest(t, privateDir(t), fixturePlan(), r)
	defer e.Close()
	e.journal.dir.Close()
	if _, err := e.Apply(context.Background(), Action{"begin", 1, "begin", ""}); !errors.Is(err, ErrStore) {
		t.Fatal(err)
	}
	if _, err := e.Current(context.Background()); !errors.Is(err, ErrStore) {
		t.Fatal("poisoned journal served a success", err)
	}
}
func TestPlanAndActionClosedShapes(t *testing.T) {
	p := fixturePlan()
	if p.Validate() != nil {
		t.Fatal("fixture invalid")
	}
	for _, raw := range []string{`{"request_id":"a","request_id":"b","expected_revision":1,"action":"begin","input":""}`, `{"request_id":"a","expected_revision":1,"action":"begin","input":"","command":"rm"}`, `{} {}`} {
		var a Action
		if Decode([]byte(raw), &a) == nil {
			t.Fatal("ambiguous action accepted")
		}
	}
	for _, edit := range []func(*Plan){func(p *Plan) { p.Mode = "production" }, func(p *Plan) { p.Steps[0].Execute.Path = "/tmp/run" }, func(p *Plan) { p.Steps[1].ID = p.Steps[0].ID }, func(p *Plan) { p.Steps[0].Execute.Timeout = 0 }} {
		var c Plan
		Decode(encoded(p), &c)
		edit(&c)
		if c.Validate() == nil {
			t.Fatal("invalid plan accepted")
		}
	}
}

func TestLongestStepIDKeepsAutomaticRequestAndRestartValid(t *testing.T) {
	p, dir := fixturePlan(), privateDir(t)
	p.Steps[1].ID, p.Steps[1].Input = strings.Repeat("s", 128), nil
	r := runnerFunc(func(_ context.Context, _ Program, x Execution) (Result, error) {
		if !idPattern.MatchString(x.Request) {
			t.Error("unbounded automatic request", x.Request)
		}
		return success(x), nil
	})
	e := openTest(t, dir, p, r)
	action(t, e, "begin", "begin", "")
	awaitStatus(t, e, "completed")
	e.Close()
	e = openTest(t, dir, p, r)
	defer e.Close()
	if current(t, e).Status != "completed" {
		t.Fatal("completion lost on restart")
	}
}

func TestJournalCannotResumeAnUncertainOrQuarantinedStepAsPaused(t *testing.T) {
	for _, outcome := range []string{"uncertain", "quarantined"} {
		t.Run(outcome, func(t *testing.T) {
			p, dir := fixturePlan(), privateDir(t)
			r := runnerFunc(func(_ context.Context, _ Program, x Execution) (Result, error) {
				v := success(x)
				v.Outcome = outcome
				return v, nil
			})
			e := openTest(t, dir, p, r)
			action(t, e, "begin", "begin", "")
			want := outcome
			if outcome == "uncertain" {
				want = "reconciliation_required"
			}
			awaitStatus(t, e, want)
			e.mu.Lock()
			e.state.Status = "paused"
			if !e.persist() {
				t.Fatal("fixture persistence failed")
			}
			e.mu.Unlock()
			e.Close()
			if opened, err := Open(context.Background(), dir, p, r); err == nil {
				opened.Close()
				t.Fatal("contradictory journal accepted")
			}
		})
	}
}
