package guidedcampaign

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ProcessExecutor has no command/argument/environment API for browser callers.
// Each immutable packet wrapper retains its own execution-authority checks.
type ProcessExecutor struct{}

func immutable(path string) (*os.File, error) {
	if !strings.HasPrefix(path, "/nix/store/") || filepath.Clean(path) != path {
		return nil, ErrInput
	}
	resolved, e := filepath.EvalSymlinks(path)
	if e != nil || !strings.HasPrefix(resolved, "/nix/store/") {
		return nil, ErrInput
	}
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, ErrInput
	}
	f := os.NewFile(uintptr(fd), path)
	s, e := f.Stat()
	if e != nil {
		f.Close()
		return nil, ErrInput
	}
	// Nix store UIDs can be remapped in build/user namespaces. Trust the fixed
	// store path plus read-only bytes and the separately pinned program digest,
	// rather than assuming every valid store object appears owned by UID zero.
	if !s.Mode().IsRegular() || s.Mode().Perm()&0222 != 0 || s.Size() > 32*1024*1024 {
		f.Close()
		return nil, ErrInput
	}
	return f, nil
}
func LoadPlan(path string) (Plan, error) {
	var p Plan
	f, e := immutable(path)
	if e != nil {
		return p, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, MaxBytes+1))
	if e != nil || Decode(b, &p) != nil || p.Validate() != nil {
		return Plan{}, ErrInput
	}
	return p, nil
}

type limitedOutput struct {
	mu       sync.Mutex
	b        bytes.Buffer
	overflow bool
}

func (w *limitedOutput) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.b.Len()+len(b) > 64*1024 {
		w.overflow = true
		return 0, ErrInvalid
	}
	return w.b.Write(b)
}
func (ProcessExecutor) Run(ctx context.Context, p Program, x Execution) (Result, error) {
	var result Result
	if !p.valid() {
		return result, ErrProgram
	}
	f, e := immutable(p.Path)
	if e != nil {
		return result, ErrProgram
	}
	defer f.Close()
	sum := sha256.New()
	if _, e = io.Copy(sum, f); e != nil || fmt.Sprintf("sha256:%x", sum.Sum(nil)) != p.Digest {
		return result, ErrProgram
	}
	if _, e = f.Seek(0, 0); e != nil {
		return result, ErrProgram
	}
	// The verified open file is executed, rather than resolving its name again.
	cmd := exec.CommandContext(ctx, "/proc/self/fd/3")
	cmd.ExtraFiles = []*os.File{f}
	cmd.Stdin = bytes.NewReader(encoded(x))
	cmd.Env = []string{"LC_ALL=C", "PATH=/no-command-search"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		e := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if e == syscall.ESRCH {
			return os.ErrProcessDone
		}
		return e
	}
	cmd.WaitDelay = time.Second
	var out, stderr limitedOutput
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	e = cmd.Run()
	// Never retain executor stdout/stderr in the public journal or a log. Bad
	// wrappers can accidentally emit credentials; only a closed result survives.
	defer clear(out.b.Bytes())
	defer clear(stderr.b.Bytes())
	if ctx.Err() != nil {
		return Result{}, ErrInterrupted
	}
	if e != nil {
		return Result{}, ErrExecution
	}
	if out.overflow || stderr.overflow || stderr.b.Len() != 0 || Decode(out.b.Bytes(), &result) != nil {
		return Result{}, ErrInvalid
	}
	return result, nil
}
