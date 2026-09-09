//go:build linux

package stablehandoff

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

const MaxCommandLineBytes = 4096

// Plan identifies retained, already verified release objects. The caller
// retains ownership of Kernel and DeviceTree. PrepareInitramfs returns a new
// sealed in-memory file owned by the caller.
type Plan struct {
	KexecPath   string
	Kernel      *os.File
	Initramfs   *os.File
	DeviceTree  *os.File
	CommandLine string
	Output      io.Writer
	Runner      Runner
}

// Runner is the narrow process boundary used by Plan. Production callers use
// ExecRunner; tests can assert the exact descriptors and arguments without
// loading a kernel into the host.
type Runner interface {
	Run(context.Context, string, []string, []*os.File, io.Writer) error
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, path string, arguments []string, extraFiles []*os.File, output io.Writer) error {
	command := exec.CommandContext(ctx, path, arguments...)
	command.ExtraFiles = extraFiles
	command.Stdout = output
	command.Stderr = output
	return command.Run()
}

// Loaded is an execution capability returned only after the exact retained
// descriptors have been accepted by kexec. Its unexported fields prevent a
// caller from fabricating a handoff without first completing Load.
type Loaded struct {
	mu        sync.Mutex
	kexecPath string
	output    io.Writer
	runner    Runner
	consumed  bool
}

// PrepareInitramfs constructs and seals the only mutable input to handoff.
func PrepareInitramfs(base *os.File, credential Credential) (*os.File, error) {
	if base == nil {
		return nil, errors.New("base initramfs is required")
	}
	identity, err := base.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect retained base initramfs: %w", err)
	}
	if !identity.Mode().IsRegular() {
		return nil, errors.New("retained base initramfs is not a regular file")
	}
	memoryFile, err := newSealableMemoryFile("kaiba-one-boot-initramfs")
	if err != nil {
		return nil, err
	}
	source := io.NewSectionReader(base, 0, identity.Size())
	if err := AppendCredentialArchive(memoryFile, source, identity.Size(), credential); err != nil {
		memoryFile.Close()
		return nil, err
	}
	if err := sealMemoryFile(memoryFile); err != nil {
		memoryFile.Close()
		return nil, err
	}
	if _, err := memoryFile.Seek(0, io.SeekStart); err != nil {
		memoryFile.Close()
		return nil, fmt.Errorf("rewind sealed handoff initramfs: %w", err)
	}
	return memoryFile, nil
}

// Load asks the pinned kexec tool to copy retained release objects into the
// kernel. /proc/self/fd paths refer only to descriptors inherited explicitly
// by the child; no original release path is reopened. The compatibility
// kexec_load syscall is required on arm64 because kexec_file_load does not
// consume the explicitly authenticated device tree.
func (plan Plan) Load(ctx context.Context) (*Loaded, error) {
	if ctx == nil {
		return nil, errors.New("kexec load requires a context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := plan.validate(); err != nil {
		return nil, err
	}
	const firstInheritedFD = 3
	kernelFD := firstInheritedFD
	initramfsFD := firstInheritedFD + 1
	dtbFD := firstInheritedFD + 2
	arguments := []string{
		"--kexec-syscall", "--load", fmt.Sprintf("/proc/self/fd/%d", kernelFD),
		fmt.Sprintf("--initrd=/proc/self/fd/%d", initramfsFD),
		fmt.Sprintf("--dtb=/proc/self/fd/%d", dtbFD),
		"--command-line=" + plan.CommandLine,
	}
	if err := plan.runner().Run(
		ctx,
		plan.KexecPath,
		arguments,
		[]*os.File{plan.Kernel, plan.Initramfs, plan.DeviceTree},
		plan.Output,
	); err != nil {
		return nil, fmt.Errorf("load verified release with kexec: %w", err)
	}
	return &Loaded{
		kexecPath: plan.KexecPath,
		output:    plan.Output,
		runner:    plan.runner(),
	}, nil
}

// Execute transfers control after a successful Load. The capability is
// consumed before invoking kexec so an ambiguous result cannot be retried.
func (loaded *Loaded) Execute(ctx context.Context) error {
	if ctx == nil {
		return errors.New("kexec execution requires a context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if loaded == nil || loaded.runner == nil || loaded.kexecPath == "" {
		return errors.New("a successful kexec load is required before execution")
	}
	loaded.mu.Lock()
	if loaded.consumed {
		loaded.mu.Unlock()
		return errors.New("kexec execution capability is already consumed")
	}
	loaded.consumed = true
	loaded.mu.Unlock()
	if err := loaded.runner.Run(ctx, loaded.kexecPath, []string{"--exec"}, nil, loaded.output); err != nil {
		return fmt.Errorf("execute verified release with kexec: %w", err)
	}
	return errors.New("kexec returned without transferring control")
}

func (plan Plan) validate() error {
	if err := plan.validateExecutable(); err != nil {
		return err
	}
	for name, file := range map[string]*os.File{
		"kernel": plan.Kernel, "initramfs": plan.Initramfs, "device tree": plan.DeviceTree,
	} {
		if file == nil {
			return fmt.Errorf("%s retained file is required", name)
		}
		identity, err := file.Stat()
		if err != nil || !identity.Mode().IsRegular() {
			return fmt.Errorf("%s retained file must be an open regular file", name)
		}
	}
	if plan.CommandLine == "" || len(plan.CommandLine) > MaxCommandLineBytes ||
		strings.ContainsAny(plan.CommandLine, "\x00\r\n") {
		return fmt.Errorf("command line must contain between 1 and %d bytes without NUL or line breaks", MaxCommandLineBytes)
	}
	return nil
}

func (plan Plan) validateExecutable() error {
	if plan.KexecPath == "" || !filepath.IsAbs(plan.KexecPath) || filepath.Clean(plan.KexecPath) != plan.KexecPath ||
		strings.IndexByte(plan.KexecPath, 0) >= 0 {
		return errors.New("kexec path must be a clean absolute path")
	}
	return nil
}

func (plan Plan) runner() Runner {
	if plan.Runner != nil {
		return plan.Runner
	}
	return ExecRunner{}
}
