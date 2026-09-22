//go:build linux

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/deviceenrollment"
)

func read(path string) ([]byte, error) {
	if path == "" {
		return nil, deviceenrollment.ErrInput
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, deviceenrollment.ErrInput
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if e != nil || len(b) > 1<<20 {
		return nil, deviceenrollment.ErrInput
	}
	return b, nil
}
func run(args []string, out io.Writer) error {
	if len(args) == 0 {
		return deviceenrollment.ErrInput
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	f.SetOutput(io.Discard)
	state := f.String("state", "", "preexisting private credential directory")
	input := f.String("input", "", "public configuration, challenge, certificate or station status file")
	if f.Parse(args[1:]) != nil || f.NArg() != 0 || *state == "" {
		return deviceenrollment.ErrInput
	}
	action := args[0]
	switch action {
	case "initialize", "bootstrap", "install", "status", "prove-installed", "reconcile", "retry-installed", "check-access":
	default:
		return deviceenrollment.ErrInput
	}
	needsInput := action == "initialize" || action == "bootstrap" || action == "install" || action == "reconcile" || action == "retry-installed"
	if needsInput != (*input != "") {
		return deviceenrollment.ErrInput
	}
	var raw []byte
	var e error
	if needsInput {
		raw, e = read(*input)
		if e != nil {
			return e
		}
	}
	runtime := deviceenrollment.SystemRuntime()
	var result any
	if action == "initialize" {
		config, err := deviceenrollment.DecodeConfig(raw)
		if err != nil {
			return err
		}
		result, e = deviceenrollment.Initialize(*state, config, runtime)
	} else {
		client, err := deviceenrollment.Open(*state, runtime)
		if err != nil {
			return err
		}
		defer client.Close()
		switch action {
		case "status":
			result, e = client.Status()
		case "bootstrap":
			result, e = client.Bootstrap(raw)
		case "install":
			result, e = client.Install(raw)
		case "prove-installed":
			result, e = client.ProveInstalled(context.Background())
		case "reconcile":
			result, e = client.Reconcile(raw)
		case "retry-installed":
			result, e = client.RetryInstalled(context.Background(), raw)
		case "check-access":
			result, e = client.CheckAccess(context.Background())
		default:
			return deviceenrollment.ErrInput
		}
	}
	if e != nil {
		return e
	}
	return json.NewEncoder(out).Encode(result)
}
func main() {
	// These restrictions apply to this process only. Deployment must separately
	// qualify encrypted storage, swap and access to the software signing key.
	if syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{}) != nil {
		fmt.Fprintln(os.Stderr, "device enrollment: core-dump restriction failed")
		os.Exit(1)
	}
	if _, _, e := syscall.Syscall6(syscall.SYS_PRCTL, 4, 0, 0, 0, 0, 0); e != 0 {
		fmt.Fprintln(os.Stderr, "device enrollment: dumpability restriction failed")
		os.Exit(1)
	}
	if e := run(os.Args[1:], os.Stdout); e != nil {
		fmt.Fprintln(os.Stderr, "device enrollment:", e)
		os.Exit(1)
	}
}
