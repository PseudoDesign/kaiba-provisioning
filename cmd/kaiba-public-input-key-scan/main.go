//go:build linux

// kaiba-public-input-key-scan reads one public artifact and emits bounded scan
// metadata. It never parses a private key, signs, or changes the input file.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/pemmarkers"
)

type singleFlag struct {
	value string
	set   bool
}

func (value *singleFlag) String() string { return value.value }
func (value *singleFlag) Set(text string) error {
	if value.set {
		return errors.New("flag may be supplied only once")
	}
	value.value = text
	value.set = true
	return nil
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
func run(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("kaiba-public-input-key-scan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	input := &singleFlag{}
	mode := &singleFlag{value: string(pemmarkers.Strict)}
	flags.Var(input, "input", "required clean absolute regular public file path")
	flags.Var(mode, "mode", "strict (default), or fixed reviewed-root-literals")
	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 || !input.set {
		fmt.Fprintln(stderr, "require exactly one --input and optional --mode")
		return 2
	}
	selected := pemmarkers.Mode(mode.value)
	if selected != pemmarkers.Strict && selected != pemmarkers.ReviewedRootLiterals {
		fmt.Fprintln(stderr, "unsupported scan mode")
		return 2
	}
	file, before, err := openInput(input.value)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer file.Close()
	// One extra byte detects growth while still bounding the reader to the
	// pinned initial size. The scanner itself retains only constant memory.
	report, err := pemmarkers.Scan(io.LimitReader(file, before.size+1), selected)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	after, err := identityOf(file)
	if err != nil || after != before || report.BytesScanned != uint64(before.size) {
		fmt.Fprintln(stderr, "input identity or size changed during scan")
		return 1
	}
	if err := file.Close(); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := json.NewEncoder(stdout).Encode(report); err != nil {
		fmt.Fprintln(stderr, "write scan report failed")
		return 1
	}
	return 0
}
