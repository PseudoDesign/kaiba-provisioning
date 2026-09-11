package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/rpi5kexecinput"
)

const (
	exitInvalid = 1
	exitUsage   = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, output, errorOutput io.Writer) int {
	flags := flag.NewFlagSet("kaiba-rpi5-kexec-input-validate", flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	var deviceTreePath string
	var commandLinePath string
	flags.StringVar(&deviceTreePath, "device-tree", "", "firmware-resolved Raspberry Pi 5 DTB")
	flags.StringVar(&commandLinePath, "command-line", "", "delegated kernel command-line file")
	if err := flags.Parse(arguments); err != nil {
		return exitUsage
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(errorOutput, "kexec input validation: unexpected positional arguments")
		return exitUsage
	}
	if deviceTreePath == "" || commandLinePath == "" {
		fmt.Fprintln(errorOutput, "kexec input validation: --device-tree and --command-line are required")
		return exitUsage
	}
	deviceTree, err := readBoundedRegular(deviceTreePath, rpi5kexecinput.MaxDeviceTreeBytes)
	if err != nil {
		fmt.Fprintf(errorOutput, "kexec input validation: read device tree: %v\n", err)
		return exitUsage
	}
	commandLineFile, err := readBoundedRegular(commandLinePath, rpi5kexecinput.MaxCommandLineBytes+1)
	if err != nil {
		fmt.Fprintf(errorOutput, "kexec input validation: read command line: %v\n", err)
		return exitUsage
	}
	commandLine, err := rpi5kexecinput.ParseCommandLineFile(commandLineFile)
	if err != nil {
		fmt.Fprintf(errorOutput, "kexec input validation: kernel command line: %v\n", err)
		return exitInvalid
	}
	if err := rpi5kexecinput.Validate(deviceTree, commandLine); err != nil {
		fmt.Fprintf(errorOutput, "kexec input validation: %v\n", err)
		return exitInvalid
	}
	fmt.Fprintln(output, "rpi5 kexec inputs: OK")
	return 0
}

func readBoundedRegular(path string, maximum int) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("input is not a regular file")
	}
	if info.Size() < 1 || info.Size() > int64(maximum) {
		return nil, fmt.Errorf("input size %d is outside 1..%d bytes", info.Size(), maximum)
	}
	contents, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil {
		return nil, err
	}
	if len(contents) != int(info.Size()) {
		return nil, errors.New("input size changed while it was read")
	}
	return contents, nil
}
