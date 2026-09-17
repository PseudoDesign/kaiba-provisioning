package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/authorityhttp"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/livestation"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mtls"
)

type stationConfig struct {
	listen      string
	observation livestation.ObservationConfig
	controlURL  string
	tlsFiles    mtls.ClientFiles
	observe     bool
}

type identifiedControlReader interface {
	livestation.TransactionReader
	StationIdentity() (mtls.StationLaneIdentity, error)
}

var (
	stationIdentifier  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	buildControlReader = func(origin string, files mtls.ClientFiles) (identifiedControlReader, error) {
		return authorityhttp.NewControlReader(origin, files)
	}
	serveObservation = livestation.ListenAndServeObserver
	serveFoundation  = livestation.ListenAndServe
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "kaiba-provision-station: %v\n", err)
		os.Exit(1)
	}
}

func parseConfig(arguments []string, output io.Writer) (stationConfig, error) {
	flags := flag.NewFlagSet("kaiba-provision-station", flag.ContinueOnError)
	flags.SetOutput(output)
	var config stationConfig
	flags.StringVar(&config.listen, "listen", "127.0.0.1:8081", "explicit loopback IP address and port")
	flags.StringVar(&config.observation.StationID, "station-id", "development-station", "fixed station identity")
	flags.StringVar(&config.observation.LaneID, "lane-id", "lane-1", "fixed lane identity")
	flags.StringVar(&config.observation.USBPath, "rpiboot-sysfs", "/sys/bus/usb/devices/1-1", "fixed USB sysfs path; observer reads presence and identifiers only")
	flags.StringVar(&config.observation.UARTPath, "uart", "/dev/serial/by-id/kaiba-target-uart", "fixed UART path; observer checks presence without opening it")
	flags.StringVar(&config.observation.TransactionID, "transaction-id", "", "one existing transaction to observe across restarts")
	flags.StringVar(&config.controlURL, "control-url", "", "control-service HTTPS origin for read-only observation")
	flags.StringVar(&config.tlsFiles.Certificate, "tls-cert", "", "runtime station client certificate PEM path")
	flags.StringVar(&config.tlsFiles.PrivateKey, "tls-key", "", "runtime station client private-key PEM path")
	flags.StringVar(&config.tlsFiles.ServerCA, "control-server-ca", "", "exclusive control-service CA PEM path")
	enableMutations := flags.Bool("enable-mutations", false, "enable an explicitly installed hardware orchestration backend")
	if err := flags.Parse(arguments); err != nil {
		return stationConfig{}, err
	}
	if flags.NArg() != 0 {
		return stationConfig{}, errors.New("unexpected positional arguments")
	}
	if err := livestation.ValidateListenAddress(config.listen); err != nil {
		return stationConfig{}, err
	}
	if *enableMutations {
		return stationConfig{}, errors.New("mutation was requested, but this build has no installed hardware orchestration backend")
	}
	flags.Visit(func(option *flag.Flag) {
		switch option.Name {
		case "transaction-id", "control-url", "tls-cert", "tls-key", "control-server-ca":
			config.observe = true
		}
	})
	if !config.observe {
		return config, nil
	}
	for _, required := range []struct{ name, value string }{
		{"--transaction-id", config.observation.TransactionID}, {"--control-url", config.controlURL},
		{"--tls-cert", config.tlsFiles.Certificate}, {"--tls-key", config.tlsFiles.PrivateKey},
		{"--control-server-ca", config.tlsFiles.ServerCA},
	} {
		if required.value == "" {
			return stationConfig{}, fmt.Errorf("%s is required for observer mode", required.name)
		}
	}
	for _, identifier := range []string{config.observation.StationID, config.observation.LaneID, config.observation.TransactionID} {
		if !stationIdentifier.MatchString(identifier) {
			return stationConfig{}, errors.New("station, lane and transaction IDs must be valid fixed identifiers")
		}
	}
	for _, credential := range []struct{ name, path string }{
		{"--tls-cert", config.tlsFiles.Certificate}, {"--tls-key", config.tlsFiles.PrivateKey},
		{"--control-server-ca", config.tlsFiles.ServerCA},
	} {
		if !filepath.IsAbs(credential.path) || filepath.Clean(credential.path) != credential.path || strings.ContainsRune(credential.path, '\x00') {
			return stationConfig{}, fmt.Errorf("%s must be a clean absolute path", credential.name)
		}
		if credential.path == "/nix/store" || strings.HasPrefix(credential.path, "/nix/store/") {
			return stationConfig{}, fmt.Errorf("%s must be a runtime credential outside the Nix store", credential.name)
		}
	}
	return config, nil
}

func run(ctx context.Context, arguments []string) error {
	config, err := parseConfig(arguments, os.Stderr)
	if err != nil {
		return err
	}
	if config.observe {
		reader, err := buildControlReader(config.controlURL, config.tlsFiles)
		if err != nil {
			return fmt.Errorf("configure read-only control authority: %w", err)
		}
		identity, err := reader.StationIdentity()
		if err != nil {
			return fmt.Errorf("read station client identity: %w", err)
		}
		if identity.StationID != config.observation.StationID || identity.LaneID != config.observation.LaneID {
			return fmt.Errorf("station/lane configuration does not match the client certificate: %w", mtls.ErrClientIdentityMismatch)
		}
		observer, err := livestation.NewObserver(config.observation, reader)
		if err != nil {
			return err
		}
		return serveObservation(ctx, config.listen, observer)
	}
	machine, err := livestation.NewMachine(livestation.Config{
		StationID: config.observation.StationID, LaneID: config.observation.LaneID,
		USBPath: config.observation.USBPath, UARTPath: config.observation.UARTPath,
		MutationCapable: false,
	}, livestation.DisabledBackend{Reason: "install and explicitly enable the production orchestration backend"})
	if err != nil {
		return err
	}
	return serveFoundation(ctx, config.listen, machine)
}
