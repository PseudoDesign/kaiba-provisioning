package main

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/controlplane"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/livestation"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mtls"
)

func observerArguments() []string {
	return []string{
		"--transaction-id", "transaction-1", "--control-url", "https://control.example:8443",
		"--tls-cert", "/run/credentials/station.crt", "--tls-key", "/run/credentials/station.key",
		"--control-server-ca", "/run/credentials/control-ca.crt",
		"--station-id", "station-1", "--lane-id", "lane-1",
	}
}

func TestObserverConfigurationIsCompleteOrAbsent(t *testing.T) {
	config, err := parseConfig(nil, io.Discard)
	if err != nil || config.observe {
		t.Fatalf("default config = %#v, %v", config, err)
	}
	config, err = parseConfig(observerArguments(), io.Discard)
	if err != nil || !config.observe || config.observation.TransactionID != "transaction-1" {
		t.Fatalf("observer config = %#v, %v", config, err)
	}
	for _, option := range []string{"--transaction-id", "--control-url", "--tls-cert", "--tls-key", "--control-server-ca"} {
		t.Run(option, func(t *testing.T) {
			if _, err := parseConfig([]string{option, ""}, io.Discard); err == nil {
				t.Fatal("an explicitly empty observer option silently selected foundation mode")
			}
			arguments := observerArguments()
			for index := 0; index < len(arguments); index += 2 {
				if arguments[index] == option {
					arguments = append(arguments[:index], arguments[index+2:]...)
					break
				}
			}
			if _, err := parseConfig(arguments, io.Discard); err == nil {
				t.Fatal("incomplete observer configuration was accepted")
			}
		})
	}
	for _, extra := range [][]string{
		{"--enable-mutations"}, {"--listen", "0.0.0.0:8081"}, {"--transaction-id", "../other"},
		{"--tls-key", "relative.key"}, {"--tls-key", "/run/../key"}, {"--tls-key", "/nix/store/secret"},
		{"unexpected"},
	} {
		if _, err := parseConfig(append(observerArguments(), extra...), io.Discard); err == nil {
			t.Fatalf("accepted invalid arguments %q", extra)
		}
	}
}

type identityReader struct {
	identity mtls.StationLaneIdentity
	err      error
}

func (reader identityReader) StationIdentity() (mtls.StationLaneIdentity, error) {
	return reader.identity, reader.err
}

func (identityReader) GetTransaction(context.Context, string) (controlplane.Transaction, error) {
	return controlplane.Transaction{}, errors.New("test authority is unavailable")
}

func restoreStationGlobals(t *testing.T) {
	t.Helper()
	build, observer, foundation := buildControlReader, serveObservation, serveFoundation
	t.Cleanup(func() { buildControlReader, serveObservation, serveFoundation = build, observer, foundation })
}

func TestConfiguredObserverValidatesIdentityBeforeServing(t *testing.T) {
	for _, test := range []struct {
		name          string
		identity      mtls.StationLaneIdentity
		identityError error
		wantServe     bool
	}{
		{"matching", mtls.StationLaneIdentity{StationID: "station-1", LaneID: "lane-1"}, nil, true},
		{"wrong station", mtls.StationLaneIdentity{StationID: "station-2", LaneID: "lane-1"}, nil, false},
		{"wrong lane", mtls.StationLaneIdentity{StationID: "station-1", LaneID: "lane-2"}, nil, false},
		{"invalid certificate identity", mtls.StationLaneIdentity{}, mtls.ErrClientIdentity, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			restoreStationGlobals(t)
			buildControlReader = func(origin string, files mtls.ClientFiles) (identifiedControlReader, error) {
				if origin != "https://control.example:8443" || files.PrivateKey != "/run/credentials/station.key" || files.ServerCA != "/run/credentials/control-ca.crt" {
					t.Fatalf("wrong authority inputs: %q %#v", origin, files)
				}
				return identityReader{test.identity, test.identityError}, nil
			}
			served := false
			serveObservation = func(_ context.Context, address string, source livestation.ObservationSource) error {
				served = true
				if address != "127.0.0.1:8081" || source == nil {
					t.Fatal("invalid observer server")
				}
				return nil
			}
			serveFoundation = func(context.Context, string, livestation.Orchestrator) error {
				t.Fatal("observer silently fell back to foundation mode")
				return nil
			}
			err := run(context.Background(), observerArguments())
			if served != test.wantServe || (err == nil) != test.wantServe {
				t.Fatalf("served=%v error=%v", served, err)
			}
		})
	}
}

func TestReaderFailureNeverFallsBack(t *testing.T) {
	restoreStationGlobals(t)
	buildControlReader = func(string, mtls.ClientFiles) (identifiedControlReader, error) {
		return nil, errors.New("invalid trust configuration")
	}
	serveObservation = func(context.Context, string, livestation.ObservationSource) error {
		t.Fatal("served observer after reader failure")
		return nil
	}
	serveFoundation = func(context.Context, string, livestation.Orchestrator) error {
		t.Fatal("served foundation after reader failure")
		return nil
	}
	if err := run(context.Background(), observerArguments()); err == nil || !strings.Contains(err.Error(), "invalid trust") {
		t.Fatalf("error = %v", err)
	}
}

func TestUnconfiguredStationRetainsDisabledFoundation(t *testing.T) {
	restoreStationGlobals(t)
	buildControlReader = func(string, mtls.ClientFiles) (identifiedControlReader, error) {
		t.Fatal("unconfigured foundation built an authority reader")
		return nil, nil
	}
	serveFoundation = func(ctx context.Context, _ string, source livestation.Orchestrator) error {
		state, err := source.Current(ctx)
		if err != nil || state.SchemaVersion != livestation.StateSchemaVersion || state.Safety.LiveMutationCapable || state.Safety.EnrollmentCapable {
			t.Fatalf("foundation state = %#v, %v", state, err)
		}
		return nil
	}
	if err := run(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
}

func campaignArguments() []string {
	return []string{"--campaign-url", "https://campaign.example", "--campaign-id", "campaign-1", "--campaign-plan-digest", "sha256:" + strings.Repeat("a", 64), "--campaign-server-ca", "/run/credentials/campaign-ca.crt", "--tls-cert", "/run/credentials/station.crt", "--tls-key", "/run/credentials/station.key", "--station-id", "station-1", "--lane-id", "lane-1"}
}
func TestCampaignConfigurationHasNoObserverOrFoundationFallback(t *testing.T) {
	c, e := parseConfig(campaignArguments(), io.Discard)
	if e != nil || !c.campaign || c.observe {
		t.Fatal(c, e)
	}
	for _, name := range []string{"--campaign-url", "--campaign-id", "--campaign-plan-digest", "--campaign-server-ca", "--tls-cert", "--tls-key"} {
		args := campaignArguments()
		for i := 0; i < len(args); i += 2 {
			if args[i] == name {
				args[i+1] = ""
			}
		}
		if _, e := parseConfig(args, io.Discard); e == nil {
			t.Fatal("partial campaign accepted", name)
		}
	}
	for _, extra := range [][]string{{"--transaction-id", "transaction-1"}, {"--control-url", "https://control.example"}, {"--control-server-ca", "/run/ca"}, {"--enable-mutations"}, {"--campaign-server-ca", "/nix/store/not-runtime"}} {
		if _, e := parseConfig(append(campaignArguments(), extra...), io.Discard); e == nil {
			t.Fatal(extra)
		}
	}
}
