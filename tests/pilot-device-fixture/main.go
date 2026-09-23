// Synthetic software test fixture, not a deployable device client.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/pilotenrollment"
	"log"
	"os"
)

func main() {
	state := flag.String("state", "", "existing protected 0700 directory")
	config := flag.String("config", "", "reviewed pilot config for init")
	input := flag.String("input", "", "public challenge, certificate or station reconciliation response")
	flag.Parse()
	if *state == "" || flag.NArg() != 1 {
		log.Fatal("state and one command required")
	}
	var value any
	var e error
	if flag.Arg(0) == "init" {
		b, err := os.ReadFile(*config)
		if err != nil {
			log.Fatal(err)
		}
		c, err := pilotenrollment.DecodeConfig(b)
		if err != nil {
			log.Fatal(err)
		}
		value, e = pilotenrollment.Initialize(*state, c, fixtureRuntime())
	} else {
		c, err := pilotenrollment.Open(*state, fixtureRuntime())
		if err != nil {
			log.Fatal(err)
		}
		defer c.Close()
		var raw []byte
		if *input != "" {
			raw, err = os.ReadFile(*input)
			if err != nil {
				log.Fatal(err)
			}
		}
		switch flag.Arg(0) {
		case "status":
			value, e = c.Status()
		case "bootstrap":
			value, e = c.Bootstrap(raw)
		case "install":
			value, e = c.Install(raw)
		case "prove-installed":
			value, e = c.ProveInstalled(context.Background())
		case "retry-installed":
			value, e = c.RetryInstalled(context.Background(), raw)
		case "reconcile":
			value, e = c.Reconcile(raw)
		case "self":
			value, e = c.CheckAccess(context.Background())
		default:
			log.Fatal("unknown command")
		}
	}
	if e != nil {
		log.Fatal(e)
	}
	if e = json.NewEncoder(os.Stdout).Encode(value); e != nil {
		log.Fatal(e)
	}
}

// This binary is built only by the synthetic software check, never as a device
// package. It substitutes the filesystem observation while exercising the same
// private-store, key, certificate and proof implementation across processes.
func fixtureRuntime() pilotenrollment.Runtime {
	r := pilotenrollment.SystemRuntime()
	r.CheckStorage = func(*os.File, string) error { return nil }
	return r
}
