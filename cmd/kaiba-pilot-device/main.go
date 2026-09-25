package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/pilotenrollment"
	"io"
	"log"
	"os"
)

func main() {
	state := flag.String("state", "", "existing protected 0700 directory")
	config := flag.String("config", "", "reviewed pilot config for init")
	input := flag.String("input", "", "public challenge, certificate or station reconciliation response")
	idempotency := flag.String("idempotency-key", "", "stable key for diagnostic submission; retain with exact input")
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
		value, e = pilotenrollment.Initialize(*state, c, pilotenrollment.SystemRuntime())
	} else {
		c, err := pilotenrollment.Open(*state, pilotenrollment.SystemRuntime())
		if err != nil {
			log.Fatal(err)
		}
		defer c.Close()
		var raw []byte
		if *input != "" {
			if flag.Arg(0) == "submit-diagnostic" {
				f, openErr := os.Open(*input)
				if openErr != nil {
					log.Fatal(openErr)
				}
				raw, err = io.ReadAll(io.LimitReader(f, 4097))
				f.Close()
			} else {
				raw, err = os.ReadFile(*input)
			}
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
		case "submit-diagnostic":
			value, e = c.SubmitDiagnostic(context.Background(), raw, *idempotency)
		case "self":
			value, e = c.CheckAccess(context.Background())
		default:
			log.Fatal("unknown command")
		}
	}
	if e != nil {
		if writeRequestError(os.Stderr, e) {
			os.Exit(1)
		}
		log.Fatal(e)
	}
	if e = json.NewEncoder(os.Stdout).Encode(value); e != nil {
		log.Fatal(e)
	}
}

func writeRequestError(w io.Writer, err error) bool {
	var request *pilotenrollment.RequestError
	if !errors.As(err, &request) {
		return false
	}
	_ = json.NewEncoder(w).Encode(struct {
		Schema string `json:"schema_version"`
		*pilotenrollment.RequestError
		Reconcile bool `json:"reconciliation_required"`
	}{"kaiba.pilot-device-error/v1alpha1", request, true})
	return true
}
