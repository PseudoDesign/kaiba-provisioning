package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/guidedcampaign"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mtls"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if e := run(ctx, os.Args[1:], os.Stderr); e != nil {
		fmt.Fprintln(os.Stderr, "kaiba-provision-campaign:", e)
		os.Exit(1)
	}
}
func run(ctx context.Context, args []string, output io.Writer) error {
	f := flag.NewFlagSet("kaiba-provision-campaign", flag.ContinueOnError)
	f.SetOutput(output)
	plan := f.String("plan", "", "immutable reviewed campaign plan in the Nix store")
	describe := f.Bool("describe-plan", false, "print public plan identity and digest without executing or serving")
	state := f.String("state", "", "existing private persistent journal directory")
	listen := f.String("listen", "127.0.0.1:8446", "explicit mTLS listener")
	var files mtls.Files
	f.StringVar(&files.Certificate, "tls-cert", "", "server certificate")
	f.StringVar(&files.PrivateKey, "tls-key", "", "server private key")
	f.StringVar(&files.ClientCA, "client-ca", "", "exclusive station client CA")
	if e := f.Parse(args); e != nil {
		return e
	}
	if f.NArg() != 0 || *plan == "" || (!*describe && (*state == "" || !files.Enabled())) {
		return errors.New("plan, state and complete mTLS credentials are required")
	}
	if e := mtls.ValidateListenAddress(*listen, true); e != nil {
		return e
	}
	p, e := guidedcampaign.LoadPlan(*plan)
	if e != nil {
		return e
	}
	if *describe {
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"campaign_id": p.ID, "plan_digest": p.Digest(), "mode": p.Mode, "production_enrollment": false})
	}
	tls, e := guidedcampaign.TLSConfig(files)
	if e != nil {
		return e
	}
	engine, e := guidedcampaign.Open(ctx, *state, p, guidedcampaign.ProcessExecutor{})
	if e != nil {
		return e
	}
	defer engine.Close()
	listener, e := net.Listen("tcp", *listen)
	if e != nil {
		return e
	}
	server := &http.Server{Handler: guidedcampaign.Handler(engine), TLSConfig: tls, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}
	result := make(chan error, 1)
	go func() { result <- server.ServeTLS(listener, "", "") }()
	select {
	case e := <-result:
		if errors.Is(e, http.ErrServerClosed) {
			return nil
		}
		return e
	case <-ctx.Done():
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(c)
	}
}
