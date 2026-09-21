package main

import (
	"flag"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/fleetexport"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/handoff"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mtls"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	config := flag.String("config", "", "export configuration")
	state := flag.String("state", "", "private revision store")
	listen := flag.String("listen", "127.0.0.1:8094", "listener")
	cert := flag.String("tls-cert", "", "server certificate")
	key := flag.String("tls-key", "", "server key")
	ca := flag.String("client-ca", "", "client CA")
	flag.Parse()
	if *config == "" || *state == "" || *cert == "" || *key == "" || *ca == "" || flag.NArg() != 0 {
		log.Fatal("complete configuration required")
	}
	b, e := os.ReadFile(*config)
	if e != nil {
		log.Fatal(e)
	}
	var c fleetexport.Config
	if e = handoff.Decode(b, &c); e != nil {
		log.Fatal(e)
	}
	s, e := fleetexport.NewServer(c, *state)
	if e != nil {
		log.Fatal(e)
	}
	defer s.Close()
	tls, e := mtls.LoadServerConfig(mtls.Files{Certificate: *cert, PrivateKey: *key, ClientCA: *ca})
	if e != nil {
		log.Fatal(e)
	}
	server := &http.Server{Addr: *listen, Handler: s.Handler(), TLSConfig: tls, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384}
	log.Fatal(server.ListenAndServeTLS(*cert, *key))
}
