// Command duo-stub serves a Duo-compatible Auth API that approves every push.
package main

import (
	"flag"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/frict-auth/frict-server/internal/duosig"
	"github.com/frict-auth/frict-server/internal/duostub"
)

func main() {
	listen := flag.String("listen", ":443", "TLS listen address")
	hostname := flag.String("hostname", "", "API hostname Authentik is configured with (required)")
	clientID := flag.String("client-id", "", "Duo client ID / integration key (required)")
	secretFile := flag.String("client-secret-file", "", "file holding the Duo client secret (required)")
	certFile := flag.String("tls-cert", "", "PEM certificate chain (required)")
	keyFile := flag.String("tls-key", "", "PEM private key (required)")
	authDelay := flag.Duration("auth-delay", 0, "how long /auth/v2/auth blocks before approving")
	maxSkew := flag.Duration("max-skew", 5*time.Minute, "allowed difference between request Date and now")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	for name, v := range map[string]string{"hostname": *hostname, "client-id": *clientID,
		"client-secret-file": *secretFile, "tls-cert": *certFile, "tls-key": *keyFile} {
		if v == "" {
			log.Error("missing required flag", "flag", name)
			os.Exit(2)
		}
	}
	secret, err := os.ReadFile(*secretFile)
	if err != nil {
		log.Error("reading client secret", "err", err)
		os.Exit(1)
	}

	v := duosig.Verifier{
		IKey:    *clientID,
		SKey:    strings.TrimSpace(string(secret)),
		Host:    *hostname,
		MaxSkew: *maxSkew,
		Now:     time.Now,
	}
	srv := &http.Server{
		Addr:              *listen,
		Handler:           duostub.New(v, *authDelay, log).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Info("listening", "addr", *listen, "hostname", *hostname, "auth_delay", authDelay.String())
	log.Error("server stopped", "err", srv.ListenAndServeTLS(*certFile, *keyFile))
	os.Exit(1)
}
