// Command frict-server serves Duo's Auth API to Authentik and the device API
// to the Frict app. It speaks plain HTTP; TLS terminates in front of it.
//
// Configuration, all from the environment:
//
//	FRICT_LISTEN              listen address (default ":8080")
//	FRICT_API_HOSTNAME        API hostname typed into Authentik's Duo stage, e.g. api.frict.app (required)
//	FRICT_CLIENT_ID           Duo stage client ID (required)
//	FRICT_CLIENT_SECRET_FILE  file holding the Duo stage client secret (required)
//	FRICT_DB_PATH             SQLite database file, created if missing (required)
//	FRICT_CHALLENGE_TTL       how long a push waits for the device's answer: whole seconds from 60s to 120s (default 60s)
//
// SIGINT or SIGTERM stops accepting connections and waits up to 15 s for
// in-flight requests.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/frict-auth/frict-server/internal/duosig"
	"github.com/frict-auth/frict-server/internal/server"
	"github.com/frict-auth/frict-server/internal/store"
)

const (
	shutdownGrace = 15 * time.Second

	defaultChallengeTTL = 60 * time.Second
	minChallengeTTL     = 60 * time.Second
	// maxChallengeTTL stays well inside the ~213 s after which Authentik
	// answers the login with HTTP 408 (docs/m0-findings.md (c′)).
	maxChallengeTTL = 120 * time.Second
)

type config struct {
	Listen           string
	APIHostname      string
	ClientID         string
	ClientSecretFile string
	DBPath           string
	ChallengeTTL     time.Duration
}

func loadConfig(getenv func(string) string) (config, error) {
	c := config{
		Listen:           getenv("FRICT_LISTEN"),
		APIHostname:      getenv("FRICT_API_HOSTNAME"),
		ClientID:         getenv("FRICT_CLIENT_ID"),
		ClientSecretFile: getenv("FRICT_CLIENT_SECRET_FILE"),
		DBPath:           getenv("FRICT_DB_PATH"),
	}
	if c.Listen == "" {
		c.Listen = ":8080"
	}
	c.ChallengeTTL = defaultChallengeTTL
	if v := getenv("FRICT_CHALLENGE_TTL"); v != "" {
		ttl, err := time.ParseDuration(v)
		if err != nil || ttl < minChallengeTTL || ttl > maxChallengeTTL || ttl%time.Second != 0 {
			return config{}, fmt.Errorf("FRICT_CHALLENGE_TTL=%q: want whole seconds from %s to %s", v, minChallengeTTL, maxChallengeTTL)
		}
		c.ChallengeTTL = ttl
	}
	var missing []string
	for _, req := range []struct{ name, value string }{
		{"FRICT_API_HOSTNAME", c.APIHostname},
		{"FRICT_CLIENT_ID", c.ClientID},
		{"FRICT_CLIENT_SECRET_FILE", c.ClientSecretFile},
		{"FRICT_DB_PATH", c.DBPath},
	} {
		if req.value == "" {
			missing = append(missing, req.name)
		}
	}
	if len(missing) > 0 {
		return config{}, fmt.Errorf("missing required environment variables: %s", strings.Join(missing, ", "))
	}
	return c, nil
}

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := loadConfig(os.Getenv)
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(2)
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		log.Error("listen", "err", err)
		os.Exit(1)
	}
	if err := run(ctx, cfg, ln, log); err != nil {
		log.Error("server stopped", "err", err)
		os.Exit(1)
	}
}

// run serves on ln until ctx is done, then shuts down gracefully.
func run(ctx context.Context, cfg config, ln net.Listener, log *slog.Logger) error {
	secret, err := os.ReadFile(cfg.ClientSecretFile)
	if err != nil {
		ln.Close()
		return fmt.Errorf("read client secret: %w", err)
	}
	skey := strings.TrimSpace(string(secret))
	if skey == "" {
		ln.Close()
		return fmt.Errorf("client secret file %s is empty", cfg.ClientSecretFile)
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		ln.Close()
		return err
	}
	defer st.Close()

	v := duosig.Verifier{
		IKey:    cfg.ClientID,
		SKey:    skey,
		Host:    cfg.APIHostname,
		MaxSkew: 5 * time.Minute,
		Now:     time.Now,
	}
	srv := &http.Server{
		Handler:           server.New(v, st, cfg.ChallengeTTL, log).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()
	log.Info("listening", "addr", ln.Addr().String(), "api_hostname", cfg.APIHostname, "challenge_ttl", cfg.ChallengeTTL.String())

	select {
	case err := <-served:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down", "grace", shutdownGrace.String())
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	if err := <-served; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
