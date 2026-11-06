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
//	FRICT_AUTHENTIK_URL       Authentik's base URL, e.g. https://auth.example, for alert links (required)
//	FRICT_PUSH_CAP            pushes since a user's last successful login before the cooldown applies, at least 1 (default 10)
//	FRICT_PUSH_COOLDOWN       once over the cap, the least time between pushes (default 15m)
//	FRICT_MAX_FAILED          denies and timeouts since the last successful login that disable the device, 1 to 100 (default 20)
//	FRICT_PAUSE               how long "I didn't start this" stops pushes to that user (default 30m)
//	FRICT_ALERT_RECIPIENTS    comma-separated Authentik usernames alerted on "I didn't start this" (default akadmin)
//	FRICT_ALERT_TTL           how long an alert stays in the device's poll (default 24h)
//
// Durations are Go durations in whole seconds. docs/PLAN.md Safeguards
// gives the reason for each default.
//
// SIGINT or SIGTERM stops accepting connections and waits up to 15 s for
// in-flight requests.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
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

	// maxFailedLimit is NIST SP 800-63B-4 §3.2.2's upper bound on
	// consecutive failed attempts before an authenticator is disabled.
	maxFailedLimit = 100
)

var defaultSafeguards = server.Safeguards{
	PushCap:         10,
	PushCooldown:    15 * time.Minute,
	MaxFailed:       20,
	Pause:           30 * time.Minute,
	AlertRecipients: []string{"akadmin"},
	AlertTTL:        24 * time.Hour,
}

type config struct {
	Listen           string
	APIHostname      string
	ClientID         string
	ClientSecretFile string
	DBPath           string
	ChallengeTTL     time.Duration
	Safeguards       server.Safeguards
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
	c.Safeguards = defaultSafeguards
	c.Safeguards.AuthentikURL = getenv("FRICT_AUTHENTIK_URL")
	if v := c.Safeguards.AuthentikURL; v != "" {
		if u, err := url.Parse(v); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return config{}, fmt.Errorf("FRICT_AUTHENTIK_URL=%q: want an http(s) URL", v)
		}
	}
	for _, n := range []struct {
		name     string
		dst      *int
		min, max int
	}{
		{"FRICT_PUSH_CAP", &c.Safeguards.PushCap, 1, math.MaxInt32},
		{"FRICT_MAX_FAILED", &c.Safeguards.MaxFailed, 1, maxFailedLimit},
	} {
		if v := getenv(n.name); v != "" {
			i, err := strconv.Atoi(v)
			if err != nil || i < n.min || i > n.max {
				return config{}, fmt.Errorf("%s=%q: want a whole number from %d to %d", n.name, v, n.min, n.max)
			}
			*n.dst = i
		}
	}
	for _, d := range []struct {
		name string
		dst  *time.Duration
	}{
		{"FRICT_PUSH_COOLDOWN", &c.Safeguards.PushCooldown},
		{"FRICT_PAUSE", &c.Safeguards.Pause},
		{"FRICT_ALERT_TTL", &c.Safeguards.AlertTTL},
	} {
		if v := getenv(d.name); v != "" {
			dur, err := time.ParseDuration(v)
			if err != nil || dur < time.Second || dur%time.Second != 0 {
				return config{}, fmt.Errorf("%s=%q: want a duration of whole seconds, at least 1s", d.name, v)
			}
			*d.dst = dur
		}
	}
	if v := getenv("FRICT_ALERT_RECIPIENTS"); v != "" {
		c.Safeguards.AlertRecipients = nil
		for _, name := range strings.Split(v, ",") {
			if name = strings.TrimSpace(name); name != "" {
				c.Safeguards.AlertRecipients = append(c.Safeguards.AlertRecipients, name)
			}
		}
		if len(c.Safeguards.AlertRecipients) == 0 {
			return config{}, fmt.Errorf("FRICT_ALERT_RECIPIENTS=%q: want at least one username", v)
		}
	}
	var missing []string
	for _, req := range []struct{ name, value string }{
		{"FRICT_API_HOSTNAME", c.APIHostname},
		{"FRICT_CLIENT_ID", c.ClientID},
		{"FRICT_CLIENT_SECRET_FILE", c.ClientSecretFile},
		{"FRICT_DB_PATH", c.DBPath},
		{"FRICT_AUTHENTIK_URL", c.Safeguards.AuthentikURL},
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
		Handler:           server.New(v, st, cfg.ChallengeTTL, cfg.Safeguards, log).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()
	log.Info("listening", "addr", ln.Addr().String(), "api_hostname", cfg.APIHostname, "challenge_ttl", cfg.ChallengeTTL.String(),
		"push_cap", cfg.Safeguards.PushCap, "push_cooldown", cfg.Safeguards.PushCooldown.String(),
		"max_failed", cfg.Safeguards.MaxFailed, "pause", cfg.Safeguards.Pause.String(),
		"alert_recipients", strings.Join(cfg.Safeguards.AlertRecipients, ","), "alert_ttl", cfg.Safeguards.AlertTTL.String(),
		"authentik_url", cfg.Safeguards.AuthentikURL)

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
