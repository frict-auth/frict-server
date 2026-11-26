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
//	FRICT_PUSH_CAP            pushes since a user's last successful login before the cooldown applies, at least 1 (default 10)
//	FRICT_PUSH_COOLDOWN       once over the cap, the least time between pushes (default 15m)
//	FRICT_NOT_ME_COUNT        "I didn't start this" answers that pause the user's pushes, at least 1 (default 2) ...
//	FRICT_NOT_ME_WINDOW       ... when given within this long (default 60m)
//	FRICT_PAUSE               how long the pause lasts (default 30m)
//	FRICT_TRUSTED_PROXIES     comma-separated addresses or CIDR prefixes whose X-Forwarded-For and X-Real-IP name the client (default 127.0.0.0/8,::1)
//	FRICT_FCM_PROJECT_ID      Firebase project to push through
//	FRICT_FCM_CREDENTIALS_FILE  that project's FCM sender service-account key (JSON)
//	FRICT_APP_SIGNING_CERTS   comma-separated SHA-256 digests of the app's signing certificates, hex, colons optional; empty refuses every enrollment
//	FRICT_APP_PACKAGES        comma-separated application IDs the app may have (default app.frict.android)
//	FRICT_ATTESTATION         "strict" (default) or "emulator"; any other value is strict
//	FRICT_MIN_APP_VERSION     least app versionCode served, from 0 to 2100000000; 0 (default) serves any
//
// Strict attestation requires each key's chain to end in a Google root, every
// certificate below the root valid, none on Google's revocation list, and
// the keys in TEE or StrongBox. "emulator" accepts any root and software keys
// and skips validity and revocation, for emulators in e2e tests only.
//
// Durations are Go durations in whole seconds. docs/PLAN.md Safeguards
// gives the reason for each default.
//
// A phone below FRICT_MIN_APP_VERSION, or sending no version, is answered
// 426 and gets no pushes (docs/device-protocol.md).
//
// Push is on only when both FRICT_FCM_* are set; with neither, the server
// sends no pushes and devices find challenges by polling.
//
// At startup and every hour, the server deletes login records that expired
// more than max(24h, FRICT_NOT_ME_WINDOW) ago, and users whose activation
// code expired more than 24h ago without enrolling a device.
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
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/frict-auth/frict-server/internal/attest"
	"github.com/frict-auth/frict-server/internal/duosig"
	"github.com/frict-auth/frict-server/internal/push"
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

	// minRetention is the least time a finished login record is kept.
	minRetention = 24 * time.Hour
	// unclaimedGrace is how long a user whose activation code expired
	// unused is kept. Deleting it changes no answer, so this is only for an
	// operator matching a failed enrollment in the logs to its username.
	unclaimedGrace = 24 * time.Hour
	pruneInterval  = time.Hour

	// fcmTimeout bounds each HTTP request to FCM or its token endpoint.
	fcmTimeout = 10 * time.Second

	// statusTimeout bounds a fetch of the attestation revocation list.
	statusTimeout = 10 * time.Second
	statusTTL     = time.Hour

	defaultAppPackage = "app.frict.android"
)

var defaultSafeguards = server.Safeguards{
	PushCap:      10,
	PushCooldown: 15 * time.Minute,
	NotMeCount:   2,
	NotMeWindow:  60 * time.Minute,
	Pause:        30 * time.Minute,
}

type config struct {
	Listen           string
	APIHostname      string
	ClientID         string
	ClientSecretFile string
	DBPath           string
	ChallengeTTL     time.Duration
	Safeguards       server.Safeguards
	TrustedProxies   []netip.Prefix
	FCM              fcmConfig
	Attestation      attestConfig
	MinAppVersion    int
}

type attestConfig struct {
	Mode attest.Mode
	// Unknown is FRICT_ATTESTATION when it named no mode.
	Unknown      string
	Packages     []string
	SigningCerts [][32]byte
}

// fcmConfig is empty when push is off.
type fcmConfig struct {
	ProjectID       string
	CredentialsFile string
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
	for _, n := range []struct {
		name     string
		dst      *int
		min, max int
	}{
		{"FRICT_PUSH_CAP", &c.Safeguards.PushCap, 1, math.MaxInt32},
		{"FRICT_NOT_ME_COUNT", &c.Safeguards.NotMeCount, 1, math.MaxInt32},
		{"FRICT_MIN_APP_VERSION", &c.MinAppVersion, 0, server.MaxAppVersion},
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
		{"FRICT_NOT_ME_WINDOW", &c.Safeguards.NotMeWindow},
		{"FRICT_PAUSE", &c.Safeguards.Pause},
	} {
		if v := getenv(d.name); v != "" {
			dur, err := time.ParseDuration(v)
			if err != nil || dur < time.Second || dur%time.Second != 0 {
				return config{}, fmt.Errorf("%s=%q: want a duration of whole seconds, at least 1s", d.name, v)
			}
			*d.dst = dur
		}
	}
	c.TrustedProxies = server.LoopbackProxies
	if v := getenv("FRICT_TRUSTED_PROXIES"); v != "" {
		c.TrustedProxies = nil
		for _, item := range strings.Split(v, ",") {
			p, err := parsePrefix(strings.TrimSpace(item))
			if err != nil {
				return config{}, fmt.Errorf("FRICT_TRUSTED_PROXIES=%q: %w", v, err)
			}
			c.TrustedProxies = append(c.TrustedProxies, p)
		}
	}
	c.FCM = fcmConfig{ProjectID: getenv("FRICT_FCM_PROJECT_ID"), CredentialsFile: getenv("FRICT_FCM_CREDENTIALS_FILE")}
	if (c.FCM.ProjectID == "") != (c.FCM.CredentialsFile == "") {
		return config{}, errors.New("FRICT_FCM_PROJECT_ID and FRICT_FCM_CREDENTIALS_FILE: set both to push through FCM, or neither to have devices poll")
	}
	c.Attestation.Mode, c.Attestation.Unknown = parseAttestationMode(getenv("FRICT_ATTESTATION"))
	c.Attestation.Packages = []string{defaultAppPackage}
	if v := getenv("FRICT_APP_PACKAGES"); v != "" {
		c.Attestation.Packages = nil
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p == "" {
				return config{}, fmt.Errorf("FRICT_APP_PACKAGES=%q: empty application ID", v)
			}
			c.Attestation.Packages = append(c.Attestation.Packages, p)
		}
	}
	if v := getenv("FRICT_APP_SIGNING_CERTS"); v != "" {
		var hexes []string
		for _, d := range strings.Split(v, ",") {
			hexes = append(hexes, strings.ToLower(strings.ReplaceAll(strings.TrimSpace(d), ":", "")))
		}
		certs, err := attest.Digests(hexes...)
		if err != nil {
			return config{}, fmt.Errorf("FRICT_APP_SIGNING_CERTS: %w: want SHA-256 digests as Play Console shows them, comma-separated", err)
		}
		c.Attestation.SigningCerts = certs
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

func parseAttestationMode(v string) (attest.Mode, string) {
	m, known := attest.ParseMode(v)
	if !known {
		return m, v
	}
	return m, ""
}

// parsePrefix reads an address as the prefix holding just it, or a CIDR
// prefix.
func parsePrefix(s string) (netip.Prefix, error) {
	if a, err := netip.ParseAddr(s); err == nil {
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is neither an IP address nor a CIDR prefix", s)
	}
	return p.Masked(), nil
}

// retention is how long a finished login record is kept: long enough to
// count its not_me deny.
func retention(sg server.Safeguards) time.Duration { return max(minRetention, sg.NotMeWindow) }

// prune deletes login records past retention and users unclaimed past
// unclaimedGrace now, then every pruneInterval until ctx is done.
func prune(ctx context.Context, st *store.Store, keep time.Duration, log *slog.Logger) {
	ticker := time.NewTicker(pruneInterval)
	defer ticker.Stop()
	for {
		now := time.Now()
		n, err := st.DeleteChallengesBefore(ctx, now.Add(-keep))
		if err != nil {
			log.Error("prune login records", "err", err)
		} else {
			log.Info("pruned login records", "deleted", n, "retention", keep.String())
		}
		n, err = st.DeleteUnclaimedEnrollmentsBefore(ctx, now.Add(-unclaimedGrace))
		if err != nil {
			log.Error("prune unclaimed enrollments", "err", err)
		} else {
			log.Info("pruned unclaimed enrollments", "deleted", n, "grace", unclaimedGrace.String())
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
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
	sender, err := newSender(cfg.FCM)
	if err != nil {
		ln.Close()
		return err
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
	pruneCtx, stopPrune := context.WithCancel(ctx)
	pruned := make(chan struct{})
	go func() {
		defer close(pruned)
		prune(pruneCtx, st, retention(cfg.Safeguards), log)
	}()
	defer func() {
		stopPrune()
		<-pruned
	}()

	att := attestVerifier(cfg.Attestation)
	h := server.New(v, st, cfg.ChallengeTTL, cfg.Safeguards, cfg.TrustedProxies, sender, att, cfg.MinAppVersion, log)
	defer h.Close()
	srv := &http.Server{
		Handler:           h.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()
	log.Info("listening", "addr", ln.Addr().String(), "api_hostname", cfg.APIHostname, "challenge_ttl", cfg.ChallengeTTL.String(),
		"push_cap", cfg.Safeguards.PushCap, "push_cooldown", cfg.Safeguards.PushCooldown.String(),
		"not_me_count", cfg.Safeguards.NotMeCount, "not_me_window", cfg.Safeguards.NotMeWindow.String(),
		"pause", cfg.Safeguards.Pause.String(), "trusted_proxies", fmt.Sprint(cfg.TrustedProxies),
		"min_app_version", cfg.MinAppVersion)
	logAttestation(cfg.Attestation, log)
	if sender == nil {
		log.Warn("push disabled: FRICT_FCM_PROJECT_ID and FRICT_FCM_CREDENTIALS_FILE are unset; devices find challenges only by polling")
	} else {
		log.Info("push enabled", "fcm_project", cfg.FCM.ProjectID)
	}

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

func attestVerifier(cfg attestConfig) *attest.Verifier {
	roots, err := attest.Digests(attest.GoogleRoots...)
	if err != nil {
		panic(err)
	}
	return &attest.Verifier{
		Mode:         cfg.Mode,
		Roots:        roots,
		Packages:     cfg.Packages,
		SigningCerts: cfg.SigningCerts,
		Status: &attest.StatusList{
			URL:    attest.GoogleStatusURL,
			Client: &http.Client{Timeout: statusTimeout},
			TTL:    statusTTL,
			Now:    time.Now,
		},
	}
}

func logAttestation(cfg attestConfig, log *slog.Logger) {
	if cfg.Unknown != "" {
		log.Warn("FRICT_ATTESTATION names no mode: using strict", "value", cfg.Unknown)
	}
	log.Info("attestation", "mode", string(cfg.Mode), "packages", strings.Join(cfg.Packages, ","), "signing_certs", len(cfg.SigningCerts))
	if cfg.Mode != attest.Strict {
		log.Warn("attestation is not strict: software keys under any root can enroll")
	}
	if len(cfg.SigningCerts) == 0 {
		log.Warn("FRICT_APP_SIGNING_CERTS is empty: every enrollment is refused")
	}
}

// newSender returns the FCM sender cfg describes, or nil when push is off.
func newSender(cfg fcmConfig) (push.Sender, error) {
	if cfg.ProjectID == "" {
		return nil, nil
	}
	key, err := os.ReadFile(cfg.CredentialsFile)
	if err != nil {
		return nil, fmt.Errorf("read FRICT_FCM_CREDENTIALS_FILE: %w", err)
	}
	client := &http.Client{Timeout: fcmTimeout}
	tokens, err := push.ServiceAccountTokens(key, client)
	if err != nil {
		return nil, fmt.Errorf("FCM service-account key %s: %w", cfg.CredentialsFile, err)
	}
	return push.NewFCM(push.FCMBaseURL, cfg.ProjectID, tokens, client), nil
}
