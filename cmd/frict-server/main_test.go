package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/frict-auth/frict-server/internal/duosig"
	"github.com/frict-auth/frict-server/internal/server"
	"github.com/frict-auth/frict-server/internal/store"
)

// isolateHome points HOME at an empty directory, so nothing a test starts
// can find credentials in the user's home.
func isolateHome(t *testing.T) { t.Setenv("HOME", t.TempDir()) }

func TestLoadConfig(t *testing.T) {
	isolateHome(t)
	full := map[string]string{
		"FRICT_API_HOSTNAME":       "api.frict.app",
		"FRICT_CLIENT_ID":          "DIXXXX",
		"FRICT_CLIENT_SECRET_FILE": "/secrets/duo-client-secret",
		"FRICT_DB_PATH":            "/data/frict.db",
	}
	without := func(keys ...string) map[string]string {
		m := map[string]string{}
		for k, v := range full {
			m[k] = v
		}
		for _, k := range keys {
			delete(m, k)
		}
		return m
	}
	with := func(k, v string) map[string]string { m := without(); m[k] = v; return m }
	sg := func(edit func(*server.Safeguards)) server.Safeguards {
		s := defaultSafeguards
		edit(&s)
		return s
	}
	defaults := sg(func(*server.Safeguards) {})
	want := func(listen string, ttl time.Duration, s server.Safeguards) config {
		return config{listen, "api.frict.app", "DIXXXX", "/secrets/duo-client-secret", "/data/frict.db", ttl, s, server.LoopbackProxies, fcmConfig{}}
	}
	withProxies := func(c config, ps ...string) config {
		c.TrustedProxies = nil
		for _, p := range ps {
			c.TrustedProxies = append(c.TrustedProxies, netip.MustParsePrefix(p))
		}
		return c
	}
	withFCM := func(c config) config { c.FCM = fcmConfig{"frict-test", "/secrets/fcm-sa.json"}; return c }

	tests := []struct {
		name    string
		env     map[string]string
		want    config
		wantErr string
	}{
		{"defaults", full, want(":8080", 60*time.Second, defaults), ""},
		{"listen set", with("FRICT_LISTEN", "127.0.0.1:9000"), want("127.0.0.1:9000", 60*time.Second, defaults), ""},
		{"challenge ttl 120s", with("FRICT_CHALLENGE_TTL", "120s"), want(":8080", 120*time.Second, defaults), ""},
		{"challenge ttl 90s", with("FRICT_CHALLENGE_TTL", "1m30s"), want(":8080", 90*time.Second, defaults), ""},
		{"challenge ttl below 60s", with("FRICT_CHALLENGE_TTL", "59s"), config{}, "FRICT_CHALLENGE_TTL"},
		{"challenge ttl above 120s", with("FRICT_CHALLENGE_TTL", "121s"), config{}, "FRICT_CHALLENGE_TTL"},
		{"challenge ttl fractional", with("FRICT_CHALLENGE_TTL", "60.5s"), config{}, "FRICT_CHALLENGE_TTL"},
		{"challenge ttl no unit", with("FRICT_CHALLENGE_TTL", "90"), config{}, "FRICT_CHALLENGE_TTL"},
		{"safeguards set", func() map[string]string {
			m := with("FRICT_PUSH_CAP", "5")
			m["FRICT_PUSH_COOLDOWN"] = "5m"
			m["FRICT_NOT_ME_COUNT"] = "3"
			m["FRICT_NOT_ME_WINDOW"] = "2h"
			m["FRICT_PAUSE"] = "1h"
			return m
		}(), want(":8080", 60*time.Second, sg(func(s *server.Safeguards) {
			s.PushCap, s.PushCooldown, s.NotMeCount, s.NotMeWindow, s.Pause = 5, 5*time.Minute, 3, 2*time.Hour, time.Hour
		})), ""},
		{"trusted proxies", with("FRICT_TRUSTED_PROXIES", " 172.17.0.1, 10.0.0.0/8 ,::1,::ffff:192.0.2.1,10.1.2.3/8"),
			withProxies(want(":8080", 60*time.Second, defaults), "172.17.0.1/32", "10.0.0.0/8", "::1/128", "192.0.2.1/32", "10.0.0.0/8"), ""},
		{"trusted proxy not an address", with("FRICT_TRUSTED_PROXIES", "localhost"), config{}, "FRICT_TRUSTED_PROXIES"},
		{"trusted proxies empty item", with("FRICT_TRUSTED_PROXIES", "127.0.0.1,"), config{}, "FRICT_TRUSTED_PROXIES"},
		{"fcm set", func() map[string]string {
			m := with("FRICT_FCM_PROJECT_ID", "frict-test")
			m["FRICT_FCM_CREDENTIALS_FILE"] = "/secrets/fcm-sa.json"
			return m
		}(), withFCM(want(":8080", 60*time.Second, defaults)), ""},
		{"fcm project without key", with("FRICT_FCM_PROJECT_ID", "frict-test"), config{}, "FRICT_FCM_CREDENTIALS_FILE"},
		{"fcm key without project", with("FRICT_FCM_CREDENTIALS_FILE", "/secrets/fcm-sa.json"), config{}, "FRICT_FCM_PROJECT_ID"},
		{"not me count zero", with("FRICT_NOT_ME_COUNT", "0"), config{}, "FRICT_NOT_ME_COUNT"},
		{"not me window no unit", with("FRICT_NOT_ME_WINDOW", "3600"), config{}, "FRICT_NOT_ME_WINDOW"},
		{"push cap zero", with("FRICT_PUSH_CAP", "0"), config{}, "FRICT_PUSH_CAP"},
		{"push cap not a number", with("FRICT_PUSH_CAP", "ten"), config{}, "FRICT_PUSH_CAP"},
		{"cooldown fractional", with("FRICT_PUSH_COOLDOWN", "1.5s"), config{}, "FRICT_PUSH_COOLDOWN"},
		{"pause zero", with("FRICT_PAUSE", "0s"), config{}, "FRICT_PAUSE"},
		{"no hostname", without("FRICT_API_HOSTNAME"), config{}, "FRICT_API_HOSTNAME"},
		{"no client id", without("FRICT_CLIENT_ID"), config{}, "FRICT_CLIENT_ID"},
		{"no secret file", without("FRICT_CLIENT_SECRET_FILE"), config{}, "FRICT_CLIENT_SECRET_FILE"},
		{"no db path", without("FRICT_DB_PATH"), config{}, "FRICT_DB_PATH"},
		{"all missing named", map[string]string{}, config{}, "FRICT_API_HOSTNAME, FRICT_CLIENT_ID, FRICT_CLIENT_SECRET_FILE, FRICT_DB_PATH"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := loadConfig(func(k string) string { return tc.env[k] })
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want one naming %s", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("config = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// testConfig writes a client secret (with a trailing newline, as editors
// leave it) and returns a config using it and a fresh database.
func testConfig(t *testing.T, secret string) config {
	t.Helper()
	isolateHome(t)
	dir := t.TempDir()
	secretFile := filepath.Join(dir, "client-secret")
	if err := os.WriteFile(secretFile, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return config{APIHostname: "api.frict.test", ClientID: "DIXXXX", ClientSecretFile: secretFile, DBPath: filepath.Join(dir, "frict.db"), ChallengeTTL: 60 * time.Second, Safeguards: defaultSafeguards, TrustedProxies: server.LoopbackProxies}
}

type running struct {
	url    string
	cancel context.CancelFunc
	done   chan error
}

func start(t *testing.T, cfg config) running {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfg, ln, slog.New(slog.DiscardHandler)) }()
	t.Cleanup(cancel)
	return running{url: "http://" + ln.Addr().String(), cancel: cancel, done: done}
}

func (r running) stop(t *testing.T) {
	t.Helper()
	r.cancel()
	select {
	case err := <-r.done:
		if err != nil {
			t.Fatalf("run returned %v after shutdown, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return within 5s of cancel")
	}
}

func TestRunServesWithConfiguredSecret(t *testing.T) {
	cfg := testConfig(t, "s3cret")
	srv := start(t, cfg)
	// A pooled client can leave a spare connection that Shutdown waits ~5s for.
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}

	resp, err := client.Get(srv.url + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/healthz = %d, want 200", resp.StatusCode)
	}

	// The right secret gets past the signature check to /auth's 400 for a
	// user with no device.
	for _, tc := range []struct {
		skey string
		want int
	}{{"s3cret", http.StatusBadRequest}, {"s3cret\n", http.StatusUnauthorized}, {"other", http.StatusUnauthorized}} {
		body := `{"user_id":"DU1"}`
		req, err := http.NewRequest(http.MethodPost, srv.url+"/auth/v2/auth", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Date", time.Now().UTC().Format(time.RFC1123Z))
		if err := duosig.Sign(req, []byte(body), cfg.ClientID, tc.skey, cfg.APIHostname); err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("POST /auth/v2/auth: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Fatalf("signed with %q: status %d, want %d", tc.skey, resp.StatusCode, tc.want)
		}
	}
	srv.stop(t)
}

func TestRunFinishesInFlightRequestOnShutdown(t *testing.T) {
	srv := start(t, testConfig(t, "s3cret"))

	// The server sends 100 Continue when the handler first reads the body,
	// so Got100Continue means the request is in flight.
	reading := make(chan struct{})
	ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{Got100Continue: func() { close(reading) }})
	body, bodyW := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.url+"/auth/v2/auth", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Expect", "100-continue")
	client := &http.Client{Transport: &http.Transport{ExpectContinueTimeout: time.Minute}}
	got := make(chan int, 1)
	go func() {
		resp, err := client.Do(req)
		if err != nil {
			t.Errorf("in-flight request failed: %v", err)
			got <- 0
			return
		}
		resp.Body.Close()
		got <- resp.StatusCode
	}()
	select {
	case <-reading:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not start reading the request body within 5s")
	}
	if _, err := bodyW.Write([]byte(`{"user_id":`)); err != nil {
		t.Fatal(err)
	}

	srv.cancel()
	waitListenerClosed(t, strings.TrimPrefix(srv.url, "http://"))
	if _, err := bodyW.Write([]byte(`"DU1"}`)); err != nil {
		t.Fatalf("finish body after shutdown began: %v", err)
	}
	bodyW.Close()

	if code := <-got; code != http.StatusUnauthorized {
		t.Fatalf("in-flight request got %d, want 401 (unsigned, but answered)", code)
	}
	srv.stop(t)
}

// waitListenerClosed returns once addr refuses connections, i.e. Shutdown
// has begun.
func waitListenerClosed(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			return
		}
		c.Close()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("listener still accepting 5s after cancel")
}

func TestRunRejectsBadSecretFile(t *testing.T) {
	tests := []struct {
		name    string
		missing bool
		wantErr string
	}{
		{"missing file", true, "read client secret"},
		{"empty file", false, "is empty"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(t, "")
			if tc.missing {
				cfg.ClientSecretFile = filepath.Join(t.TempDir(), "absent")
			}
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			err = run(context.Background(), cfg, ln, slog.New(slog.DiscardHandler))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("run = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

// syncBuffer is a log destination the running server writes to while a
// test reads it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestRunWithoutFCMSaysPollOnly(t *testing.T) {
	cfg := testConfig(t, "s3cret")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfg, ln, slog.New(slog.NewTextHandler(logs, nil))) }()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(logs.String(), "push disabled") {
		if time.Now().After(deadline) {
			t.Fatalf("no poll-only notice at startup; logs:\n%s", logs)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(logs.String(), "level=WARN") {
		t.Fatalf("poll-only notice is not a warning; logs:\n%s", logs)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run = %v", err)
	}
}

func TestRunRejectsBadFCMKey(t *testing.T) {
	dir := t.TempDir()
	userCreds := filepath.Join(dir, "user.json")
	if err := os.WriteFile(userCreds, []byte(`{"type":"authorized_user","client_id":"x","client_secret":"y","refresh_token":"z"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, file, wantErr string }{
		{"missing file", filepath.Join(dir, "absent.json"), "read FRICT_FCM_CREDENTIALS_FILE"},
		{"not a service account", userCreds, "service_account"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(t, "s3cret")
			cfg.FCM = fcmConfig{ProjectID: "frict-test", CredentialsFile: tc.file}
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			err = run(context.Background(), cfg, ln, slog.New(slog.DiscardHandler))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("run = %v, want an error containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestRetentionIsAtLeastADayAndTheNotMeWindow(t *testing.T) {
	for window, want := range map[time.Duration]time.Duration{
		time.Hour:      24 * time.Hour,
		24 * time.Hour: 24 * time.Hour,
		48 * time.Hour: 48 * time.Hour,
	} {
		if got := retention(server.Safeguards{NotMeWindow: window}); got != want {
			t.Errorf("retention with a %s window = %s, want %s", window, got, want)
		}
	}
}

// TestRunPrunesLoginRecordsAtStartup: a challenge that expired more than
// the retention ago is gone once the server is up; a newer one stays.
func TestRunPrunesLoginRecordsAtStartup(t *testing.T) {
	cfg := testConfig(t, "s3cret")
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Now()
	keep := retention(cfg.Safeguards)
	if err := st.CreateEnrollment(ctx, "DUAAAAAAAAAAAAAAAAAAAAAAAAAA", "alice", "CODE", now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := st.Enroll(ctx, "CODE", "DUAAAAAAAAAAAAAAAAAAAAAAAAAA", store.Device{DeviceKey: []byte{1}, ApprovalKey: []byte{2}, Attestation: []byte("{}"), EnrolledAt: now}); err != nil {
		t.Fatal(err)
	}
	old, recent := make([]byte, 16), make([]byte, 16)
	recent[0] = 1
	for id, created := range map[*[]byte]time.Time{&old: now.Add(-keep - 2*time.Minute), &recent: now.Add(-keep + time.Minute)} {
		c := store.Challenge{ID: *id, UserID: "DUAAAAAAAAAAAAAAAAAAAAAAAAAA", CreatedAt: created, ExpiresAt: created.Add(time.Minute)}
		if _, err := st.StartPush(ctx, c, store.Limits{PushCap: 100, Cooldown: time.Second}); err != nil {
			t.Fatal(err)
		}
	}
	st.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	runCtx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(runCtx, cfg, ln, slog.New(slog.NewTextHandler(logs, nil))) }()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(logs.String(), "pruned login records") {
		if time.Now().After(deadline) {
			t.Fatalf("no prune at startup; logs:\n%s", logs)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run = %v", err)
	}
	if !strings.Contains(logs.String(), "deleted=1 ") {
		t.Fatalf("startup prune did not delete exactly the old challenge; logs:\n%s", logs)
	}
	st, err = store.Open(cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.CloseChallenge(ctx, old); !errors.Is(err, store.ErrChallengeNotFound) {
		t.Fatalf("old challenge after startup: %v, want deleted", err)
	}
	if _, err := st.CloseChallenge(ctx, recent); err != nil {
		t.Fatalf("recent challenge after startup: %v, want kept", err)
	}
}
