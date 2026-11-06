package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/frict-auth/frict-server/internal/duosig"
	"github.com/frict-auth/frict-server/internal/server"
)

func TestLoadConfig(t *testing.T) {
	full := map[string]string{
		"FRICT_API_HOSTNAME":       "api.frict.app",
		"FRICT_CLIENT_ID":          "DIXXXX",
		"FRICT_CLIENT_SECRET_FILE": "/secrets/duo-client-secret",
		"FRICT_DB_PATH":            "/data/frict.db",
		"FRICT_AUTHENTIK_URL":      "https://auth.example",
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
		s.AuthentikURL = "https://auth.example"
		edit(&s)
		return s
	}
	defaults := sg(func(*server.Safeguards) {})
	want := func(listen string, ttl time.Duration, s server.Safeguards) config {
		return config{listen, "api.frict.app", "DIXXXX", "/secrets/duo-client-secret", "/data/frict.db", ttl, s}
	}

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
			m["FRICT_MAX_FAILED"] = "100"
			m["FRICT_PAUSE"] = "1h"
			m["FRICT_ALERT_RECIPIENTS"] = " akadmin, sec ,,"
			m["FRICT_ALERT_TTL"] = "48h"
			return m
		}(), want(":8080", 60*time.Second, sg(func(s *server.Safeguards) {
			s.PushCap, s.PushCooldown, s.MaxFailed, s.Pause = 5, 5*time.Minute, 100, time.Hour
			s.AlertRecipients, s.AlertTTL = []string{"akadmin", "sec"}, 48*time.Hour
		})), ""},
		{"max failed above NIST's 100", with("FRICT_MAX_FAILED", "101"), config{}, "FRICT_MAX_FAILED"},
		{"max failed zero", with("FRICT_MAX_FAILED", "0"), config{}, "FRICT_MAX_FAILED"},
		{"push cap zero", with("FRICT_PUSH_CAP", "0"), config{}, "FRICT_PUSH_CAP"},
		{"push cap not a number", with("FRICT_PUSH_CAP", "ten"), config{}, "FRICT_PUSH_CAP"},
		{"cooldown fractional", with("FRICT_PUSH_COOLDOWN", "1.5s"), config{}, "FRICT_PUSH_COOLDOWN"},
		{"pause zero", with("FRICT_PAUSE", "0s"), config{}, "FRICT_PAUSE"},
		{"alert ttl no unit", with("FRICT_ALERT_TTL", "3600"), config{}, "FRICT_ALERT_TTL"},
		{"no alert recipients", with("FRICT_ALERT_RECIPIENTS", " , "), config{}, "FRICT_ALERT_RECIPIENTS"},
		{"authentik url without scheme", with("FRICT_AUTHENTIK_URL", "auth.example"), config{}, "FRICT_AUTHENTIK_URL"},
		{"no authentik url", without("FRICT_AUTHENTIK_URL"), config{}, "FRICT_AUTHENTIK_URL"},
		{"no hostname", without("FRICT_API_HOSTNAME"), config{}, "FRICT_API_HOSTNAME"},
		{"no client id", without("FRICT_CLIENT_ID"), config{}, "FRICT_CLIENT_ID"},
		{"no secret file", without("FRICT_CLIENT_SECRET_FILE"), config{}, "FRICT_CLIENT_SECRET_FILE"},
		{"no db path", without("FRICT_DB_PATH"), config{}, "FRICT_DB_PATH"},
		{"all missing named", map[string]string{}, config{}, "FRICT_API_HOSTNAME, FRICT_CLIENT_ID, FRICT_CLIENT_SECRET_FILE, FRICT_DB_PATH, FRICT_AUTHENTIK_URL"},
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
	dir := t.TempDir()
	secretFile := filepath.Join(dir, "client-secret")
	if err := os.WriteFile(secretFile, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return config{APIHostname: "api.frict.test", ClientID: "DIXXXX", ClientSecretFile: secretFile, DBPath: filepath.Join(dir, "frict.db"), ChallengeTTL: 60 * time.Second, Safeguards: defaultSafeguards}
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
