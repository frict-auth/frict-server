package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/frict-auth/frict-server/internal/duosig"
)

const (
	host     = "api.frict.test"
	clientID = "DIXXXXXXXXXXXXXXXXXX"
	secret   = "client-secret"
)

var now = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

type fakeStore struct{ err error }

func (f fakeStore) Ping(context.Context) error { return f.err }

func newServer(store Pinger) *Server {
	v := duosig.Verifier{IKey: clientID, SKey: secret, Host: host, MaxSkew: 5 * time.Minute, Now: func() time.Time { return now }}
	return New(v, store, slog.New(slog.DiscardHandler))
}

// signedRequest builds a POST signed the way duo_client signs it, with skey.
func signedRequest(t *testing.T, path, body, skey string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "https://"+host+path, strings.NewReader(body))
	r.Header.Set("Date", now.Format(time.RFC1123Z))
	r.Header.Set("Content-Type", "application/json")
	if err := duosig.Sign(r, []byte(body), clientID, skey, host); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return r
}

func TestAuthAPIRequiresDuoSignature(t *testing.T) {
	unsigned := func(path string) *http.Request {
		return httptest.NewRequest(http.MethodPost, "https://"+host+path, strings.NewReader(`{}`))
	}
	tests := []struct {
		name string
		req  *http.Request
		want int
	}{
		{"enroll signed", signedRequest(t, "/auth/v2/enroll", `{"username":"alice"}`, secret), http.StatusNotImplemented},
		{"enroll_status signed", signedRequest(t, "/auth/v2/enroll_status", `{}`, secret), http.StatusNotImplemented},
		{"auth signed", signedRequest(t, "/auth/v2/auth", `{"user_id":"DU1"}`, secret), http.StatusNotImplemented},
		{"enroll unsigned", unsigned("/auth/v2/enroll"), http.StatusUnauthorized},
		{"enroll_status unsigned", unsigned("/auth/v2/enroll_status"), http.StatusUnauthorized},
		{"auth unsigned", unsigned("/auth/v2/auth"), http.StatusUnauthorized},
		{"auth wrong secret", signedRequest(t, "/auth/v2/auth", `{}`, "wrong"), http.StatusUnauthorized},
		{"unknown endpoint", signedRequest(t, "/auth/v2/ping", `{}`, secret), http.StatusNotFound},
	}
	h := newServer(fakeStore{}).Handler()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, tc.req)
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d; body %s", w.Code, tc.want, w.Body)
			}
			if tc.want != http.StatusNotFound && !strings.Contains(w.Body.String(), `"stat":"FAIL"`) {
				t.Fatalf("body %q is not a Duo FAIL response", w.Body)
			}
		})
	}
}

func TestDuoSignedPassesBodyThrough(t *testing.T) {
	const body = `{"username":"élodie"}`
	var got string
	h := newServer(fakeStore{}).duoSigned(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		got = string(b)
	})
	h.ServeHTTP(httptest.NewRecorder(), signedRequest(t, "/auth/v2/enroll", body, secret))
	if got != body {
		t.Fatalf("handler saw body %q, want %q", got, body)
	}
}

func TestHealthz(t *testing.T) {
	tests := []struct {
		name  string
		store fakeStore
		want  int
	}{
		{"store up", fakeStore{}, http.StatusOK},
		{"store down", fakeStore{err: errors.New("database is closed")}, http.StatusServiceUnavailable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			newServer(tc.store).Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d", w.Code, tc.want)
			}
		})
	}
}
