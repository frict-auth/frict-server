package attest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// statusServer serves body with code and counts requests.
func statusServer(t *testing.T, code *atomic.Int32, body *atomic.Value) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(int(code.Load()))
		w.Write([]byte(body.Load().(string)))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func TestStatusListCachesForTTLAndNeverServesAnExpiredCopy(t *testing.T) {
	var code atomic.Int32
	var body atomic.Value
	code.Store(http.StatusOK)
	body.Store(`{"entries":{"2c8cdddfd5e03bfc":{"status":"REVOKED","expires":"2020-11-13","reason":"KEY_COMPROMISE"}}}`)
	srv, hits := statusServer(t, &code, &body)
	clock := now
	l := &StatusList{URL: srv.URL, Client: srv.Client(), TTL: time.Hour, Now: func() time.Time { return clock }}

	for range 3 {
		got, err := l.Load(context.Background())
		if err != nil || got["2c8cdddfd5e03bfc"] != "REVOKED" {
			t.Fatalf("Load = %v, %v", got, err)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("%d fetches within the TTL, want 1", hits.Load())
	}

	clock = clock.Add(time.Hour)
	code.Store(http.StatusServiceUnavailable)
	if got, err := l.Load(context.Background()); err == nil {
		t.Fatalf("Load after the TTL with the list down = %v, want an error", got)
	}
	code.Store(http.StatusOK)
	body.Store(`{"entries":{}}`)
	if got, err := l.Load(context.Background()); err != nil || len(got) != 0 {
		t.Fatalf("Load once the list is back = %v, %v, want the new, empty list", got, err)
	}
	if hits.Load() != 3 {
		t.Fatalf("%d fetches, want 3", hits.Load())
	}
}

func TestStatusListRejectsBrokenLists(t *testing.T) {
	for name, b := range map[string]string{
		"not JSON":   `<html>`,
		"no entries": `{"revoked":{}}`,
	} {
		t.Run(name, func(t *testing.T) {
			var code atomic.Int32
			var body atomic.Value
			code.Store(http.StatusOK)
			body.Store(b)
			srv, _ := statusServer(t, &code, &body)
			l := &StatusList{URL: srv.URL, Client: srv.Client(), TTL: time.Hour, Now: time.Now}
			if got, err := l.Load(context.Background()); err == nil {
				t.Fatalf("Load = %v, want an error", got)
			}
		})
	}
}
