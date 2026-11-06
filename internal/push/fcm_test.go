package push

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// tokens is a TokenSource that hands out the next of its tokens on each
// call, or err.
type tokens struct {
	list []string
	err  error
}

func (s *tokens) Token(context.Context) (string, error) {
	if s.err != nil {
		return "", s.err
	}
	t := s.list[0]
	s.list = s.list[1:]
	return t, nil
}

// testFCM returns an FCM sender whose endpoint is served by h.
func testFCM(t *testing.T, ts TokenSource, h http.HandlerFunc) *FCM {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return NewFCM(srv.URL, "frict-test", ts, &http.Client{Timeout: 5 * time.Second})
}

func TestFCMSendsDataMessage(t *testing.T) {
	var gotMethod, gotPath string
	var gotAuth []string
	var gotBody map[string]any
	f := testFCM(t, &tokens{list: []string{"tok-1", "tok-2"}}, func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		gotAuth = append(gotAuth, r.Header.Get("Authorization"))
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode FCM request: %v", err)
		}
		io.WriteString(w, `{"name":"projects/frict-test/messages/1"}`)
	})

	for range 2 {
		name, err := f.Send(context.Background(), Message{FID: "the-fid", Data: map[string]string{"challenge_id": "AAAA"}})
		if err != nil || name != "projects/frict-test/messages/1" {
			t.Fatalf("Send = %q, %v; want FCM's message name", name, err)
		}
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/projects/frict-test/messages:send" {
		t.Fatalf("request = %s %s, want POST /v1/projects/frict-test/messages:send", gotMethod, gotPath)
	}
	if strings.Join(gotAuth, ",") != "Bearer tok-1,Bearer tok-2" {
		t.Fatalf("Authorization headers %q, want the token source's token for each send", gotAuth)
	}
	var want map[string]any
	json.Unmarshal([]byte(`{"message":{"fid":"the-fid","data":{"challenge_id":"AAAA"},"android":{"priority":"high"}}}`), &want)
	if g, w := mustJSON(t, gotBody), mustJSON(t, want); g != w {
		t.Fatalf("body = %s\nwant   %s", g, w)
	}
}

func TestFCMTokenFailureSendsNothing(t *testing.T) {
	called := false
	f := testFCM(t, &tokens{err: errors.New("token endpoint down")}, func(http.ResponseWriter, *http.Request) { called = true })
	_, err := f.Send(context.Background(), Message{FID: "the-fid", Data: map[string]string{"challenge_id": "AAAA"}})
	if err == nil || !strings.Contains(err.Error(), "fcm token: token endpoint down") {
		t.Fatalf("Send = %v, want the token error", err)
	}
	if called {
		t.Fatal("Send reached FCM without a token")
	}
}

func TestFCMErrorMapping(t *testing.T) {
	cases := []struct {
		name         string
		status       int
		body         string
		unregistered bool
		wantCode     string
	}{
		{"unregistered", 404, fcmError("NOT_FOUND", "UNREGISTERED"), true, "UNREGISTERED"},
		{"invalid argument", 400, fcmError("INVALID_ARGUMENT", "INVALID_ARGUMENT"), true, "INVALID_ARGUMENT"},
		{"not found without errorCode", 404, `{"error":{"code":404,"status":"NOT_FOUND"}}`, false, "NOT_FOUND"},
		{"sender mismatch", 403, fcmError("PERMISSION_DENIED", "SENDER_ID_MISMATCH"), false, "SENDER_ID_MISMATCH"},
		{"auth", 401, fcmError("UNAUTHENTICATED", "THIRD_PARTY_AUTH_ERROR"), false, "THIRD_PARTY_AUTH_ERROR"},
		{"quota", 429, fcmError("RESOURCE_EXHAUSTED", "QUOTA_EXCEEDED"), false, "QUOTA_EXCEEDED"},
		{"unavailable", 503, `<html>upstream down</html>`, false, "unparseable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := testFCM(t, &tokens{list: []string{"tok"}}, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			})
			_, err := f.Send(context.Background(), Message{FID: "secret-fid", Data: map[string]string{"alert_id": "secret-id"}})
			if err == nil {
				t.Fatal("Send succeeded, want an error")
			}
			if got := errors.Is(err, ErrUnregistered); got != tc.unregistered {
				t.Fatalf("errors.Is(%v, ErrUnregistered) = %v, want %v", err, got, tc.unregistered)
			}
			if msg := err.Error(); strings.Contains(msg, "secret") || !strings.Contains(msg, tc.wantCode) {
				t.Fatalf("error %q: want FCM's code %s and neither the FID nor the data", msg, tc.wantCode)
			}
		})
	}
}

func TestFCMBrokenSuccessBodyStillSucceeds(t *testing.T) {
	f := testFCM(t, &tokens{list: []string{"tok"}}, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "100")
		io.WriteString(w, `{"na`)
	})
	if _, err := f.Send(context.Background(), Message{FID: "the-fid", Data: map[string]string{"challenge_id": "AAAA"}}); err != nil {
		t.Fatalf("Send after FCM accepted = %v, want nil", err)
	}
}

func fcmError(status, errorCode string) string {
	return `{"error":{"code":0,"message":"echoes secret-fid","status":"` + status + `","details":[` +
		`{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":"` + errorCode + `"}]}}`
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}
