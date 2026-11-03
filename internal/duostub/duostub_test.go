package duostub

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/frict-auth/frict-server/internal/duosig"
)

const (
	ikey = "DITESTIKEY"
	skey = "test-skey"
	host = "duo.frict.test"
)

const deniedUserID = "DUDENIED"

func newStub(delay time.Duration) *Server {
	v := duosig.Verifier{IKey: ikey, SKey: skey, Host: host, MaxSkew: 5 * time.Minute, Now: time.Now}
	return New(v, delay, []string{deniedUserID}, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

type reply struct {
	code int
	Stat string          `json:"stat"`
	Resp json.RawMessage `json:"response"`
	Msg  string          `json:"message"`
}

func post(ctx context.Context, h http.Handler, path string, params map[string]string, secret string) (reply, error) {
	body, err := json.Marshal(params)
	if err != nil {
		return reply{}, err
	}
	r := httptest.NewRequestWithContext(ctx, "POST", path, strings.NewReader(string(body)))
	r.Header.Set("Date", time.Now().UTC().Format(time.RFC1123Z))
	r.Header.Set("Content-Type", "application/json")
	if secret != "" {
		if err := duosig.Sign(r, body, ikey, secret, host); err != nil {
			return reply{}, err
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	rep := reply{code: w.Code}
	if w.Body.Len() > 0 {
		if err := json.Unmarshal(w.Body.Bytes(), &rep); err != nil {
			return rep, fmt.Errorf("%s: non-JSON reply %q", path, w.Body.String())
		}
	}
	return rep, nil
}

func call(t *testing.T, ctx context.Context, h http.Handler, path string, params map[string]string, secret string) reply {
	t.Helper()
	rep, err := post(ctx, h, path, params, secret)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func enroll(t *testing.T, h http.Handler, username string) (userID, code string) {
	t.Helper()
	rep := call(t, context.Background(), h, "/auth/v2/enroll", map[string]string{"username": username}, skey)
	if rep.code != 200 || rep.Stat != "OK" {
		t.Fatalf("enroll: %d %+v", rep.code, rep)
	}
	var e struct {
		UserID         string `json:"user_id"`
		ActivationCode string `json:"activation_code"`
		Barcode        string `json:"activation_barcode"`
		Username       string `json:"username"`
	}
	if err := json.Unmarshal(rep.Resp, &e); err != nil {
		t.Fatal(err)
	}
	if e.UserID == "" || e.ActivationCode == "" || e.Barcode == "" || e.Username != username {
		t.Fatalf("enroll response incomplete: %+v", e)
	}
	return e.UserID, e.ActivationCode
}

func enrollStatus(t *testing.T, h http.Handler, userID, code string) string {
	t.Helper()
	rep := call(t, context.Background(), h, "/auth/v2/enroll_status",
		map[string]string{"user_id": userID, "activation_code": code}, skey)
	var s string
	if err := json.Unmarshal(rep.Resp, &s); err != nil {
		t.Fatalf("enroll_status: %d %+v", rep.code, rep)
	}
	return s
}

func TestEnrollThenStatusSuccess(t *testing.T) {
	h := newStub(0).Handler()
	uid, code := enroll(t, h, "alice")
	if got := enrollStatus(t, h, uid, code); got != "success" {
		t.Fatalf("enroll_status = %q, want success", got)
	}
}

func TestEnrollStatusInvalidForUnknownPair(t *testing.T) {
	h := newStub(0).Handler()
	uid, code := enroll(t, h, "alice")
	for _, tc := range []struct{ uid, code string }{{uid, code + "x"}, {uid + "x", code}, {"", ""}} {
		if got := enrollStatus(t, h, tc.uid, tc.code); got != "invalid" {
			t.Errorf("enroll_status(%q,%q) = %q, want invalid", tc.uid, tc.code, got)
		}
	}
}

func TestConcurrentEnrollments(t *testing.T) {
	s := newStub(0)
	h := s.Handler()
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			rep, err := post(context.Background(), h, "/auth/v2/enroll", map[string]string{"username": "u"}, skey)
			if err != nil || rep.code != 200 {
				t.Errorf("enroll: %d %v", rep.code, err)
			}
		})
	}
	wg.Wait()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.enrollments) != 16 {
		t.Fatalf("%d enrollments, want 16", len(s.enrollments))
	}
}

func TestAuthBlocksForDelayThenApproves(t *testing.T) {
	const delay = 300 * time.Millisecond
	h := newStub(delay).Handler()
	start := time.Now()
	rep := call(t, context.Background(), h, "/auth/v2/auth",
		map[string]string{"factor": "auto", "async": "0", "user_id": "DU1", "device": "auto"}, skey)
	elapsed := time.Since(start)
	if elapsed < delay {
		t.Fatalf("returned after %s, want >= %s", elapsed, delay)
	}
	var res struct{ Result, Status string }
	if err := json.Unmarshal(rep.Resp, &res); err != nil || rep.code != 200 || res.Result != "allow" {
		t.Fatalf("auth: %d %+v %v", rep.code, rep, err)
	}
}

func TestAuthDeniesListedUserAfterDelay(t *testing.T) {
	const delay = 300 * time.Millisecond
	h := newStub(delay).Handler()
	start := time.Now()
	rep := call(t, context.Background(), h, "/auth/v2/auth",
		map[string]string{"factor": "auto", "async": "0", "user_id": deniedUserID, "device": "auto"}, skey)
	elapsed := time.Since(start)
	if elapsed < delay {
		t.Fatalf("returned after %s, want >= %s", elapsed, delay)
	}
	var res struct{ Result, Status string }
	if err := json.Unmarshal(rep.Resp, &res); err != nil || rep.code != 200 || res.Result != "deny" || res.Status != "deny" {
		t.Fatalf("auth: %d %+v %v", rep.code, rep, err)
	}
}

func TestAuthStopsWhenCallerGivesUp(t *testing.T) {
	h := newStub(time.Hour).Handler()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	call(t, ctx, h, "/auth/v2/auth", map[string]string{"factor": "auto", "async": "0", "user_id": "DU1"}, skey)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("handler kept blocking %s after caller left", elapsed)
	}
}

func TestAsyncAuthRejected(t *testing.T) {
	h := newStub(0).Handler()
	rep := call(t, context.Background(), h, "/auth/v2/auth", map[string]string{"factor": "auto", "async": "1"}, skey)
	if rep.code != 400 {
		t.Fatalf("async auth: %d, want 400", rep.code)
	}
}

func TestBadSignatureRejectedBeforeAnyWork(t *testing.T) {
	const delay = time.Hour
	s := newStub(delay)
	h := s.Handler()
	for _, path := range []string{"/auth/v2/enroll", "/auth/v2/enroll_status", "/auth/v2/auth"} {
		for name, secret := range map[string]string{"wrong secret": "not-the-secret", "unsigned": ""} {
			t.Run(path+"/"+name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				rep := call(t, ctx, h, path,
					map[string]string{"factor": "auto", "async": "0", "username": "mallory"}, secret)
				if rep.code != 401 || rep.Stat != "FAIL" {
					t.Fatalf("got %d %+v, want 401 FAIL", rep.code, rep)
				}
			})
		}
	}
	if len(s.enrollments) != 0 {
		t.Fatalf("rejected enroll still created %d enrollments", len(s.enrollments))
	}
}

func TestUnknownPathIs404(t *testing.T) {
	h := newStub(0).Handler()
	for _, path := range []string{"/auth/v2/ping", "/auth/v2/preauth", "/admin/v1/users"} {
		if rep := call(t, context.Background(), h, path, map[string]string{}, skey); rep.code != 404 {
			t.Errorf("%s: %d, want 404", path, rep.code)
		}
	}
}
