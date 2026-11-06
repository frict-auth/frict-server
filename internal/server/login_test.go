package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/frict-auth/frict-server/internal/duosig"
	"github.com/frict-auth/frict-server/internal/fakephone"
)

// enrolledPhone enrolls a new phone for username and returns its account.
func (f *fixture) enrolledPhone(username string) (fakephone.Activation, *fakephone.Phone) {
	f.t.Helper()
	a := f.enroll(username)
	phone := newPhone(f.t)
	if w := f.serve(must[*http.Request](f.t)(phone.EnrollRequest(a, f.now()))); w.Code != http.StatusOK {
		f.t.Fatalf("enroll %s: %d %s", username, w.Code, w.Body)
	}
	return a, phone
}

// authParams is what Authentik 2026.8.5 sends to /auth/v2/auth
// (authenticator_validate/challenge.py:276-290, duo_client auth.py:142-163).
func authParams(userID string) string {
	b, _ := json.Marshal(map[string]string{
		"factor":           "auto",
		"async":            "0",
		"user_id":          userID,
		"ipaddr":           "203.0.113.7",
		"type":             "authentik Login request",
		"display_username": "élodie",
		"device":           "auto",
		"pushinfo":         "Domain=auth.example&Application=Grafana",
	})
	return string(b)
}

// startAuth calls /auth/v2/auth for userID in the background, as Authentik
// does, until ctx or the test ends. The recorder arrives once the handler
// returns. Cleanup ends the call and waits for the handler, so a failed test
// leaves no /auth behind.
func (f *fixture) startAuth(ctx context.Context, userID string) <-chan *httptest.ResponseRecorder {
	f.t.Helper()
	ctx, cancel := context.WithCancel(ctx)
	body := authParams(userID)
	r := httptest.NewRequestWithContext(ctx, http.MethodPost, "https://"+host+"/auth/v2/auth", strings.NewReader(body))
	r.Header.Set("Date", f.now().Format(time.RFC1123Z))
	r.Header.Set("Content-Type", "application/json")
	if err := duosig.Sign(r, []byte(body), clientID, secret, host); err != nil {
		f.t.Fatal(err)
	}
	done := make(chan *httptest.ResponseRecorder, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		done <- f.serve(r)
	}()
	f.t.Cleanup(func() {
		cancel()
		<-finished
	})
	return done
}

// authResult waits for a startAuth call and decodes its Duo response.
func (f *fixture) authResult(done <-chan *httptest.ResponseRecorder) map[string]string {
	f.t.Helper()
	select {
	case w := <-done:
		var resp struct {
			Stat     string
			Response map[string]string
		}
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &resp) != nil || resp.Stat != "OK" {
			f.t.Fatalf("/auth: %d %s", w.Code, w.Body)
		}
		return resp.Response
	case <-time.After(10 * time.Second):
		f.t.Fatal("/auth did not return within 10s")
		return nil
	}
}

// pending polls as the phone until a has exactly n pending challenges.
func (f *fixture) pending(a fakephone.Activation, phone *fakephone.Phone, n int) []string {
	f.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		w := f.serve(must[*http.Request](f.t)(phone.PendingRequest(a, f.now())))
		var p fakephone.Pending
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &p) != nil {
			f.t.Fatalf("pending: %d %s", w.Code, w.Body)
		}
		if p.PollInterval != PollInterval {
			f.t.Fatalf("poll_interval %d, want %d", p.PollInterval, PollInterval)
		}
		if len(p.ChallengeIDs) == n {
			return p.ChallengeIDs
		}
		if time.Now().After(deadline) {
			f.t.Fatalf("pending = %v, want %d challenges", p.ChallengeIDs, n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (f *fixture) answer(a fakephone.Activation, phone *fakephone.Phone, id, decision, reason string) *httptest.ResponseRecorder {
	f.t.Helper()
	return f.serve(must[*http.Request](f.t)(phone.AnswerRequest(a, id, decision, reason, f.now())))
}

func wantStatus(t *testing.T, what string, w *httptest.ResponseRecorder, status int, body string) {
	t.Helper()
	if w.Code != status || strings.TrimSpace(w.Body.String()) != body {
		t.Fatalf("%s: %d %s, want %d %s", what, w.Code, strings.TrimSpace(w.Body.String()), status, body)
	}
}

func wantResult(t *testing.T, got map[string]string, result, status string) {
	t.Helper()
	if got["result"] != result || got["status"] != status || got["status_msg"] == "" {
		t.Fatalf("/auth response %v, want result %q status %q and a status_msg", got, result, status)
	}
}

func TestAuthReturnsDevicesAnswer(t *testing.T) {
	tests := []struct {
		decision, reason string
		result, status   string
	}{
		{"approve", "", "allow", "allow"},
		{"deny", "cancel", "deny", "deny"},
		{"deny", "not_me", "deny", "fraud"},
	}
	for _, tc := range tests {
		t.Run(tc.decision+" "+tc.reason, func(t *testing.T) {
			f := newFixture(t)
			a, phone := f.enrolledPhone("alice")
			done := f.startAuth(context.Background(), a.UserID)
			id := f.pending(a, phone, 1)[0]
			wantStatus(t, "answer", f.answer(a, phone, id, tc.decision, tc.reason), http.StatusOK, "{}")
			wantResult(t, f.authResult(done), tc.result, tc.status)
			f.pending(a, phone, 0)
		})
	}
}

func TestChallengeDetailsPassThroughAuthentiksFields(t *testing.T) {
	f := newFixture(t)
	a, phone := f.enrolledPhone("alice")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.startAuth(ctx, a.UserID)
	id := f.pending(a, phone, 1)[0]

	w := f.serve(must[*http.Request](t)(phone.ChallengeRequest(a, id, f.now())))
	if w.Code != http.StatusOK {
		t.Fatalf("challenge: %d %s", w.Code, w.Body)
	}
	var got fakephone.Challenge
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	want := fakephone.Challenge{ChallengeID: id, Username: "élodie", IPAddr: "203.0.113.7",
		PushInfo: "Domain=auth.example&Application=Grafana", Type: "authentik Login request",
		Created: t0.Unix(), Expires: t0.Add(time.Minute).Unix()}
	if got != want {
		t.Fatalf("challenge details %+v, want %+v", got, want)
	}
	if len(id) != 22 {
		t.Fatalf("challenge_id %q is not 22 base64url characters", id)
	}
}

func TestAnswerSignedWithDeviceKeyRejected(t *testing.T) {
	f := newFixture(t)
	a, phone := f.enrolledPhone("alice")
	done := f.startAuth(context.Background(), a.UserID)
	id := f.pending(a, phone, 1)[0]

	body := must[[]byte](t)(fakephone.AnswerBody(id, "approve", ""))
	byDeviceKey := must[*http.Request](t)(fakephone.SignedRequest("https://"+host, fakephone.AnswerPath, a.UserID, f.now().Unix(), body, phone.DeviceKey))
	wantStatus(t, "answer signed with device_key", f.serve(byDeviceKey), http.StatusUnauthorized, `{"error":"unauthorized"}`)
	byOtherPhone := must[*http.Request](t)(fakephone.SignedRequest("https://"+host, fakephone.AnswerPath, a.UserID, f.now().Unix(), body, newPhone(t).ApprovalKey))
	wantStatus(t, "answer signed by another phone", f.serve(byOtherPhone), http.StatusUnauthorized, `{"error":"unauthorized"}`)

	f.pending(a, phone, 1)
	wantStatus(t, "answer signed with approval_key", f.answer(a, phone, id, "deny", "cancel"), http.StatusOK, "{}")
	wantResult(t, f.authResult(done), "deny", "deny")
}

func TestSecondAnswerRejected(t *testing.T) {
	f := newFixture(t)
	a, phone := f.enrolledPhone("alice")
	done := f.startAuth(context.Background(), a.UserID)
	id := f.pending(a, phone, 1)[0]

	body := must[[]byte](t)(fakephone.AnswerBody(id, "approve", ""))
	approve := must[*http.Request](t)(fakephone.SignedRequest("https://"+host, fakephone.AnswerPath, a.UserID, f.now().Unix(), body, phone.ApprovalKey))
	replay := httptest.NewRequest(http.MethodPost, approve.URL.String(), bytes.NewReader(body))
	replay.Header = approve.Header.Clone()

	wantStatus(t, "first answer", f.serve(approve), http.StatusOK, "{}")
	wantStatus(t, "replayed answer", f.serve(replay), http.StatusConflict, `{"error":"not_pending"}`)
	wantStatus(t, "different second answer", f.answer(a, phone, id, "deny", "not_me"), http.StatusConflict, `{"error":"not_pending"}`)
	wantResult(t, f.authResult(done), "allow", "allow")
}

func TestAnswerAfterExpiryRejected(t *testing.T) {
	f := newFixture(t)
	a, phone := f.enrolledPhone("alice")
	ctx, cancel := context.WithCancel(context.Background())
	done := f.startAuth(ctx, a.UserID)
	id := f.pending(a, phone, 1)[0]

	f.setClock(t0.Add(time.Minute))
	wantStatus(t, "answer at expiry", f.answer(a, phone, id, "approve", ""), http.StatusConflict, `{"error":"not_pending"}`)
	select {
	case w := <-done:
		t.Fatalf("/auth returned after a rejected answer: %d %s", w.Code, w.Body)
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	<-done
}

func TestAnswerValidatesDecisionAndReason(t *testing.T) {
	f := newFixture(t)
	a, phone := f.enrolledPhone("alice")
	done := f.startAuth(context.Background(), a.UserID)
	id := f.pending(a, phone, 1)[0]

	for _, body := range []string{
		`{"challenge_id":"` + id + `","decision":"deny"}`,
		`{"challenge_id":"` + id + `","decision":"deny","reason":""}`,
		`{"challenge_id":"` + id + `","decision":"deny","reason":"bored"}`,
		`{"challenge_id":"` + id + `","decision":"approve","reason":"cancel"}`,
		`{"challenge_id":"` + id + `","decision":"maybe"}`,
		`{"challenge_id":"` + id + `"}`,
		`{"challenge_id":"` + id + `","decision":"approve","extra":1}`,
		`{"challenge_id":"short","decision":"approve"}`,
		`not json`,
	} {
		r := must[*http.Request](t)(fakephone.SignedRequest("https://"+host, fakephone.AnswerPath, a.UserID, f.now().Unix(), []byte(body), phone.ApprovalKey))
		wantStatus(t, body, f.serve(r), http.StatusBadRequest, `{"error":"bad_request"}`)
	}
	f.pending(a, phone, 1)
	wantStatus(t, "valid deny", f.answer(a, phone, id, "deny", "not_me"), http.StatusOK, "{}")
	wantResult(t, f.authResult(done), "deny", "fraud")
}

func TestOtherUsersChallengeRejected(t *testing.T) {
	f := newFixture(t)
	alice, alicePhone := f.enrolledPhone("alice")
	bob, bobPhone := f.enrolledPhone("bob")
	done := f.startAuth(context.Background(), alice.UserID)
	id := f.pending(alice, alicePhone, 1)[0]

	f.pending(bob, bobPhone, 0)
	wantStatus(t, "bob fetches alice's challenge", f.serve(must[*http.Request](t)(bobPhone.ChallengeRequest(bob, id, f.now()))), http.StatusNotFound, `{"error":"not_found"}`)
	wantStatus(t, "bob answers alice's challenge", f.answer(bob, bobPhone, id, "approve", ""), http.StatusNotFound, `{"error":"not_found"}`)

	f.pending(alice, alicePhone, 1)
	wantStatus(t, "alice answers", f.answer(alice, alicePhone, id, "deny", "cancel"), http.StatusOK, "{}")
	wantResult(t, f.authResult(done), "deny", "deny")
}

// serverGoroutines returns the stacks of goroutines running Server methods.
func serverGoroutines() []string {
	buf := make([]byte, 1<<20)
	buf = buf[:runtime.Stack(buf, true)]
	var out []string
	for _, g := range strings.Split(string(buf), "\n\n") {
		if strings.Contains(g, "internal/server.(*Server)") {
			out = append(out, g)
		}
	}
	return out
}

func TestAuthTimesOutWithoutLeaking(t *testing.T) {
	f := newFixtureTTL(t, time.Second)
	a, phone := f.enrolledPhone("alice")
	start := time.Now()
	done := f.startAuth(context.Background(), a.UserID)
	id := f.pending(a, phone, 1)[0]

	wantResult(t, f.authResult(done), "deny", "timeout")
	if elapsed := time.Since(start); elapsed < time.Second {
		t.Fatalf("/auth timed out after %s, before the 1s challenge TTL", elapsed)
	}
	f.pending(a, phone, 0)
	wantStatus(t, "answer after timeout", f.answer(a, phone, id, "approve", ""), http.StatusConflict, `{"error":"not_pending"}`)

	deadline := time.Now().Add(time.Second)
	for g := serverGoroutines(); len(g) > 0; g = serverGoroutines() {
		if time.Now().After(deadline) {
			t.Fatalf("goroutines still in Server after /auth returned:\n%s", strings.Join(g, "\n\n"))
		}
		time.Sleep(10 * time.Millisecond)
	}
	f.srv.mu.Lock()
	defer f.srv.mu.Unlock()
	if len(f.srv.answered) != 0 {
		t.Fatalf("%d answer waiters left after /auth returned", len(f.srv.answered))
	}
}

func TestAuthEndsWhenCallerGoes(t *testing.T) {
	f := newFixture(t)
	a, phone := f.enrolledPhone("alice")
	ctx, cancel := context.WithCancel(context.Background())
	done := f.startAuth(ctx, a.UserID)
	id := f.pending(a, phone, 1)[0]

	cancel()
	select {
	case w := <-done:
		if w.Body.Len() != 0 {
			t.Fatalf("/auth wrote %q to a caller that left", w.Body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("/auth still blocked 5s after its caller left")
	}
	f.pending(a, phone, 0)
	wantStatus(t, "answer after the caller left", f.answer(a, phone, id, "approve", ""), http.StatusConflict, `{"error":"not_pending"}`)
}

func TestAuthRejectsBadParams(t *testing.T) {
	f := newFixture(t)
	a, _ := f.enrolledPhone("alice")
	withParam := func(k, v string) string {
		m := map[string]string{}
		json.Unmarshal([]byte(authParams(a.UserID)), &m)
		m[k] = v
		return string(must[[]byte](t)(json.Marshal(m)))
	}
	for name, body := range map[string]string{
		"async":           withParam("async", "1"),
		"passcode factor": withParam("factor", "passcode"),
		"unknown user":    withParam("user_id", "DUCCCCCCCCCCCCCCCCCCCCCCCCCC"),
		"user not yet enrolled": func() string {
			return withParam("user_id", f.enroll("bob").UserID)
		}(),
		"not json": "nope",
	} {
		w := f.duo("/auth/v2/auth", body, secret)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `"stat":"FAIL"`) {
			t.Errorf("%s: %d %s, want 400 FAIL", name, w.Code, w.Body)
		}
	}
}

func TestDeviceRequestsNeedTheDevicesSignature(t *testing.T) {
	f := newFixture(t)
	a, phone := f.enrolledPhone("alice")
	unenrolled := f.enroll("bob")
	other := newPhone(t)
	id := encodeID(make([]byte, 16))
	challengeBody := []byte(`{"challenge_id":"` + id + `"}`)
	tests := map[string]*http.Request{
		"pending by another key":        must[*http.Request](t)(fakephone.SignedRequest("https://"+host, fakephone.PendingPath, a.UserID, f.now().Unix(), []byte("{}"), other.DeviceKey)),
		"pending by the approval_key":   must[*http.Request](t)(fakephone.SignedRequest("https://"+host, fakephone.PendingPath, a.UserID, f.now().Unix(), []byte("{}"), phone.ApprovalKey)),
		"pending stale":                 must[*http.Request](t)(phone.PendingRequest(a, f.now().Add(-6*time.Minute))),
		"pending for unenrolled user":   must[*http.Request](t)(other.PendingRequest(unenrolled, f.now())),
		"challenge by another key":      must[*http.Request](t)(fakephone.SignedRequest("https://"+host, fakephone.ChallengePath, a.UserID, f.now().Unix(), challengeBody, other.DeviceKey)),
		"challenge signed for pending":  signedForPath(t, phone, a, fakephone.ChallengePath, fakephone.PendingPath, challengeBody, f.now()),
		"answer signed for challenge":   signedForPath(t, phone, a, fakephone.AnswerPath, fakephone.ChallengePath, []byte(`{"challenge_id":"`+id+`","decision":"approve"}`), f.now()),
		"challenge for unenrolled user": must[*http.Request](t)(other.ChallengeRequest(unenrolled, id, f.now())),
	}
	for name, r := range tests {
		wantStatus(t, name, f.serve(r), http.StatusUnauthorized, `{"error":"unauthorized"}`)
	}
}

// signedForPath sends to path a request whose signature covers signedPath.
func signedForPath(t *testing.T, phone *fakephone.Phone, a fakephone.Activation, path, signedPath string, body []byte, now time.Time) *http.Request {
	t.Helper()
	key := phone.DeviceKey
	if signedPath == fakephone.AnswerPath {
		key = phone.ApprovalKey
	}
	r := must[*http.Request](t)(fakephone.SignedRequest("https://"+host, signedPath, a.UserID, now.Unix(), body, key))
	r.URL.Path = path
	return r
}

func TestDeviceRequestsRejectMalformedBodies(t *testing.T) {
	f := newFixture(t)
	a, phone := f.enrolledPhone("alice")
	for name, tc := range map[string]struct{ path, body string }{
		"pending with a field":    {fakephone.PendingPath, `{"user_id":"x"}`},
		"pending not json":        {fakephone.PendingPath, `nope`},
		"challenge id too short":  {fakephone.ChallengePath, `{"challenge_id":"AAAA"}`},
		"challenge id not base64": {fakephone.ChallengePath, `{"challenge_id":"++++++++++++++++++++++"}`},
		"challenge extra field":   {fakephone.ChallengePath, `{"challenge_id":"AAAAAAAAAAAAAAAAAAAAAA","x":1}`},
	} {
		r := must[*http.Request](t)(fakephone.SignedRequest("https://"+host, tc.path, a.UserID, f.now().Unix(), []byte(tc.body), phone.DeviceKey))
		wantStatus(t, name, f.serve(r), http.StatusBadRequest, `{"error":"bad_request"}`)
	}
	unknown := encodeID(make([]byte, 16))
	wantStatus(t, "unknown challenge", f.serve(must[*http.Request](t)(phone.ChallengeRequest(a, unknown, f.now()))), http.StatusNotFound, `{"error":"not_found"}`)
	wantStatus(t, "answer unknown challenge", f.answer(a, phone, unknown, "approve", ""), http.StatusNotFound, `{"error":"not_found"}`)
}

// TestDeviceEnrollConcurrentSameCode: phones racing to enroll with one
// activation code get exactly one 200; the rest get 401.
func TestDeviceEnrollConcurrentSameCode(t *testing.T) {
	f := newFixture(t)
	a := f.enroll("alice")
	const racers = 8
	reqs := make([]*http.Request, racers)
	for i := range reqs {
		reqs[i] = must[*http.Request](t)(newPhone(t).EnrollRequest(a, f.now()))
	}
	codes := make(chan int, racers)
	start := make(chan struct{})
	for _, r := range reqs {
		go func() {
			<-start
			codes <- f.serve(r).Code
		}()
	}
	close(start)
	count := map[int]int{}
	for range racers {
		count[<-codes]++
	}
	if count[http.StatusOK] != 1 || count[http.StatusUnauthorized] != racers-1 {
		t.Fatalf("status counts %v, want one 200 and %d 401", count, racers-1)
	}
}
