package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/frict-auth/frict-server/internal/fakephone"
	"github.com/frict-auth/frict-server/internal/push"
)

// syncBuffer is a log destination that pushes in the background can write
// to while a test reads it.
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

// newPushFixture is a fixture that sends its pushes to sender and logs to
// the returned buffer.
func newPushFixture(t *testing.T, sg Safeguards, sender push.Sender) (*fixture, *syncBuffer) {
	t.Helper()
	logs := &syncBuffer{}
	return newFixtureSender(t, time.Minute, sg, sender, slog.New(slog.NewTextHandler(logs, nil))), logs
}

// nextPush waits for the fake's next message.
func nextPush(t *testing.T, fake *push.Fake) push.Message {
	t.Helper()
	select {
	case m := <-fake.Sent():
		return m
	case <-time.After(5 * time.Second):
		t.Fatal("no push within 5s")
		return push.Message{}
	}
}

// settledPushes waits for every push in flight and returns the messages
// sent since the last read.
func (f *fixture) settledPushes(fake *push.Fake) []push.Message {
	f.srv.Close()
	var out []push.Message
	for {
		select {
		case m := <-fake.Sent():
			out = append(out, m)
		default:
			return out
		}
	}
}

func (f *fixture) fid(userID string) string {
	f.t.Helper()
	d, err := f.st.DeviceOf(context.Background(), userID)
	if err != nil {
		f.t.Fatal(err)
	}
	return d.FID
}

func TestChallengeCreationPushesDevice(t *testing.T) {
	fake := push.NewFake()
	f, logs := newPushFixture(t, testSafeguards, fake)
	a, phone := f.enrolledPhone("alice")
	f.enrolledPhone("bob")

	done := f.startAuth(context.Background(), a.UserID)
	m := nextPush(t, fake)
	id := f.pending(a, phone, 1)[0]
	if m.FID != phone.FID || m.Data["challenge_id"] != id {
		t.Fatalf("push %+v, want challenge %s to alice's FID %s", m, id, phone.FID)
	}
	wantStatus(t, "answer", f.answer(a, phone, id, "approve", ""), http.StatusOK, "{}")
	wantResult(t, f.authResult(done), "allow", "allow")
	if extra := f.settledPushes(fake); len(extra) != 0 {
		t.Fatalf("pushes after the first: %+v, want none", extra)
	}
	if !strings.Contains(logs.String(), "fcm_message=projects/fake/messages/1") {
		t.Fatalf("success not logged with FCM's message name; logs:\n%s", logs)
	}
}

func TestRefusedAuthSendsNoPush(t *testing.T) {
	fake := push.NewFake()
	f, _ := newPushFixture(t, safeguards(func(sg *Safeguards) { sg.PushCap, sg.PushCooldown = 1, time.Hour }), fake)
	a, phone := f.enrolledPhone("alice")
	f.wantPushed(a, phone)
	nextPush(t, fake)
	f.wantRefused(a, "Too many pushes")
	if got := f.settledPushes(fake); len(got) != 0 {
		t.Fatalf("refused /auth pushed %+v", got)
	}
}

// TestPushPayloadHasNoChallengeDetails: a push carries one opaque ID and
// nothing Authentik sent, for challenges and alerts alike.
func TestPushPayloadHasNoChallengeDetails(t *testing.T) {
	fake := push.NewFake()
	f, _ := newPushFixture(t, testSafeguards, fake)
	admin, adminPhone := f.enrolledPhone("admin")
	a, phone := f.enrolledPhone("alice")
	f.push(a, phone, "deny", "not_me", "fraud")
	got := f.settledPushes(fake)
	if len(got) != 2 {
		t.Fatalf("pushes %+v, want alice's challenge and admin's alert", got)
	}
	if got[0].FID != phone.FID {
		got[0], got[1] = got[1], got[0]
	}
	alertID := f.alerts(admin, adminPhone)[0].AlertID
	for i, want := range []struct{ fid, key string }{{phone.FID, "challenge_id"}, {adminPhone.FID, "alert_id"}} {
		m := got[i]
		if m.FID != want.fid || len(m.Data) != 1 || m.Data[want.key] == "" {
			t.Fatalf("push %d = %+v, want only %s to %s", i, m, want.key, want.fid)
		}
		if _, ok := decodeID(m.Data[want.key]); !ok {
			t.Fatalf("push %d %s %q is not a 16-byte ID", i, want.key, m.Data[want.key])
		}
		for _, detail := range []string{"élodie", "203.0.113.7", "Grafana", "auth.example", "Login request", a.UserID, admin.UserID} {
			if strings.Contains(m.Data[want.key], detail) {
				t.Fatalf("push %d carries %q: %+v", i, detail, m)
			}
		}
	}
	if got[1].Data["alert_id"] != alertID {
		t.Fatalf("alert push %+v, want alert_id %s from the poll", got[1], alertID)
	}
}

func TestNotMePushesEachAlertRecipient(t *testing.T) {
	fake := push.NewFake()
	f, _ := newPushFixture(t, safeguards(func(sg *Safeguards) { sg.AlertRecipients = []string{"admin", "sec"} }), fake)
	admin, adminPhone := f.enrolledPhone("admin")
	sec, secPhone := f.enrolledPhone("sec")
	alice, alicePhone := f.enrolledPhone("alice")
	f.enrolledPhone("bob")

	f.push(alice, alicePhone, "deny", "cancel", "deny")
	if got := f.settledPushes(fake); len(got) != 1 || got[0].FID != alicePhone.FID {
		t.Fatalf("pushes after a cancel deny %+v, want only alice's challenge", got)
	}

	f.push(alice, alicePhone, "deny", "not_me", "fraud")
	got := map[string]string{}
	for _, m := range f.settledPushes(fake) {
		if id, ok := m.Data["alert_id"]; ok {
			got[m.FID] = id
		}
	}
	want := map[string]string{
		adminPhone.FID: f.alerts(admin, adminPhone)[0].AlertID,
		secPhone.FID:   f.alerts(sec, secPhone)[0].AlertID,
	}
	if len(got) != len(want) || got[adminPhone.FID] != want[adminPhone.FID] || got[secPhone.FID] != want[secPhone.FID] {
		t.Fatalf("alert pushes by FID %v, want %v (one per recipient, none to alice or bob)", got, want)
	}
}

// TestPushFailureLeavesAuthAndPoll: a push that fails or hangs changes
// nothing about /auth: the device still finds the challenge by polling,
// and its answer still decides the login.
func TestPushFailureLeavesAuthAndPoll(t *testing.T) {
	for _, tc := range []struct {
		name    string
		fake    func() *push.Fake
		wantLog string
	}{
		{"send fails", func() *push.Fake {
			fake := push.NewFake()
			fake.Err = errors.New("fcm send: HTTP 503 UNAVAILABLE")
			return fake
		}, `msg="push failed"`},
		{"send hangs", func() *push.Fake {
			fake := push.NewFake()
			fake.Gate = make(chan struct{})
			return fake
		}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := tc.fake()
			f, logs := newPushFixture(t, testSafeguards, fake)
			if fake.Gate != nil {
				t.Cleanup(func() { close(fake.Gate) })
			}
			a, phone := f.enrolledPhone("alice")
			done := f.startAuth(context.Background(), a.UserID)
			nextPush(t, fake)
			id := f.pending(a, phone, 1)[0]
			wantStatus(t, "answer", f.answer(a, phone, id, "approve", ""), http.StatusOK, "{}")
			wantResult(t, f.authResult(done), "allow", "allow")
			if fake.Gate != nil {
				return
			}
			f.settledPushes(fake)
			if l := logs.String(); !strings.Contains(l, tc.wantLog) || !strings.Contains(l, "503 UNAVAILABLE") {
				t.Fatalf("failure not logged with its FCM error; logs:\n%s", l)
			}
			if f.fid(a.UserID) != phone.FID {
				t.Fatal("a failure other than an unregistered FID cleared the FID")
			}
		})
	}
}

// fcmStub is an FCM endpoint that answers every send with status and body,
// and reports the FID of each.
func fcmStub(t *testing.T, status int, body string) (*push.FCM, <-chan string) {
	t.Helper()
	fids := make(chan string, 16)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Message struct{ FID string } }
		json.NewDecoder(r.Body).Decode(&req)
		fids <- req.Message.FID
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return push.NewFCM(srv.URL, "frict-test", staticToken("tok"), srv.Client()), fids
}

type staticToken string

func (s staticToken) Token(context.Context) (string, error) { return string(s), nil }

// TestUnregisteredFIDCleared: FCM's UNREGISTERED clears the stored FID and
// nothing else. The device stays enrolled, polls and answers, and gets
// pushes again once it sends a new FID.
func TestUnregisteredFIDCleared(t *testing.T) {
	sender, fids := fcmStub(t, http.StatusNotFound,
		`{"error":{"code":404,"status":"NOT_FOUND","details":[{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":"UNREGISTERED"}]}}`)
	f, logs := newPushFixture(t, testSafeguards, sender)
	a, phone := f.enrolledPhone("alice")

	f.push(a, phone, "approve", "", "allow")
	f.srv.Close()
	if got := <-fids; got != phone.FID {
		t.Fatalf("pushed to %q, want %q", got, phone.FID)
	}
	if fid := f.fid(a.UserID); fid != "" {
		t.Fatalf("FID after UNREGISTERED = %q, want it cleared", fid)
	}
	if !strings.Contains(logs.String(), "UNREGISTERED") {
		t.Fatalf("UNREGISTERED not logged; logs:\n%s", logs)
	}

	f.push(a, phone, "approve", "", "allow")
	f.srv.Close()
	select {
	case got := <-fids:
		t.Fatalf("pushed to %q with no FID stored", got)
	default:
	}

	wantStatus(t, "fid update", f.serve(must[*http.Request](t)(phone.FIDRequest(a, "fid-2", f.now()))), http.StatusOK, "{}")
	f.push(a, phone, "approve", "", "allow")
	f.srv.Close()
	if got := <-fids; got != "fid-2" {
		t.Fatalf("pushed to %q after the FID update, want fid-2", got)
	}
}

func TestOtherFCMErrorKeepsFID(t *testing.T) {
	sender, fids := fcmStub(t, http.StatusServiceUnavailable, `{"error":{"code":503,"status":"UNAVAILABLE"}}`)
	f, _ := newPushFixture(t, testSafeguards, sender)
	a, phone := f.enrolledPhone("alice")
	f.push(a, phone, "approve", "", "allow")
	f.srv.Close()
	<-fids
	if fid := f.fid(a.UserID); fid != phone.FID {
		t.Fatalf("FID after a 503 = %q, want %q kept", fid, phone.FID)
	}
}

func TestFIDUpdateRequiresDeviceKeyOfThatUser(t *testing.T) {
	f := newFixture(t)
	a, phone := f.enrolledPhone("alice")
	b, bobPhone := f.enrolledPhone("bob")
	body := []byte(`{"fid":"stolen"}`)
	signed := func(key *fakephone.Phone, approval bool) *http.Request {
		k := key.DeviceKey
		if approval {
			k = key.ApprovalKey
		}
		return must[*http.Request](t)(fakephone.SignedRequest("https://"+host, fakephone.FIDPath, a.UserID, f.now().Unix(), body, k))
	}
	unsigned := signed(phone, false)
	unsigned.Header.Del("Authorization")
	for name, r := range map[string]*http.Request{
		"approval_key":       signed(phone, true),
		"bob's device_key":   signed(bobPhone, false),
		"unsigned":           unsigned,
		"bob signs as alice": must[*http.Request](t)(bobPhone.FIDRequest(fakephone.Activation{Host: host, UserID: a.UserID}, "stolen", f.now())),
	} {
		wantStatus(t, name, f.serve(r), http.StatusUnauthorized, `{"error":"unauthorized"}`)
	}
	if fid := f.fid(a.UserID); fid != phone.FID {
		t.Fatalf("alice's FID after rejected updates = %q, want %q", fid, phone.FID)
	}

	for name, body := range map[string]string{"empty fid": `{"fid":""}`, "unknown field": `{"fid":"x","y":1}`, "not JSON": `fid`} {
		r := must[*http.Request](t)(fakephone.SignedRequest("https://"+host, fakephone.FIDPath, a.UserID, f.now().Unix(), []byte(body), phone.DeviceKey))
		wantStatus(t, name, f.serve(r), http.StatusBadRequest, `{"error":"bad_request"}`)
	}

	wantStatus(t, "alice's device_key", f.serve(must[*http.Request](t)(phone.FIDRequest(a, "alice-fid-2", f.now()))), http.StatusOK, "{}")
	if fid := f.fid(a.UserID); fid != "alice-fid-2" {
		t.Fatalf("alice's FID = %q, want alice-fid-2", fid)
	}
	if fid := f.fid(b.UserID); fid != bobPhone.FID {
		t.Fatalf("bob's FID = %q after alice's update, want %q", fid, bobPhone.FID)
	}
}
