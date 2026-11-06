package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/frict-auth/frict-server/internal/fakephone"
)

// challengeCount is how many challenges, of any status, userID has.
func (f *fixture) challengeCount(userID string) int {
	f.t.Helper()
	db, err := sql.Open("sqlite", "file:"+f.dbPath)
	if err != nil {
		f.t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM challenges WHERE user_id = ?`, userID).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

// push runs one /auth for a that the phone answers with decision and
// reason, and requires the /auth result Duo status wantStatus.
func (f *fixture) push(a fakephone.Activation, phone *fakephone.Phone, decision, reason, wantStatus string) {
	f.t.Helper()
	done := f.startAuth(context.Background(), a.UserID)
	id := f.pending(a, phone, 1)[0]
	if w := f.answer(a, phone, id, decision, reason); w.Code != http.StatusOK {
		f.t.Fatalf("answer %s %s: %d %s", decision, reason, w.Code, w.Body)
	}
	got := f.authResult(done)
	if got["status"] != wantStatus {
		f.t.Fatalf("/auth after %s %s = %v, want status %q", decision, reason, got, wantStatus)
	}
}

// timeout runs one /auth for a whose caller leaves before anyone answers.
func (f *fixture) timeout(a fakephone.Activation, phone *fakephone.Phone) {
	f.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := f.startAuth(ctx, a.UserID)
	f.pending(a, phone, 1)
	cancel()
	<-done
}

// wantRefused requires /auth for a to deny at once with Duo's locked_out
// status and a status_msg containing msg, and to create no challenge.
func (f *fixture) wantRefused(a fakephone.Activation, msg string) {
	f.t.Helper()
	before := f.challengeCount(a.UserID)
	got := f.authResult(f.startAuth(context.Background(), a.UserID))
	if got["result"] != "deny" || got["status"] != "locked_out" || !strings.Contains(got["status_msg"], msg) {
		f.t.Fatalf("/auth at %s = %v, want deny locked_out with status_msg containing %q", f.now().Sub(t0), got, msg)
	}
	if after := f.challengeCount(a.UserID); after != before {
		f.t.Fatalf("refused /auth created %d challenges", after-before)
	}
}

// wantPushed requires /auth for a to create a challenge, then denies it.
func (f *fixture) wantPushed(a fakephone.Activation, phone *fakephone.Phone) {
	f.t.Helper()
	before := f.challengeCount(a.UserID)
	f.push(a, phone, "deny", "cancel", "deny")
	if after := f.challengeCount(a.UserID); after != before+1 {
		f.t.Fatalf("/auth at %s created %d challenges, want 1", f.now().Sub(t0), after-before)
	}
}

func safeguards(edit func(*Safeguards)) Safeguards {
	sg := testSafeguards
	sg.AlertRecipients = append([]string(nil), sg.AlertRecipients...)
	edit(&sg)
	return sg
}

func TestPushCapRefusesWithoutPush(t *testing.T) {
	f := newFixtureWith(t, time.Minute, safeguards(func(sg *Safeguards) { sg.PushCap, sg.PushCooldown = 3, time.Hour }))
	a, phone := f.enrolledPhone("alice")
	for range 3 {
		f.wantPushed(a, phone)
	}
	f.wantRefused(a, "Too many pushes")
	f.pending(a, phone, 0)
}

func TestSuccessfulLoginResetsPushCap(t *testing.T) {
	f := newFixtureWith(t, time.Minute, safeguards(func(sg *Safeguards) { sg.PushCap, sg.PushCooldown = 3, time.Hour }))
	a, phone := f.enrolledPhone("alice")
	f.wantPushed(a, phone)
	f.wantPushed(a, phone)
	f.push(a, phone, "approve", "", "allow")
	for range 3 {
		f.wantPushed(a, phone)
	}
	f.wantRefused(a, "Too many pushes")
}

// TestPushCooldownLetsOnePushPerWindow: over the cap, a push goes out only
// once PushCooldown has passed since the last one, and then just one.
func TestPushCooldownLetsOnePushPerWindow(t *testing.T) {
	f := newFixtureWith(t, time.Minute, safeguards(func(sg *Safeguards) { sg.PushCap, sg.PushCooldown = 1, time.Minute }))
	a, phone := f.enrolledPhone("alice")
	f.wantPushed(a, phone)
	for _, window := range []time.Time{t0, t0.Add(time.Minute), t0.Add(2 * time.Minute)} {
		if window != t0 {
			f.setClock(window.Add(-time.Second))
			f.wantRefused(a, "Too many pushes")
			f.setClock(window)
			f.wantPushed(a, phone)
		}
		f.wantRefused(a, "Too many pushes")
	}
}

// TestFailedCountSurvivesNewChallenge: denies and timeouts add up across
// challenges; a new challenge does not reset the count, and MaxFailed of
// them disable the device.
func TestFailedCountSurvivesNewChallenge(t *testing.T) {
	f := newFixtureWith(t, time.Minute, safeguards(func(sg *Safeguards) { sg.MaxFailed = 3 }))
	a, phone := f.enrolledPhone("alice")
	f.wantPushed(a, phone)
	f.timeout(a, phone)
	f.wantPushed(a, phone)
	f.wantRefused(a, "disabled")
}

func TestSuccessfulLoginResetsFailedCount(t *testing.T) {
	f := newFixtureWith(t, time.Minute, safeguards(func(sg *Safeguards) { sg.MaxFailed = 3 }))
	a, phone := f.enrolledPhone("alice")
	f.wantPushed(a, phone)
	f.wantPushed(a, phone)
	f.push(a, phone, "approve", "", "allow")
	f.wantPushed(a, phone)
	f.wantPushed(a, phone)
	f.wantPushed(a, phone)
	f.wantRefused(a, "disabled")
}

// TestDisabledDeviceGetsNoPush: a disabled device stays disabled however
// long the user waits, while another user's pushes go on.
func TestDisabledDeviceGetsNoPush(t *testing.T) {
	f := newFixtureWith(t, time.Minute, safeguards(func(sg *Safeguards) { sg.MaxFailed = 1 }))
	a, phone := f.enrolledPhone("alice")
	b, bobPhone := f.enrolledPhone("bob")
	f.wantPushed(a, phone)
	f.wantRefused(a, "disabled")
	f.setClock(t0.Add(30 * 24 * time.Hour))
	f.wantRefused(a, "disabled")
	f.pending(a, phone, 0)
	f.wantPushed(b, bobPhone)
}

func TestNotMePausesPushes(t *testing.T) {
	f := newFixtureWith(t, time.Minute, safeguards(func(sg *Safeguards) { sg.Pause = 10 * time.Minute }))
	a, phone := f.enrolledPhone("alice")
	f.push(a, phone, "deny", "not_me", "fraud")
	f.setClock(t0.Add(time.Second))
	f.wantRefused(a, "paused")
	f.setClock(t0.Add(10*time.Minute - time.Second))
	f.wantRefused(a, "paused")
	f.setClock(t0.Add(10 * time.Minute))
	f.wantPushed(a, phone)
}

// alerts polls as the phone and returns the alerts in its answer.
func (f *fixture) alerts(a fakephone.Activation, phone *fakephone.Phone) []fakephone.Alert {
	f.t.Helper()
	w := f.serve(must[*http.Request](f.t)(phone.PendingRequest(a, f.now())))
	var p fakephone.Pending
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &p) != nil {
		f.t.Fatalf("pending: %d %s", w.Code, w.Body)
	}
	if p.Alerts == nil {
		f.t.Fatalf("pending without an alerts list: %s", w.Body)
	}
	return p.Alerts
}

// adminSearch is the username an Authentik admin UI link searches for, read
// back the way the UI reads it (web/src/elements/router/RouteMatch.ts).
func adminSearch(t *testing.T, link string) string {
	t.Helper()
	const prefix = "https://auth.example/if/admin/#/identity/users;"
	if !strings.HasPrefix(link, prefix) {
		t.Fatalf("link %q does not open Authentik's user list", link)
	}
	raw, err := url.PathUnescape(strings.TrimPrefix(link, prefix))
	if err != nil {
		t.Fatalf("link %q: %v", link, err)
	}
	var params map[string]string
	if err := json.Unmarshal([]byte(raw), &params); err != nil || len(params) != 1 {
		t.Fatalf("link %q params %q: want one JSON parameter", link, raw)
	}
	return params["ak-user-list-search"]
}

func TestNotMeAlertsEachRecipient(t *testing.T) {
	f := newFixtureWith(t, time.Minute, safeguards(func(sg *Safeguards) { sg.AlertRecipients = []string{"admin", "sec"} }))
	admin, adminPhone := f.enrolledPhone("admin")
	sec, secPhone := f.enrolledPhone("sec")
	alice, alicePhone := f.enrolledPhone("alice")
	bob, bobPhone := f.enrolledPhone("bob")

	done := f.startAuth(context.Background(), alice.UserID)
	id := f.pending(alice, alicePhone, 1)[0]
	f.setClock(t0.Add(5 * time.Second))
	wantStatus(t, "not_me", f.answer(alice, alicePhone, id, "deny", "not_me"), http.StatusOK, "{}")
	wantResult(t, f.authResult(done), "deny", "fraud")

	got := f.alerts(admin, adminPhone)
	if len(got) != 1 {
		t.Fatalf("admin alerts %+v, want 1", got)
	}
	al := got[0]
	want := fakephone.Alert{AlertID: al.AlertID, Username: "élodie", IPAddr: "203.0.113.7",
		PushInfo: "Domain=auth.example&Application=Grafana", Type: "authentik Login request",
		Attempted: t0.Unix(), Reported: t0.Add(5 * time.Second).Unix(),
		ResetPasswordURL: al.ResetPasswordURL, RevokeSessionsURL: al.RevokeSessionsURL}
	if al != want {
		t.Fatalf("alert %+v, want %+v", al, want)
	}
	if _, ok := decodeID(al.AlertID); !ok {
		t.Fatalf("alert_id %q is not 16 base64url bytes", al.AlertID)
	}
	for name, link := range map[string]string{"reset_password_url": al.ResetPasswordURL, "revoke_sessions_url": al.RevokeSessionsURL} {
		if got := adminSearch(t, link); got != "élodie" {
			t.Fatalf("%s searches for %q, want élodie", name, got)
		}
	}

	secAlerts := f.alerts(sec, secPhone)
	if len(secAlerts) != 1 || secAlerts[0].AlertID == al.AlertID || secAlerts[0].Username != "élodie" {
		t.Fatalf("sec alerts %+v, want one of its own for élodie", secAlerts)
	}
	if again := f.alerts(admin, adminPhone); len(again) != 1 || again[0] != al {
		t.Fatalf("admin's second poll %+v, want the same alert", again)
	}
	for name, who := range map[string]struct {
		a     fakephone.Activation
		phone *fakephone.Phone
	}{"alice": {alice, alicePhone}, "bob": {bob, bobPhone}} {
		if got := f.alerts(who.a, who.phone); len(got) != 0 {
			t.Fatalf("%s is not a recipient but got alerts %+v", name, got)
		}
	}

	asAdmin := func(key *fakephone.Phone, approval bool) *http.Request {
		k := key.DeviceKey
		if approval {
			k = key.ApprovalKey
		}
		return must[*http.Request](t)(fakephone.SignedRequest("https://"+host, fakephone.PendingPath, admin.UserID, f.now().Unix(), []byte("{}"), k))
	}
	wantStatus(t, "bob polls as admin", f.serve(asAdmin(bobPhone, false)), http.StatusUnauthorized, `{"error":"unauthorized"}`)
	wantStatus(t, "admin polls with the approval_key", f.serve(asAdmin(adminPhone, true)), http.StatusUnauthorized, `{"error":"unauthorized"}`)
	unsigned := must[*http.Request](t)(fakephone.SignedRequest("https://"+host, fakephone.PendingPath, admin.UserID, f.now().Unix(), []byte("{}"), adminPhone.DeviceKey))
	unsigned.Header.Del("Authorization")
	wantStatus(t, "unsigned poll", f.serve(unsigned), http.StatusUnauthorized, `{"error":"unauthorized"}`)

	f.setClock(t0.Add(5*time.Second + 24*time.Hour - time.Second))
	if got := f.alerts(admin, adminPhone); len(got) != 1 {
		t.Fatalf("admin alerts just before AlertTTL: %+v, want 1", got)
	}
	f.setClock(t0.Add(5*time.Second + 24*time.Hour))
	if got := f.alerts(admin, adminPhone); len(got) != 0 {
		t.Fatalf("admin alerts at AlertTTL: %+v, want none", got)
	}
}

func TestCancelDenyNeitherPausesNorAlerts(t *testing.T) {
	f := newFixture(t)
	admin, adminPhone := f.enrolledPhone("admin")
	a, phone := f.enrolledPhone("alice")
	f.push(a, phone, "deny", "cancel", "deny")
	f.setClock(t0.Add(time.Second))
	f.wantPushed(a, phone)
	if got := f.alerts(admin, adminPhone); len(got) != 0 {
		t.Fatalf("admin alerts after a cancel deny: %+v, want none", got)
	}
}
