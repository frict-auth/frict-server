package server

import (
	"context"
	"database/sql"
	"net/http"
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

// TestDeniesAndTimeoutsNeverDisable: however many cancels and timeouts a
// user piles up, pushes go on; only the push cap and a not_me pause
// refuse them.
func TestDeniesAndTimeoutsNeverDisable(t *testing.T) {
	f := newFixture(t)
	a, phone := f.enrolledPhone("alice")
	for range 30 {
		f.wantPushed(a, phone)
		f.timeout(a, phone)
	}
	f.push(a, phone, "approve", "", "allow")
}

// notMeSafeguards pause for 10 minutes after 2 not_me denies within an
// hour.
var notMeSafeguards = safeguards(func(sg *Safeguards) { sg.NotMeCount, sg.NotMeWindow, sg.Pause = 2, time.Hour, 10*time.Minute })

func TestNotMeCountPausesPushes(t *testing.T) {
	f := newFixtureWith(t, time.Minute, notMeSafeguards)
	a, phone := f.enrolledPhone("alice")
	f.push(a, phone, "deny", "not_me", "fraud")
	f.setClock(t0.Add(time.Minute))
	f.wantPushed(a, phone)
	f.push(a, phone, "deny", "not_me", "fraud")
	f.setClock(t0.Add(time.Minute + time.Second))
	f.wantRefused(a, "paused")
	f.setClock(t0.Add(11*time.Minute - time.Second))
	f.wantRefused(a, "paused")
	f.pending(a, phone, 0)
	f.setClock(t0.Add(11 * time.Minute))
	f.wantPushed(a, phone)
}

// TestApprovalDoesNotResetNotMeCount: a not_me, an approved login, then
// another not_me within the window still pause pushes.
func TestApprovalDoesNotResetNotMeCount(t *testing.T) {
	f := newFixtureWith(t, time.Minute, notMeSafeguards)
	a, phone := f.enrolledPhone("alice")
	f.push(a, phone, "deny", "not_me", "fraud")
	f.setClock(t0.Add(time.Minute))
	f.push(a, phone, "approve", "", "allow")
	f.setClock(t0.Add(2 * time.Minute))
	f.push(a, phone, "deny", "not_me", "fraud")
	f.wantRefused(a, "paused")
}

func TestNotMesOutsideWindowDoNotPause(t *testing.T) {
	f := newFixtureWith(t, time.Minute, notMeSafeguards)
	a, phone := f.enrolledPhone("alice")
	b, bobPhone := f.enrolledPhone("bob")
	f.push(a, phone, "deny", "not_me", "fraud")
	f.push(b, bobPhone, "deny", "not_me", "fraud")
	f.setClock(t0.Add(time.Hour))
	f.push(a, phone, "deny", "not_me", "fraud")
	f.wantPushed(a, phone)
	f.wantPushed(b, bobPhone)
}

func TestCancelDenyDoesNotPause(t *testing.T) {
	f := newFixtureWith(t, time.Minute, safeguards(func(sg *Safeguards) { sg.NotMeCount = 1 }))
	a, phone := f.enrolledPhone("alice")
	f.push(a, phone, "deny", "cancel", "deny")
	f.setClock(t0.Add(time.Second))
	f.wantPushed(a, phone)
	f.push(a, phone, "deny", "not_me", "fraud")
	f.wantRefused(a, "paused")
}
