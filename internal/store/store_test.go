package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func openTemp(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "frict.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}

func goldenPath(version int) string {
	return filepath.Join("testdata", fmt.Sprintf("schema_v%d.sql", version))
}

func userVersion(t *testing.T, db *sql.DB) int {
	t.Helper()
	var v int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		t.Fatalf("read user_version: %v", err)
	}
	return v
}

// schemaDump renders every table, index and trigger's SQL in name order.
func schemaDump(t *testing.T, db *sql.DB) string {
	t.Helper()
	rows, err := db.Query(`SELECT sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY name`)
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	defer rows.Close()
	var stmts []string
	for rows.Next() {
		var stmt string
		if err := rows.Scan(&stmt); err != nil {
			t.Fatalf("scan schema: %v", err)
		}
		stmts = append(stmts, stmt+";\n")
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read schema: %v", err)
	}
	return strings.Join(stmts, "\n")
}

func TestOpenMigratesEmptyDatabaseToFrozenSchema(t *testing.T) {
	s, _ := openTemp(t)

	if got := userVersion(t, s.db); got != len(migrations) {
		t.Fatalf("user_version = %d, want %d", got, len(migrations))
	}
	golden := goldenPath(len(migrations))
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read %s: %v", golden, err)
	}
	if got := schemaDump(t, s.db); got != string(want) {
		t.Fatalf("schema differs from %s; a deployed migration was edited, or a new one needs its own golden.\ngot:\n%s", golden, got)
	}
}

// TestOpenMigratesPriorSchemaCopy loads each frozen schema older than the
// current one, and the empty database, and requires Open to bring it to the
// current schema.
func TestOpenMigratesPriorSchemaCopy(t *testing.T) {
	current, err := os.ReadFile(goldenPath(len(migrations)))
	if err != nil {
		t.Fatal(err)
	}
	for v := 0; v < len(migrations); v++ {
		path := filepath.Join(t.TempDir(), "frict.db")
		old, err := sql.Open("sqlite", "file:"+path)
		if err != nil {
			t.Fatal(err)
		}
		if v > 0 {
			prior, err := os.ReadFile(goldenPath(v))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := old.Exec(string(prior)); err != nil {
				t.Fatalf("load schema v%d: %v", v, err)
			}
		}
		if _, err := old.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, v)); err != nil {
			t.Fatal(err)
		}
		old.Close()

		s, err := Open(path)
		if err != nil {
			t.Fatalf("Open schema v%d copy: %v", v, err)
		}
		got := schemaDump(t, s.db)
		s.Close()
		if got != string(current) {
			t.Fatalf("schema v%d migrated to:\n%s\nwant:\n%s", v, got, current)
		}
	}
}

func TestReopenIsNoOp(t *testing.T) {
	s, path := openTemp(t)
	if _, err := s.db.Exec(`INSERT INTO users (user_id, username, created_at) VALUES ('DU1', 'alice', 1)`); err != nil {
		t.Fatalf("insert: %v", err)
	}
	s.Close()

	s2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	var n int
	if err := s2.db.QueryRow(`SELECT count(*) FROM users`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("users after reopen = %d err:%v, want 1", n, err)
	}
}

func TestOpenRejectsNewerSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "frict.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA user_version = 99`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	if s, err := Open(path); err == nil {
		s.Close()
		t.Fatal("Open accepted a database at schema version 99")
	} else if !strings.Contains(err.Error(), "newer than this binary") {
		t.Fatalf("Open error = %v, want one naming the newer schema", err)
	}
}

func TestSchemaConstraints(t *testing.T) {
	const id = `x'00112233445566778899aabbccddeeff'`
	const challenge = `INSERT INTO challenges (id, user_id, ipaddr, pushinfo, status, created_at, expires_at, answered_at, reason) VALUES `
	tests := []struct {
		name   string
		stmt   string
		accept bool
	}{
		{"pending challenge", challenge + `(` + id + `, 'DU1', '203.0.113.7', '', 'pending', 100, 160, NULL, NULL)`, true},
		{"approved challenge", challenge + `(` + id + `, 'DU1', '', '', 'approved', 100, 160, 130, NULL)`, true},
		{"denied not_me", challenge + `(` + id + `, 'DU1', '', '', 'denied', 100, 160, 130, 'not_me')`, true},
		{"denied cancel", challenge + `(` + id + `, 'DU1', '', '', 'denied', 100, 160, 130, 'cancel')`, true},
		{"expired challenge", challenge + `(` + id + `, 'DU1', '', '', 'expired', 100, 160, NULL, NULL)`, true},
		{"denied without reason", challenge + `(` + id + `, 'DU1', '', '', 'denied', 100, 160, 130, NULL)`, false},
		{"approved with reason", challenge + `(` + id + `, 'DU1', '', '', 'approved', 100, 160, 130, 'cancel')`, false},
		{"unknown reason", challenge + `(` + id + `, 'DU1', '', '', 'denied', 100, 160, 130, 'bored')`, false},
		{"unknown status", challenge + `(` + id + `, 'DU1', '', '', 'maybe', 100, 160, NULL, NULL)`, false},
		{"answered without answered_at", challenge + `(` + id + `, 'DU1', '', '', 'approved', 100, 160, NULL, NULL)`, false},
		{"pending with answered_at", challenge + `(` + id + `, 'DU1', '', '', 'pending', 100, 160, 130, NULL)`, false},
		{"expires before created", challenge + `(` + id + `, 'DU1', '', '', 'pending', 100, 100, NULL, NULL)`, false},
		{"15-byte id", challenge + `(x'00112233445566778899aabbccddee', 'DU1', '', '', 'pending', 100, 160, NULL, NULL)`, false},
		{"16-character text id", challenge + `('0123456789abcdef', 'DU1', '', '', 'pending', 100, 160, NULL, NULL)`, false},
		{"challenge for unknown user", challenge + `(` + id + `, 'DU404', '', '', 'pending', 100, 160, NULL, NULL)`, false},
		{"device for known user", `INSERT INTO devices (user_id, device_key, approval_key, attestation, fid, enrolled_at) VALUES ('DU1', x'01', x'02', x'03', 'fid', 1)`, true},
		{"device for unknown user", `INSERT INTO devices (user_id, device_key, approval_key, attestation, fid, enrolled_at) VALUES ('DU404', x'01', x'02', x'03', 'fid', 1)`, false},
		{"negative app_version", `INSERT INTO devices (user_id, device_key, approval_key, attestation, fid, enrolled_at, app_version) VALUES ('DU1', x'01', x'02', x'03', 'fid', 1, -1)`, false},
		{"negative pushes_since_success", `UPDATE users SET pushes_since_success = -1 WHERE user_id = 'DU1'`, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := openTemp(t)
			if _, err := s.db.Exec(`INSERT INTO users (user_id, username, created_at) VALUES ('DU1', 'alice', 1)`); err != nil {
				t.Fatalf("insert user: %v", err)
			}
			_, err := s.db.Exec(tc.stmt)
			if tc.accept && err != nil {
				t.Fatalf("rejected: %v", err)
			}
			if !tc.accept && err == nil {
				t.Fatal("accepted, want a constraint error")
			}
		})
	}
}

func TestPing(t *testing.T) {
	s, _ := openTemp(t)
	if err := s.Ping(context.Background()); err != nil {
		t.Fatalf("Ping open store: %v", err)
	}
	s.Close()
	if err := s.Ping(context.Background()); err == nil {
		t.Fatal("Ping on a closed store returned nil")
	}
}

var t0 = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

const (
	aliceID   = "DUAAAAAAAAAAAAAAAAAAAAAAAAAA"
	bobID     = "DUBBBBBBBBBBBBBBBBBBBBBBBBBB"
	aliceCode = "ALICECODE"
	bobCode   = "BOBCODE"
)

// enrolling returns a store where alice and bob each hold an activation code
// valid from t0 for ten minutes.
func enrolling(t *testing.T) *Store {
	t.Helper()
	s, _ := openTemp(t)
	ctx := context.Background()
	for _, u := range []struct{ id, name, code string }{{aliceID, "alice", aliceCode}, {bobID, "bob", bobCode}} {
		if err := s.CreateEnrollment(ctx, u.id, u.name, u.code, t0, t0.Add(10*time.Minute)); err != nil {
			t.Fatalf("CreateEnrollment %s: %v", u.name, err)
		}
	}
	return s
}

func device(key string, at time.Time) Device {
	return Device{DeviceKey: []byte("dk-" + key), ApprovalKey: []byte("ak-" + key), Attestation: []byte(`{"k":"` + key + `"}`), FID: "fid-" + key, EnrolledAt: at}
}

func TestCreateEnrollmentStoresOnlyCodeHash(t *testing.T) {
	s := enrolling(t)
	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM users WHERE instr(activation_hash, ?) > 0`, aliceCode).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("activation code stored in clear")
	}
}

func TestEnrollThenStatus(t *testing.T) {
	s := enrolling(t)
	ctx := context.Background()
	status := func(userID, code string, at time.Time) EnrollmentStatus {
		t.Helper()
		st, err := s.EnrollmentStatusOf(ctx, userID, code, at)
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	if got := status(aliceID, aliceCode, t0); got != EnrollmentWaiting {
		t.Fatalf("before enroll: %q, want waiting", got)
	}
	want := device("alice", t0.Add(time.Minute))
	if err := s.Enroll(ctx, aliceCode, aliceID, want); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	for _, tc := range []struct {
		name, user, code string
		at               time.Time
		want             EnrollmentStatus
	}{
		{"enrolled", aliceID, aliceCode, t0.Add(time.Minute), EnrollmentSuccess},
		{"enrolled, asked after expiry", aliceID, aliceCode, t0.Add(time.Hour), EnrollmentSuccess},
		{"other user's code", aliceID, bobCode, t0, EnrollmentInvalid},
		{"unknown user", "DUCCCCCCCCCCCCCCCCCCCCCCCCCC", aliceCode, t0, EnrollmentInvalid},
		{"unenrolled bob", bobID, bobCode, t0, EnrollmentWaiting},
		{"unenrolled bob after expiry", bobID, bobCode, t0.Add(10 * time.Minute), EnrollmentInvalid},
	} {
		if got := status(tc.user, tc.code, tc.at); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
	got, err := s.DeviceOf(ctx, aliceID)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.DeviceKey) != string(want.DeviceKey) || string(got.ApprovalKey) != string(want.ApprovalKey) ||
		string(got.Attestation) != string(want.Attestation) || got.FID != want.FID || !got.EnrolledAt.Equal(want.EnrolledAt) {
		t.Fatalf("DeviceOf = %+v, want %+v", got, want)
	}
	if _, err := s.DeviceOf(ctx, bobID); !errors.Is(err, ErrNoDevice) {
		t.Fatalf("DeviceOf bob = %v, want ErrNoDevice", err)
	}
}

func TestEnrollRejectsReusedCode(t *testing.T) {
	s := enrolling(t)
	ctx := context.Background()
	if err := s.Enroll(ctx, aliceCode, aliceID, device("first", t0)); err != nil {
		t.Fatalf("first Enroll: %v", err)
	}
	if err := s.Enroll(ctx, aliceCode, aliceID, device("second", t0.Add(time.Second))); !errors.Is(err, ErrActivationUsed) {
		t.Fatalf("second Enroll = %v, want ErrActivationUsed", err)
	}
	got, err := s.DeviceOf(ctx, aliceID)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.DeviceKey) != "dk-first" {
		t.Fatalf("device_key = %q after reuse, want the first device's", got.DeviceKey)
	}
}

func TestEnrollRejectsExpiredCode(t *testing.T) {
	s := enrolling(t)
	ctx := context.Background()
	if err := s.Enroll(ctx, aliceCode, aliceID, device("late", t0.Add(10*time.Minute))); !errors.Is(err, ErrActivationInvalid) {
		t.Fatalf("Enroll at expiry = %v, want ErrActivationInvalid", err)
	}
	if err := s.Enroll(ctx, aliceCode, aliceID, device("in time", t0.Add(10*time.Minute-time.Second))); err != nil {
		t.Fatalf("Enroll a second before expiry: %v", err)
	}
}

func TestEnrollTakesUserFromCode(t *testing.T) {
	s := enrolling(t)
	ctx := context.Background()
	if err := s.Enroll(ctx, aliceCode, bobID, device("mallory", t0)); !errors.Is(err, ErrUserMismatch) {
		t.Fatalf("Enroll alice's code claiming bob = %v, want ErrUserMismatch", err)
	}
	for _, id := range []string{aliceID, bobID} {
		if _, err := s.DeviceOf(ctx, id); !errors.Is(err, ErrNoDevice) {
			t.Fatalf("DeviceOf %s = %v, want ErrNoDevice", id, err)
		}
	}
}

func TestEnrollRejectsUnknownCode(t *testing.T) {
	s := enrolling(t)
	if err := s.Enroll(context.Background(), "NOSUCHCODE", aliceID, device("x", t0)); !errors.Is(err, ErrActivationInvalid) {
		t.Fatalf("Enroll unknown code = %v, want ErrActivationInvalid", err)
	}
}

// enrolled returns a store where alice and bob each have a device.
func enrolled(t *testing.T) *Store {
	t.Helper()
	s := enrolling(t)
	for _, u := range []struct{ id, code string }{{aliceID, aliceCode}, {bobID, bobCode}} {
		if err := s.Enroll(context.Background(), u.code, u.id, device(u.id, t0)); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

// noLimits never refuses a push.
var noLimits = Limits{PushCap: 1000, Cooldown: time.Second}

func challengeID(b byte) []byte { return []byte{b, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, b} }

// pushTo stores a pending challenge for userID created at at, expiring a
// minute later.
func pushTo(t *testing.T, s *Store, id []byte, userID string, at time.Time) Challenge {
	t.Helper()
	c := Challenge{ID: id, UserID: userID, DisplayUsername: "alice", IPAddr: "203.0.113.7",
		PushInfo: "Domain=auth.example&Application=Grafana", Type: "authentik Login request",
		CreatedAt: at, ExpiresAt: at.Add(time.Minute)}
	if lock, err := s.StartPush(context.Background(), c, noLimits); err != nil || lock != Unlocked {
		t.Fatalf("StartPush: %q %v", lock, err)
	}
	return c
}

func pendingIDs(t *testing.T, s *Store, userID string, now time.Time) []string {
	t.Helper()
	cs, err := s.PendingChallenges(context.Background(), userID, now)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, c := range cs {
		ids = append(ids, fmt.Sprintf("%x", c.ID))
	}
	return ids
}

func TestPendingChallengesAreTheUsersUnexpiredOnes(t *testing.T) {
	s := enrolled(t)
	ctx := context.Background()
	pushTo(t, s, challengeID(1), aliceID, t0)
	pushTo(t, s, challengeID(2), aliceID, t0.Add(30*time.Second))
	pushTo(t, s, challengeID(3), bobID, t0)
	answered := pushTo(t, s, challengeID(4), aliceID, t0)
	if err := s.AnswerChallenge(ctx, answered.ID, aliceID, Outcome{Status: ChallengeApproved}, t0, NotMe{}); err != nil {
		t.Fatal(err)
	}

	if got, want := pendingIDs(t, s, aliceID, t0.Add(59*time.Second)), []string{fmt.Sprintf("%x", challengeID(1)), fmt.Sprintf("%x", challengeID(2))}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("alice pending at t0+59s = %v, want %v", got, want)
	}
	if got := pendingIDs(t, s, aliceID, t0.Add(time.Minute)); len(got) != 1 || got[0] != fmt.Sprintf("%x", challengeID(2)) {
		t.Fatalf("alice pending at t0+60s = %v, want only the second", got)
	}
}

func TestPendingChallengeDetails(t *testing.T) {
	s := enrolled(t)
	ctx := context.Background()
	want := pushTo(t, s, challengeID(1), aliceID, t0)
	got, err := s.PendingChallenge(ctx, want.ID, aliceID, t0)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%+v", got) != fmt.Sprintf("%+v", Challenge{ID: want.ID, UserID: aliceID, DisplayUsername: want.DisplayUsername,
		IPAddr: want.IPAddr, PushInfo: want.PushInfo, Type: want.Type, CreatedAt: time.Unix(t0.Unix(), 0), ExpiresAt: time.Unix(want.ExpiresAt.Unix(), 0)}) {
		t.Fatalf("PendingChallenge = %+v, want %+v", got, want)
	}
	for name, tc := range map[string]struct {
		user string
		at   time.Time
	}{
		"another user's": {bobID, t0},
		"expired":        {aliceID, t0.Add(time.Minute)},
	} {
		if _, err := s.PendingChallenge(ctx, want.ID, tc.user, tc.at); !errors.Is(err, ErrChallengeNotFound) {
			t.Errorf("%s: %v, want ErrChallengeNotFound", name, err)
		}
	}
}

func TestAnswerChallengeOnce(t *testing.T) {
	for _, answer := range []Outcome{
		{Status: ChallengeApproved},
		{Status: ChallengeDenied, Reason: "not_me"},
		{Status: ChallengeDenied, Reason: "cancel"},
	} {
		t.Run(string(answer.Status)+answer.Reason, func(t *testing.T) {
			s := enrolled(t)
			ctx := context.Background()
			c := pushTo(t, s, challengeID(1), aliceID, t0)
			if err := s.AnswerChallenge(ctx, c.ID, aliceID, answer, t0.Add(time.Second), NotMe{}); err != nil {
				t.Fatalf("first answer: %v", err)
			}
			if err := s.AnswerChallenge(ctx, c.ID, aliceID, Outcome{Status: ChallengeApproved}, t0.Add(2*time.Second), NotMe{}); !errors.Is(err, ErrChallengeNotPending) {
				t.Fatalf("second answer: %v, want ErrChallengeNotPending", err)
			}
			got, err := s.CloseChallenge(ctx, c.ID)
			if err != nil {
				t.Fatal(err)
			}
			if got != answer {
				t.Fatalf("outcome %+v, want the first answer %+v", got, answer)
			}
		})
	}
}

func TestAnswerChallengeRejected(t *testing.T) {
	s := enrolled(t)
	ctx := context.Background()
	c := pushTo(t, s, challengeID(1), aliceID, t0)
	approve := Outcome{Status: ChallengeApproved}
	if err := s.AnswerChallenge(ctx, c.ID, bobID, approve, t0, NotMe{}); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("bob answering alice's challenge: %v, want ErrChallengeNotFound", err)
	}
	if err := s.AnswerChallenge(ctx, challengeID(9), aliceID, approve, t0, NotMe{}); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("unknown challenge: %v, want ErrChallengeNotFound", err)
	}
	if err := s.AnswerChallenge(ctx, c.ID, aliceID, approve, c.ExpiresAt, NotMe{}); !errors.Is(err, ErrChallengeNotPending) {
		t.Fatalf("answer at expiry: %v, want ErrChallengeNotPending", err)
	}
	if err := s.AnswerChallenge(ctx, c.ID, aliceID, Outcome{Status: ChallengeDenied}, t0, NotMe{}); err == nil {
		t.Fatal("deny without a reason accepted")
	}
	if err := s.AnswerChallenge(ctx, c.ID, aliceID, Outcome{Status: ChallengeDenied, Reason: "bored"}, t0, NotMe{}); err == nil {
		t.Fatal("deny with an unknown reason accepted")
	}
	if got := pendingIDs(t, s, aliceID, t0); len(got) != 1 {
		t.Fatalf("rejected answers changed the challenge: pending %v", got)
	}
}

func TestCloseChallengeExpiresPending(t *testing.T) {
	s := enrolled(t)
	ctx := context.Background()
	c := pushTo(t, s, challengeID(1), aliceID, t0)
	got, err := s.CloseChallenge(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got != (Outcome{Status: ChallengeExpired}) {
		t.Fatalf("CloseChallenge on a pending challenge = %+v, want expired", got)
	}
	if err := s.AnswerChallenge(ctx, c.ID, aliceID, Outcome{Status: ChallengeApproved}, t0, NotMe{}); !errors.Is(err, ErrChallengeNotPending) {
		t.Fatalf("answer after close: %v, want ErrChallengeNotPending", err)
	}
}

// TestEnrollConcurrentSameCode: of several devices racing to enroll with one
// activation code, exactly one succeeds and the rest get ErrActivationUsed.
func TestEnrollConcurrentSameCode(t *testing.T) {
	s := enrolling(t)
	const racers = 8
	errs := make(chan error, racers)
	start := make(chan struct{})
	for i := range racers {
		go func() {
			<-start
			errs <- s.Enroll(context.Background(), aliceCode, aliceID, device(fmt.Sprint(i), t0))
		}()
	}
	close(start)
	var ok, used int
	for range racers {
		switch err := <-errs; {
		case err == nil:
			ok++
		case errors.Is(err, ErrActivationUsed):
			used++
		default:
			t.Errorf("Enroll: %v", err)
		}
	}
	if ok != 1 || used != racers-1 {
		t.Fatalf("%d enrolls succeeded and %d got ErrActivationUsed, want 1 and %d", ok, used, racers-1)
	}
}

func TestStartPushRequiresDevice(t *testing.T) {
	s := enrolling(t)
	c := Challenge{ID: challengeID(1), UserID: aliceID, CreatedAt: t0, ExpiresAt: t0.Add(time.Minute)}
	if _, err := s.StartPush(context.Background(), c, noLimits); !errors.Is(err, ErrNoDevice) {
		t.Fatalf("StartPush for a user without a device: %v, want ErrNoDevice", err)
	}
	if got := pendingIDs(t, s, aliceID, t0); len(got) != 0 {
		t.Fatalf("pending after a refused push: %v", got)
	}
}

func fidOf(t *testing.T, s *Store, userID string) string {
	t.Helper()
	d, err := s.DeviceOf(context.Background(), userID)
	if err != nil {
		t.Fatal(err)
	}
	return d.FID
}

func TestSetFIDOnlyForEnrolledDevice(t *testing.T) {
	s := enrolled(t)
	ctx := context.Background()
	if err := s.SetFID(ctx, aliceID, "alice-2"); err != nil {
		t.Fatal(err)
	}
	if got := fidOf(t, s, aliceID); got != "alice-2" {
		t.Fatalf("alice's FID = %q, want alice-2", got)
	}
	if got := fidOf(t, s, bobID); got != device(bobID, t0).FID {
		t.Fatalf("bob's FID = %q, changed by alice's update", got)
	}
	if err := s.SetFID(ctx, "DUNOBODY", "x"); !errors.Is(err, ErrNoDevice) {
		t.Fatalf("SetFID for a user without a device: %v, want ErrNoDevice", err)
	}
}

// TestClearFIDKeepsNewerFID: clearing a dead FID leaves a FID the device
// sent after the failed push, and leaves the device enrolled either way.
func TestClearFIDKeepsNewerFID(t *testing.T) {
	s := enrolled(t)
	ctx := context.Background()
	dead := fidOf(t, s, aliceID)
	if err := s.SetFID(ctx, aliceID, "alice-2"); err != nil {
		t.Fatal(err)
	}
	if err := s.ClearFID(ctx, aliceID, dead); err != nil {
		t.Fatal(err)
	}
	if got := fidOf(t, s, aliceID); got != "alice-2" {
		t.Fatalf("FID after clearing the old one = %q, want alice-2 kept", got)
	}
	if err := s.ClearFID(ctx, aliceID, "alice-2"); err != nil {
		t.Fatal(err)
	}
	if got := fidOf(t, s, aliceID); got != "" {
		t.Fatalf("FID after clearing it = %q, want empty", got)
	}
}

// rowsOf counts table's rows for userID.
func rowsOf(t *testing.T, s *Store, table, userID string) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM `+table+` WHERE user_id = ?`, userID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestRemoveUserDeletesEverythingItsOwn: removal deletes the user, its device
// and all its challenges, answered or not, and nothing of another user's.
// The removed user then has no device to push to, and a second removal
// finds nothing.
func TestRemoveUserDeletesEverythingItsOwn(t *testing.T) {
	s := enrolled(t)
	ctx := context.Background()
	approved := pushTo(t, s, challengeID(1), aliceID, t0)
	if err := s.AnswerChallenge(ctx, approved.ID, aliceID, Outcome{Status: ChallengeApproved}, t0, NotMe{}); err != nil {
		t.Fatal(err)
	}
	pending := pushTo(t, s, challengeID(2), aliceID, t0)
	pushTo(t, s, challengeID(3), bobID, t0)

	if err := s.RemoveUser(ctx, aliceID); err != nil {
		t.Fatalf("RemoveUser: %v", err)
	}
	for _, table := range []string{"users", "devices", "challenges"} {
		if n := rowsOf(t, s, table, aliceID); n != 0 {
			t.Errorf("%s rows for alice after removal = %d, want 0", table, n)
		}
		if n := rowsOf(t, s, table, bobID); n == 0 {
			t.Errorf("%s rows for bob after alice's removal = 0, want his kept", table)
		}
	}
	if err := s.RemoveUser(ctx, aliceID); !errors.Is(err, ErrNoDevice) {
		t.Fatalf("second RemoveUser: %v, want ErrNoDevice", err)
	}
	if _, err := s.StartPush(ctx, Challenge{ID: challengeID(4), UserID: aliceID, CreatedAt: t0, ExpiresAt: t0.Add(time.Minute)}, noLimits); !errors.Is(err, ErrNoDevice) {
		t.Fatalf("StartPush for a removed user: %v, want ErrNoDevice", err)
	}
	if _, err := s.CloseChallenge(ctx, pending.ID); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("CloseChallenge of a removed user's challenge: %v, want ErrChallengeNotFound", err)
	}
}

func TestRemoveUserNeedsADevice(t *testing.T) {
	s := enrolling(t)
	if err := s.RemoveUser(context.Background(), aliceID); !errors.Is(err, ErrNoDevice) {
		t.Fatalf("RemoveUser before enrollment: %v, want ErrNoDevice", err)
	}
	if got, err := s.EnrollmentStatusOf(context.Background(), aliceID, aliceCode, t0); err != nil || got != EnrollmentWaiting {
		t.Fatalf("enrollment after a refused removal: %q %v, want waiting", got, err)
	}
}

// TestDeleteChallengesBefore deletes challenges that expired before the
// cutoff, answered or not, and keeps the rest.
func TestDeleteChallengesBefore(t *testing.T) {
	s := enrolled(t)
	ctx := context.Background()
	old := pushTo(t, s, challengeID(1), aliceID, t0)
	if err := s.AnswerChallenge(ctx, old.ID, aliceID, Outcome{Status: ChallengeDenied, Reason: "not_me"}, t0, NotMe{Count: 1, Window: time.Hour, Pause: time.Second}); err != nil {
		t.Fatal(err)
	}
	pushTo(t, s, challengeID(2), bobID, t0)
	edge := pushTo(t, s, challengeID(3), aliceID, t0.Add(time.Second))

	n, err := s.DeleteChallengesBefore(ctx, edge.ExpiresAt)
	if err != nil || n != 2 {
		t.Fatalf("DeleteChallengesBefore = %d %v, want 2", n, err)
	}
	if got := rowsOf(t, s, "challenges", aliceID) + rowsOf(t, s, "challenges", bobID); got != 1 {
		t.Fatalf("challenges left = %d, want only the one expiring at the cutoff", got)
	}
	if _, err := s.CloseChallenge(ctx, edge.ID); err != nil {
		t.Fatalf("challenge expiring at the cutoff: %v, want it kept", err)
	}
}

// notMe answers a new challenge for alice with not_me at at.
func notMe(t *testing.T, s *Store, b byte, at time.Time, policy NotMe) {
	t.Helper()
	c := pushTo(t, s, challengeID(b), aliceID, at)
	if err := s.AnswerChallenge(context.Background(), c.ID, aliceID, Outcome{Status: ChallengeDenied, Reason: "not_me"}, at, policy); err != nil {
		t.Fatal(err)
	}
}

// pausedAt reports whether alice's pushes are paused at at.
func pausedAt(t *testing.T, s *Store, b byte, at time.Time) bool {
	t.Helper()
	lock, err := s.StartPush(context.Background(), Challenge{ID: challengeID(b), UserID: aliceID, CreatedAt: at, ExpiresAt: at.Add(time.Minute)}, noLimits)
	if err != nil {
		t.Fatal(err)
	}
	return lock == LockPaused
}

func TestNotMeCountWithinWindowPauses(t *testing.T) {
	policy := NotMe{Count: 3, Window: time.Hour, Pause: 30 * time.Minute}
	for _, tc := range []struct {
		name  string
		third time.Duration
		pause bool
	}{
		{"third just inside the window", time.Hour - time.Second, true},
		{"third at the window", time.Hour, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := enrolled(t)
			notMe(t, s, 1, t0, policy)
			notMe(t, s, 2, t0.Add(time.Minute), policy)
			if pausedAt(t, s, 3, t0.Add(2*time.Minute)) {
				t.Fatal("paused after 2 not_me denies, want 3")
			}
			at := t0.Add(tc.third)
			notMe(t, s, 4, at, policy)
			if got := pausedAt(t, s, 5, at); got != tc.pause {
				t.Fatalf("paused after the third not_me = %v, want %v", got, tc.pause)
			}
		})
	}
}

func TestApprovalDoesNotResetNotMeCount(t *testing.T) {
	policy := NotMe{Count: 2, Window: time.Hour, Pause: 30 * time.Minute}
	s := enrolled(t)
	notMe(t, s, 1, t0, policy)
	ok := pushTo(t, s, challengeID(2), aliceID, t0.Add(time.Minute))
	if err := s.AnswerChallenge(context.Background(), ok.ID, aliceID, Outcome{Status: ChallengeApproved}, t0.Add(time.Minute), policy); err != nil {
		t.Fatal(err)
	}
	at := t0.Add(2 * time.Minute)
	notMe(t, s, 3, at, policy)
	if !pausedAt(t, s, 4, at) {
		t.Fatal("not paused after not_me, approve, not_me")
	}
	if !pausedAt(t, s, 5, at.Add(30*time.Minute-time.Second)) || pausedAt(t, s, 6, at.Add(30*time.Minute)) {
		t.Fatal("pause does not last exactly Pause")
	}
}

// TestAppVersion: enrollment stores the version the phone sent, the latest
// one replaces it, and a device below MinAppVersion gets no push: nothing is
// stored and no counter moves. A device at the minimum, or any device with
// no minimum, is pushed.
func TestAppVersion(t *testing.T) {
	s := enrolling(t)
	ctx := context.Background()
	d := device(aliceID, t0)
	d.AppVersion = 1000
	if err := s.Enroll(ctx, aliceCode, aliceID, d); err != nil {
		t.Fatal(err)
	}
	versionOf := func() int {
		t.Helper()
		d, err := s.DeviceOf(ctx, aliceID)
		if err != nil {
			t.Fatal(err)
		}
		return d.AppVersion
	}
	if got := versionOf(); got != 1000 {
		t.Fatalf("app version after enroll = %d, want 1000", got)
	}
	if err := s.SetAppVersion(ctx, aliceID, 999); err != nil {
		t.Fatal(err)
	}
	if got := versionOf(); got != 999 {
		t.Fatalf("app version after SetAppVersion = %d, want 999", got)
	}

	push := func(b byte, min int) Lock {
		t.Helper()
		lim := noLimits
		lim.MinAppVersion = min
		lock, err := s.StartPush(ctx, Challenge{ID: challengeID(b), UserID: aliceID, CreatedAt: t0, ExpiresAt: t0.Add(time.Minute)}, lim)
		if err != nil {
			t.Fatal(err)
		}
		return lock
	}
	if lock := push(1, 1000); lock != LockOutdated {
		t.Fatalf("push to version 999 with minimum 1000: %q, want outdated", lock)
	}
	var pushes int
	if err := s.db.QueryRow(`SELECT pushes_since_success FROM users WHERE user_id = ?`, aliceID).Scan(&pushes); err != nil {
		t.Fatal(err)
	}
	if n := rowsOf(t, s, "challenges", aliceID); n != 0 || pushes != 0 {
		t.Fatalf("refused push left %d challenges and %d pushes counted", n, pushes)
	}
	if lock := push(2, 999); lock != Unlocked {
		t.Fatalf("push to version 999 with minimum 999: %q, want unlocked", lock)
	}
	if lock := push(3, 0); lock != Unlocked {
		t.Fatalf("push with no minimum: %q, want unlocked", lock)
	}
}
