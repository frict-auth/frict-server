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
// current one and requires Open to bring it to the current schema. With one
// schema version, the only prior one is the empty database.
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
		{"negative failed_attempts", `UPDATE users SET failed_attempts = -1 WHERE user_id = 'DU1'`, false},
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

func TestDeletingUserRemovesDeviceAndChallenges(t *testing.T) {
	s, _ := openTemp(t)
	for _, stmt := range []string{
		`INSERT INTO users (user_id, username, created_at) VALUES ('DU1', 'alice', 1)`,
		`INSERT INTO devices (user_id, device_key, approval_key, attestation, enrolled_at) VALUES ('DU1', x'01', x'02', x'03', 1)`,
		`INSERT INTO challenges (id, user_id, ipaddr, pushinfo, created_at, expires_at) VALUES (x'00112233445566778899aabbccddeeff', 'DU1', '', '', 100, 160)`,
		`DELETE FROM users WHERE user_id = 'DU1'`,
	} {
		if _, err := s.db.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	for _, table := range []string{"devices", "challenges"} {
		var n int
		if err := s.db.QueryRow(`SELECT count(*) FROM ` + table).Scan(&n); err != nil || n != 0 {
			t.Fatalf("%s rows after deleting the user = %d err:%v, want 0", table, n, err)
		}
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
