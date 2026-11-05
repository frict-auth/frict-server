package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
