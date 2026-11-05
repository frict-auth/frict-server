// Package store holds Frict's users, devices and challenges in SQLite.
package store

import (
	"context"
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

// migrations[i] moves the schema from PRAGMA user_version i to i+1. Append
// only: deployed databases have already applied the earlier entries, and
// testdata/schema_v<N>.sql freezes each version's result.
var migrations = []string{
	`CREATE TABLE users (
		user_id               TEXT PRIMARY KEY,
		username              TEXT NOT NULL,
		activation_hash       BLOB UNIQUE,
		activation_expires_at INTEGER,
		created_at            INTEGER NOT NULL,
		pushes_since_success  INTEGER NOT NULL DEFAULT 0 CHECK (pushes_since_success >= 0),
		failed_attempts       INTEGER NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
		paused_until          INTEGER
	) STRICT;
	CREATE TABLE devices (
		user_id      TEXT PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
		device_key   BLOB NOT NULL,
		approval_key BLOB NOT NULL,
		attestation  BLOB NOT NULL,
		fid          TEXT,
		enrolled_at  INTEGER NOT NULL
	) STRICT;
	CREATE TABLE challenges (
		id          BLOB PRIMARY KEY CHECK (length(id) = 16),
		user_id     TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
		ipaddr      TEXT NOT NULL,
		pushinfo    TEXT NOT NULL,
		status      TEXT NOT NULL DEFAULT 'pending'
		            CHECK (status IN ('pending', 'approved', 'denied', 'expired')),
		created_at  INTEGER NOT NULL,
		expires_at  INTEGER NOT NULL CHECK (expires_at > created_at),
		answered_at INTEGER,
		reason      TEXT CHECK (reason IN ('not_me', 'cancel')),
		CHECK ((status = 'denied') = (reason IS NOT NULL)),
		CHECK ((status IN ('approved', 'denied')) = (answered_at IS NOT NULL))
	) STRICT;`,
}

type Store struct {
	db *sql.DB
}

// Open opens the database at path, creating the file and migrating the
// schema to the current version if needed.
func Open(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate %s: %w", path, err)
	}
	return &Store{db: db}, nil
}

func migrate(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var version int
	if err := tx.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	if version > len(migrations) {
		return fmt.Errorf("database is at schema version %d, newer than this binary's %d", version, len(migrations))
	}
	for i := version; i < len(migrations); i++ {
		if _, err := tx.Exec(migrations[i]); err != nil {
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
	}
	if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, len(migrations))); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

func (s *Store) Close() error { return s.db.Close() }
