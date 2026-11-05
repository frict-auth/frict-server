// Package store holds Frict's users, devices and challenges in SQLite.
package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"time"

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

// EnrollmentStatus is Duo's enroll_status vocabulary.
type EnrollmentStatus string

const (
	EnrollmentSuccess EnrollmentStatus = "success"
	EnrollmentWaiting EnrollmentStatus = "waiting"
	EnrollmentInvalid EnrollmentStatus = "invalid"
)

var (
	ErrActivationInvalid = errors.New("activation code unknown or expired")
	ErrActivationUsed    = errors.New("activation code already used")
	ErrUserMismatch      = errors.New("activation code was issued for another user")
	ErrNoDevice          = errors.New("user has no enrolled device")
)

// Device is what a phone registers at enrollment. Keys are SPKI DER;
// Attestation is the request's attestation JSON as sent.
type Device struct {
	DeviceKey   []byte
	ApprovalKey []byte
	Attestation []byte
	FID         string
	EnrolledAt  time.Time
}

// activationHash is what the store keeps of an activation code. Codes carry
// 128 random bits, so an unsalted hash cannot be inverted by guessing.
func activationHash(code string) []byte {
	h := sha256.Sum256([]byte(code))
	return h[:]
}

// CreateEnrollment adds a user who can enroll one device with code until
// expires.
func (s *Store) CreateEnrollment(ctx context.Context, userID, username, code string, now, expires time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO users (user_id, username, activation_hash, activation_expires_at, created_at) VALUES (?, ?, ?, ?, ?)`,
		userID, username, activationHash(code), expires.Unix(), now.Unix())
	return err
}

// EnrollmentStatusOf reports success once a device has claimed code for
// userID, waiting while code is unclaimed and unexpired, and invalid for any
// other user_id and code pair.
func (s *Store) EnrollmentStatusOf(ctx context.Context, userID, code string, now time.Time) (EnrollmentStatus, error) {
	var expires int64
	var enrolled bool
	err := s.db.QueryRowContext(ctx,
		`SELECT u.activation_expires_at, d.user_id IS NOT NULL
		 FROM users u LEFT JOIN devices d ON d.user_id = u.user_id
		 WHERE u.user_id = ? AND u.activation_hash = ?`,
		userID, activationHash(code)).Scan(&expires, &enrolled)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return EnrollmentInvalid, nil
	case err != nil:
		return "", err
	case enrolled:
		return EnrollmentSuccess, nil
	case now.Unix() >= expires:
		return EnrollmentInvalid, nil
	}
	return EnrollmentWaiting, nil
}

// Enroll registers d for the user code was issued to. claimedUserID is the
// user the device's request names; it must be that same user. A code enrolls
// at most one device, and only before it expires.
func (s *Store) Enroll(ctx context.Context, code, claimedUserID string, d Device) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var userID string
	var expires int64
	err = tx.QueryRowContext(ctx,
		`SELECT user_id, activation_expires_at FROM users WHERE activation_hash = ?`,
		activationHash(code)).Scan(&userID, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrActivationInvalid
	}
	if err != nil {
		return err
	}
	if d.EnrolledAt.Unix() >= expires {
		return ErrActivationInvalid
	}
	if userID != claimedUserID {
		return ErrUserMismatch
	}
	res, err := tx.ExecContext(ctx,
		`INSERT INTO devices (user_id, device_key, approval_key, attestation, fid, enrolled_at)
		 VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (user_id) DO NOTHING`,
		userID, d.DeviceKey, d.ApprovalKey, d.Attestation, d.FID, d.EnrolledAt.Unix())
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrActivationUsed
	}
	return tx.Commit()
}

// DeviceOf returns userID's enrolled device.
func (s *Store) DeviceOf(ctx context.Context, userID string) (Device, error) {
	var d Device
	var fid sql.NullString
	var enrolled int64
	err := s.db.QueryRowContext(ctx,
		`SELECT device_key, approval_key, attestation, fid, enrolled_at FROM devices WHERE user_id = ?`,
		userID).Scan(&d.DeviceKey, &d.ApprovalKey, &d.Attestation, &fid, &enrolled)
	if errors.Is(err, sql.ErrNoRows) {
		return Device{}, ErrNoDevice
	}
	if err != nil {
		return Device{}, err
	}
	d.FID = fid.String
	d.EnrolledAt = time.Unix(enrolled, 0)
	return d, nil
}
