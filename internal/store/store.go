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
	`ALTER TABLE challenges ADD COLUMN display_username TEXT NOT NULL DEFAULT '';
	ALTER TABLE challenges ADD COLUMN type TEXT NOT NULL DEFAULT '';`,
	`ALTER TABLE users ADD COLUMN last_push_at INTEGER;
	CREATE TABLE alerts (
		id                BLOB PRIMARY KEY CHECK (length(id) = 16),
		recipient_user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
		challenge_id      BLOB NOT NULL REFERENCES challenges(id) ON DELETE CASCADE,
		created_at        INTEGER NOT NULL,
		UNIQUE (recipient_user_id, challenge_id)
	) STRICT;
	CREATE INDEX alerts_by_recipient ON alerts (recipient_user_id, created_at);`,
}

type Store struct {
	db *sql.DB
}

// Open opens the database at path, creating the file and migrating the
// schema to the current version if needed.
func Open(path string) (*Store, error) {
	// _txlock=immediate takes the write lock at BEGIN, so concurrent
	// read-then-write transactions wait on busy_timeout instead of failing
	// SQLITE_BUSY when one upgrades after another has written.
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_txlock=immediate"
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

// ChallengeStatus is a challenge's state in the challenges table.
type ChallengeStatus string

const (
	ChallengePending  ChallengeStatus = "pending"
	ChallengeApproved ChallengeStatus = "approved"
	ChallengeDenied   ChallengeStatus = "denied"
	ChallengeExpired  ChallengeStatus = "expired"
)

var (
	ErrChallengeNotFound   = errors.New("challenge unknown or belongs to another user")
	ErrChallengeNotPending = errors.New("challenge already answered or expired")
)

// Challenge is one push: what Authentik's /auth call asked the user to
// approve. The display fields are stored as Authentik sent them.
type Challenge struct {
	ID              []byte
	UserID          string
	DisplayUsername string
	IPAddr          string
	PushInfo        string
	Type            string
	CreatedAt       time.Time
	ExpiresAt       time.Time
}

// Outcome is how a challenge ended. Reason is set only for a denial.
type Outcome struct {
	Status ChallengeStatus
	Reason string
}

// Limits gate pushes for a user since that user's last successful login.
type Limits struct {
	// PushCap is how many pushes a user gets before Cooldown applies.
	PushCap int
	// Cooldown is the least time between pushes once PushCap is reached.
	Cooldown time.Duration
	// MaxFailed failed attempts disable the user's device.
	MaxFailed int
}

// Lock is why StartPush refused a push; empty when it created one.
type Lock string

const (
	Unlocked     Lock = ""
	LockDisabled Lock = "disabled"
	LockPaused   Lock = "paused"
	LockCapped   Lock = "capped"
)

// StartPush stores c as a pending challenge and counts it as a push for
// c.UserID, unless lim or a pause refuses it at c.CreatedAt. A refused push
// stores nothing and changes no counter. It returns ErrNoDevice if the user
// has no enrolled device.
func (s *Store) StartPush(ctx context.Context, c Challenge, lim Limits) (Lock, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	var pushes, failed int
	var pausedUntil, lastPush sql.NullInt64
	err = tx.QueryRowContext(ctx,
		`SELECT u.pushes_since_success, u.failed_attempts, u.paused_until, u.last_push_at
		 FROM users u JOIN devices d ON d.user_id = u.user_id WHERE u.user_id = ?`,
		c.UserID).Scan(&pushes, &failed, &pausedUntil, &lastPush)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNoDevice
	}
	if err != nil {
		return "", err
	}
	now := c.CreatedAt.Unix()
	switch {
	case failed >= lim.MaxFailed:
		return LockDisabled, nil
	case pausedUntil.Valid && now < pausedUntil.Int64:
		return LockPaused, nil
	case pushes >= lim.PushCap && lastPush.Valid && now < lastPush.Int64+int64(lim.Cooldown/time.Second):
		return LockCapped, nil
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE users SET pushes_since_success = pushes_since_success + 1, last_push_at = ? WHERE user_id = ?`,
		now, c.UserID); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO challenges (id, user_id, display_username, ipaddr, pushinfo, type, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.UserID, c.DisplayUsername, c.IPAddr, c.PushInfo, c.Type, now, c.ExpiresAt.Unix()); err != nil {
		return "", err
	}
	return Unlocked, tx.Commit()
}

const challengeColumns = `id, user_id, display_username, ipaddr, pushinfo, type, created_at, expires_at`

func scanChallenge(row interface{ Scan(...any) error }) (Challenge, error) {
	var c Challenge
	var created, expires int64
	err := row.Scan(&c.ID, &c.UserID, &c.DisplayUsername, &c.IPAddr, &c.PushInfo, &c.Type, &created, &expires)
	c.CreatedAt, c.ExpiresAt = time.Unix(created, 0), time.Unix(expires, 0)
	return c, err
}

// PendingChallenges returns userID's challenges that are pending and
// unexpired at now, oldest first.
func (s *Store) PendingChallenges(ctx context.Context, userID string, now time.Time) ([]Challenge, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+challengeColumns+` FROM challenges
		 WHERE user_id = ? AND status = 'pending' AND expires_at > ?
		 ORDER BY created_at, id`,
		userID, now.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Challenge
	for rows.Next() {
		c, err := scanChallenge(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// PendingChallenge returns challenge id if it belongs to userID and is
// pending and unexpired at now; otherwise ErrChallengeNotFound.
func (s *Store) PendingChallenge(ctx context.Context, id []byte, userID string, now time.Time) (Challenge, error) {
	c, err := scanChallenge(s.db.QueryRowContext(ctx,
		`SELECT `+challengeColumns+` FROM challenges
		 WHERE id = ? AND user_id = ? AND status = 'pending' AND expires_at > ?`,
		id, userID, now.Unix()))
	if errors.Is(err, sql.ErrNoRows) {
		return Challenge{}, ErrChallengeNotFound
	}
	return c, err
}

// Fraud is what a not_me deny does: it pauses the user's pushes until
// PausedUntil and alerts every enrolled user whose username is in
// AlertRecipients.
type Fraud struct {
	PausedUntil     time.Time
	AlertRecipients []string
}

// AnswerChallenge moves userID's challenge id from pending to answer's
// status, once: only while it is pending and unexpired at now. In the same
// transaction an approval resets the user's push and failed-attempt counts,
// any deny adds a failed attempt, and a not_me deny also applies fraud. It
// returns ErrChallengeNotFound if no such challenge belongs to userID and
// ErrChallengeNotPending if it was already answered or has expired.
func (s *Store) AnswerChallenge(ctx context.Context, id []byte, userID string, answer Outcome, now time.Time, fraud Fraud) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var reason sql.NullString
	if answer.Reason != "" {
		reason = sql.NullString{String: answer.Reason, Valid: true}
	}
	res, err := tx.ExecContext(ctx,
		`UPDATE challenges SET status = ?, reason = ?, answered_at = ?
		 WHERE id = ? AND user_id = ? AND status = 'pending' AND expires_at > ?`,
		string(answer.Status), reason, now.Unix(), id, userID, now.Unix())
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		var exists bool
		err = tx.QueryRowContext(ctx,
			`SELECT EXISTS (SELECT 1 FROM challenges WHERE id = ? AND user_id = ?)`, id, userID).Scan(&exists)
		if err != nil {
			return err
		}
		if !exists {
			return ErrChallengeNotFound
		}
		return ErrChallengeNotPending
	}

	if answer.Status == ChallengeApproved {
		_, err = tx.ExecContext(ctx, `UPDATE users SET pushes_since_success = 0, failed_attempts = 0 WHERE user_id = ?`, userID)
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE users SET failed_attempts = failed_attempts + 1 WHERE user_id = ?`, userID)
	}
	if err != nil {
		return err
	}
	if answer.Reason == "not_me" {
		if err := applyFraud(ctx, tx, id, userID, now, fraud); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func applyFraud(ctx context.Context, tx *sql.Tx, id []byte, userID string, now time.Time, fraud Fraud) error {
	if _, err := tx.ExecContext(ctx, `UPDATE users SET paused_until = ? WHERE user_id = ?`, fraud.PausedUntil.Unix(), userID); err != nil {
		return err
	}
	for _, username := range fraud.AlertRecipients {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO alerts (id, recipient_user_id, challenge_id, created_at)
			 SELECT randomblob(16), u.user_id, ?, ?
			 FROM users u JOIN devices d ON d.user_id = u.user_id WHERE u.username = ?
			 ON CONFLICT DO NOTHING`,
			id, now.Unix(), username); err != nil {
			return err
		}
	}
	return nil
}

// CloseChallenge expires challenge id if it is still pending, counting that
// as a failed attempt for its user, and returns how it ended.
func (s *Store) CloseChallenge(ctx context.Context, id []byte) (Outcome, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Outcome{}, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE challenges SET status = 'expired' WHERE id = ? AND status = 'pending'`, id)
	if err != nil {
		return Outcome{}, err
	}
	if n, err := res.RowsAffected(); err != nil {
		return Outcome{}, err
	} else if n == 1 {
		if _, err := tx.ExecContext(ctx,
			`UPDATE users SET failed_attempts = failed_attempts + 1
			 WHERE user_id = (SELECT user_id FROM challenges WHERE id = ?)`, id); err != nil {
			return Outcome{}, err
		}
	}
	var o Outcome
	var reason sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT status, reason FROM challenges WHERE id = ?`, id).Scan(&o.Status, &reason); err != nil {
		return Outcome{}, err
	}
	o.Reason = reason.String
	return o, tx.Commit()
}

// Alert tells a recipient that someone reported a push as not theirs. The
// sign-in's fields are the challenge's, as Authentik sent them.
type Alert struct {
	ID              []byte
	DisplayUsername string
	IPAddr          string
	PushInfo        string
	Type            string
	AttemptedAt     time.Time
	ReportedAt      time.Time
}

// Alerts returns recipientUserID's alerts created at or after since, oldest
// first.
func (s *Store) Alerts(ctx context.Context, recipientUserID string, since time.Time) ([]Alert, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT a.id, c.display_username, c.ipaddr, c.pushinfo, c.type, c.created_at, a.created_at
		 FROM alerts a JOIN challenges c ON c.id = a.challenge_id
		 WHERE a.recipient_user_id = ? AND a.created_at >= ?
		 ORDER BY a.created_at, a.id`,
		recipientUserID, since.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Alert
	for rows.Next() {
		var a Alert
		var attempted, reported int64
		if err := rows.Scan(&a.ID, &a.DisplayUsername, &a.IPAddr, &a.PushInfo, &a.Type, &attempted, &reported); err != nil {
			return nil, err
		}
		a.AttemptedAt, a.ReportedAt = time.Unix(attempted, 0), time.Unix(reported, 0)
		out = append(out, a)
	}
	return out, rows.Err()
}
