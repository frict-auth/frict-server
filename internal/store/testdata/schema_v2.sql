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
		reason      TEXT CHECK (reason IN ('not_me', 'cancel')), display_username TEXT NOT NULL DEFAULT '', type TEXT NOT NULL DEFAULT '',
		CHECK ((status = 'denied') = (reason IS NOT NULL)),
		CHECK ((status IN ('approved', 'denied')) = (answered_at IS NOT NULL))
	) STRICT;

CREATE TABLE devices (
		user_id      TEXT PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
		device_key   BLOB NOT NULL,
		approval_key BLOB NOT NULL,
		attestation  BLOB NOT NULL,
		fid          TEXT,
		enrolled_at  INTEGER NOT NULL
	) STRICT;

CREATE TABLE users (
		user_id               TEXT PRIMARY KEY,
		username              TEXT NOT NULL,
		activation_hash       BLOB UNIQUE,
		activation_expires_at INTEGER,
		created_at            INTEGER NOT NULL,
		pushes_since_success  INTEGER NOT NULL DEFAULT 0 CHECK (pushes_since_success >= 0),
		failed_attempts       INTEGER NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
		paused_until          INTEGER
	) STRICT;
