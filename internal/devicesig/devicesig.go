// Package devicesig verifies Frict-P256 signatures on device API requests,
// as specified in docs/device-protocol.md.
package devicesig

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	tag    = "frict-device-v1"
	scheme = "Frict-P256 "

	// MaxSkew is how far a request's unix_seconds may be from the server's
	// clock, either way.
	MaxSkew = 5 * time.Minute

	userIDLen = len("DU") + 26
)

var (
	ErrMissingCredentials = errors.New("missing Authorization header")
	ErrMalformedHeader    = errors.New("malformed Authorization header")
	ErrStale              = errors.New("unix_seconds outside allowed clock skew")
	ErrBadSignature       = errors.New("signature does not verify")
)

// KeyFunc returns the public key that must have signed a request carrying
// userID in its Authorization header.
type KeyFunc func(userID string) (*ecdsa.PublicKey, error)

// Verify checks r's Authorization header against body, in the order the
// protocol fixes: header format, freshness against now, then the signature
// with the key keyFor returns. It returns the header's user_id.
func Verify(r *http.Request, body []byte, now time.Time, keyFor KeyFunc) (string, error) {
	userID, unix, sig, err := parseAuthorization(r.Header.Get("Authorization"))
	if err != nil {
		return "", err
	}
	if skew := now.Sub(time.Unix(unix, 0)); skew > MaxSkew || skew < -MaxSkew {
		return "", fmt.Errorf("%w: %s", ErrStale, skew)
	}
	key, err := keyFor(userID)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(SignedBytes(userID, unix, r.URL.Path, body))
	if !ecdsa.VerifyASN1(key, digest[:], sig) {
		return "", ErrBadSignature
	}
	return userID, nil
}

// SignedBytes is the byte string a device signs for one request.
func SignedBytes(userID string, unix int64, path string, body []byte) []byte {
	head := tag + "\n" + userID + "\n" + strconv.FormatInt(unix, 10) + "\n" + path + "\n"
	return append([]byte(head), body...)
}

// ValidUserID reports whether id is "DU" followed by 26 base32 characters,
// the form /auth/v2/enroll issues.
func ValidUserID(id string) bool {
	if len(id) != userIDLen || !strings.HasPrefix(id, "DU") {
		return false
	}
	for _, c := range id[2:] {
		if !(c >= 'A' && c <= 'Z' || c >= '2' && c <= '7') {
			return false
		}
	}
	return true
}

func parseAuthorization(h string) (userID string, unix int64, sig []byte, err error) {
	if h == "" {
		return "", 0, nil, ErrMissingCredentials
	}
	creds, ok := strings.CutPrefix(h, scheme)
	if !ok {
		return "", 0, nil, fmt.Errorf("%w: scheme is not Frict-P256", ErrMalformedHeader)
	}
	parts := strings.Split(creds, ":")
	if len(parts) != 3 {
		return "", 0, nil, fmt.Errorf("%w: want user_id:unix_seconds:signature", ErrMalformedHeader)
	}
	if !ValidUserID(parts[0]) {
		return "", 0, nil, fmt.Errorf("%w: user_id", ErrMalformedHeader)
	}
	if !allDigits(parts[1]) || len(parts[1]) > 12 {
		return "", 0, nil, fmt.Errorf("%w: unix_seconds", ErrMalformedHeader)
	}
	unix, err = strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return "", 0, nil, fmt.Errorf("%w: unix_seconds: %v", ErrMalformedHeader, err)
	}
	sig, err = base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(sig) == 0 {
		return "", 0, nil, fmt.Errorf("%w: signature encoding", ErrMalformedHeader)
	}
	return parts[0], unix, sig, nil
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
