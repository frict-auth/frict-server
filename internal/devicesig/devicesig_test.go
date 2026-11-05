package devicesig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/frict-auth/frict-server/internal/fakephone"
)

const (
	alice = "DUAAAAAAAAAAAAAAAAAAAAAAAAAA"
	bob   = "DUBBBBBBBBBBBBBBBBBBBBBBBBBB"
	body  = `{"activation_code":"X"}`
)

var now = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// schemeSig signs SignedBytes as this package builds them: what an attacker
// who knows the server's actual scheme would sign.
func schemeSig(t *testing.T, key *ecdsa.PrivateKey, userID string, unix int64, path, body string) string {
	t.Helper()
	d := sha256.Sum256(SignedBytes(userID, unix, path, []byte(body)))
	der, err := ecdsa.SignASN1(rand.Reader, key, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(der)
}

func request(path, authorization, body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "https://api.frict.test"+path, strings.NewReader(body))
	if authorization != "" {
		r.Header.Set("Authorization", authorization)
	}
	return r
}

func header(userID string, unix int64, sig string) string {
	return fmt.Sprintf("Frict-P256 %s:%d:%s", userID, unix, sig)
}

// The layout is copied from docs/device-protocol.md "Request signing".
func TestSignedBytesLayout(t *testing.T) {
	got := string(SignedBytes(alice, 1762345678, "/device/v1/enroll", []byte("{\"a\":\n1}")))
	want := "frict-device-v1\n" + alice + "\n1762345678\n/device/v1/enroll\n{\"a\":\n1}"
	if got != want {
		t.Fatalf("signed bytes\n%q\nwant\n%q", got, want)
	}
}

func TestVerifyAcceptsFakePhone(t *testing.T) {
	phone, err := fakephone.New()
	if err != nil {
		t.Fatal(err)
	}
	r, err := fakephone.SignedRequest("https://api.frict.test", fakephone.EnrollPath, alice, now.Unix(), []byte(body), phone.DeviceKey)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verify(r, []byte(body), now, func(string) (*ecdsa.PublicKey, error) { return &phone.DeviceKey.PublicKey, nil })
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got != alice {
		t.Fatalf("user_id = %q, want %q", got, alice)
	}
}

func TestVerifyFreshnessWindow(t *testing.T) {
	key := newKey(t)
	tests := []struct {
		name    string
		offset  time.Duration
		wantErr error
	}{
		{"now", 0, nil},
		{"4m59s old", -4*time.Minute - 59*time.Second, nil},
		{"4m59s ahead", 4*time.Minute + 59*time.Second, nil},
		{"5m1s old", -5*time.Minute - time.Second, ErrStale},
		{"5m1s ahead", 5*time.Minute + time.Second, ErrStale},
		{"a day old", -24 * time.Hour, ErrStale},
		{"epoch", -now.Sub(time.Unix(0, 0)), ErrStale},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			unix := now.Add(tc.offset).Unix()
			r := request(fakephone.EnrollPath, header(alice, unix, schemeSig(t, key, alice, unix, fakephone.EnrollPath, body)), body)
			_, err := Verify(r, []byte(body), now, func(string) (*ecdsa.PublicKey, error) { return &key.PublicKey, nil })
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Verify = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// A malformed user_id is rejected as a header error before any key is looked
// up, even when the signature over it is valid.
func TestVerifyRejectsMalformedUserIDBeforeSignature(t *testing.T) {
	key := newKey(t)
	for _, id := range []string{
		"",
		"DU",
		strings.ToLower(alice),
		"DX" + alice[2:],
		alice + "A",
		alice[:len(alice)-1],
		alice[:27] + "1",
		alice[:27] + "=",
		alice[:20] + "\n" + alice[21:],
		"DUAAAAAAAAAAAA AAAAAAAAAAAAA",
	} {
		t.Run(fmt.Sprintf("%q", id), func(t *testing.T) {
			unix := now.Unix()
			r := request(fakephone.EnrollPath, header(id, unix, schemeSig(t, key, id, unix, fakephone.EnrollPath, body)), body)
			looked := false
			_, err := Verify(r, []byte(body), now, func(string) (*ecdsa.PublicKey, error) {
				looked = true
				return &key.PublicKey, nil
			})
			if !errors.Is(err, ErrMalformedHeader) {
				t.Fatalf("Verify = %v, want ErrMalformedHeader", err)
			}
			if looked {
				t.Fatal("key was looked up for a malformed user_id")
			}
		})
	}
}

func TestVerifyRejects(t *testing.T) {
	key, other := newKey(t), newKey(t)
	unix := now.Unix()
	good := schemeSig(t, key, alice, unix, fakephone.EnrollPath, body)
	tests := []struct {
		name    string
		req     *http.Request
		wantErr error
	}{
		{"no header", request(fakephone.EnrollPath, "", body), ErrMissingCredentials},
		{"other scheme", request(fakephone.EnrollPath, "Basic "+alice+":1:"+good, body), ErrMalformedHeader},
		{"two fields", request(fakephone.EnrollPath, fmt.Sprintf("Frict-P256 %s:%d", alice, unix), body), ErrMalformedHeader},
		{"four fields", request(fakephone.EnrollPath, header(alice, unix, good)+":x", body), ErrMalformedHeader},
		{"signed unix_seconds", request(fakephone.EnrollPath, fmt.Sprintf("Frict-P256 %s:+%d:%s", alice, unix, good), body), ErrMalformedHeader},
		{"empty signature", request(fakephone.EnrollPath, header(alice, unix, ""), body), ErrMalformedHeader},
		{"padded signature", request(fakephone.EnrollPath, header(alice, unix, good+"="), body), ErrMalformedHeader},
		{"wrong key", request(fakephone.EnrollPath, header(alice, unix, schemeSig(t, other, alice, unix, fakephone.EnrollPath, body)), body), ErrBadSignature},
		{"user_id swapped", request(fakephone.EnrollPath, header(bob, unix, good), body), ErrBadSignature},
		{"unix_seconds changed", request(fakephone.EnrollPath, header(alice, unix-1, good), body), ErrBadSignature},
		{"signed for another path", request(fakephone.EnrollPath, header(alice, unix, schemeSig(t, key, alice, unix, "/device/v1/fid", body)), body), ErrBadSignature},
		{"body changed", request(fakephone.EnrollPath, header(alice, unix, good), body+" "), ErrBadSignature},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sent, err := io.ReadAll(tc.req.Body)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Verify(tc.req, sent, now, func(string) (*ecdsa.PublicKey, error) { return &key.PublicKey, nil })
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Verify = %v, want %v", err, tc.wantErr)
			}
		})
	}
}
