package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/frict-auth/frict-server/internal/attest"
	"github.com/frict-auth/frict-server/internal/fakephone"
	"github.com/frict-auth/frict-server/internal/store"
)

// fakeRevocation is a revocation list a test can change or take down.
type fakeRevocation struct {
	mu      sync.Mutex
	entries map[string]string
	err     error
}

func (r *fakeRevocation) Load(context.Context) (map[string]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.entries, r.err
}

func (r *fakeRevocation) set(entries map[string]string, err error) {
	r.mu.Lock()
	r.entries, r.err = entries, err
	r.mu.Unlock()
}

// testAttestation is strict, pins fakephone's shared root and allows its
// debug build.
func testAttestation(t *testing.T, status attest.StatusSource) *attest.Verifier {
	t.Helper()
	ca, err := fakephone.SharedCA()
	if err != nil {
		t.Fatal(err)
	}
	roots, err := attest.Digests(ca.RootSPKIHash())
	if err != nil {
		t.Fatal(err)
	}
	certs, err := attest.Digests(fakephone.DebugSigningCert)
	if err != nil {
		t.Fatal(err)
	}
	return &attest.Verifier{Mode: attest.Strict, Roots: roots, Packages: []string{fakephone.DebugPackage}, SigningCerts: certs, Status: status}
}

// TestDeviceEnrollRejectsBadAttestation: each bad attestation is a 401
// that leaves the code unspent, with one security line naming the reason
// and the key and holding no certificate.
func TestDeviceEnrollRejectsBadAttestation(t *testing.T) {
	other, err := fakephone.NewCA(time.Date(2045, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, reason, key string
		change            func(*fakephone.Attestation)
	}{
		{"another root", attest.ReasonUntrustedRoot, "device_key", func(a *fakephone.Attestation) { a.CA = other }},
		{"software keys", attest.ReasonSecurityLevel, "device_key", func(a *fakephone.Attestation) { a.SecurityLevel = fakephone.Software }},
		{"release package", attest.ReasonPackage, "device_key", func(a *fakephone.Attestation) { a.Package = "app.frict.android" }},
		{"other signer", attest.ReasonSigningCert, "device_key", func(a *fakephone.Attestation) { a.SigningCert = strings.Repeat("ab", 32) }},
		{"approval_key without user auth", attest.ReasonUserAuth, "approval_key", func(a *fakephone.Attestation) { a.ApprovalAuth = 0 }},
		{"keys made for another code", attest.ReasonChallengeMismatch, "device_key", func(a *fakephone.Attestation) { a.Challenge = "ANOTHERCODE" }},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, logs := newLoggedFixture(t)
			a := f.enroll("alice")
			phone := newPhone(t)
			c.change(&phone.Attestation)
			skip := lineCount(logs)
			r := must[*http.Request](t)(phone.EnrollRequest(a, f.now()))
			body := must[[]byte](t)(io.ReadAll(r.Body))
			r.Body = io.NopCloser(bytes.NewReader(body))
			var sent struct {
				Attestation map[string][]string `json:"attestation"`
			}
			if err := json.Unmarshal(body, &sent); err != nil {
				t.Fatal(err)
			}
			f.rejectEnroll(r, a)
			if got := f.status(a); got != "waiting" {
				t.Fatalf("after a rejected attestation: %q, want waiting", got)
			}
			lines := securityLines(t, logs, skip)
			if len(lines) != 1 {
				t.Fatalf("%d security lines, want 1: %v", len(lines), lines)
			}
			want := map[string]any{"event": "attestation_rejected", "endpoint": fakephone.EnrollPath, "reason": c.reason, "key": c.key, "user_id": a.UserID, "client_ip": "192.0.2.1"}
			for k, v := range want {
				if lines[0][k] != v {
					t.Errorf("security line %v: %s = %v, want %v", lines[0], k, lines[0][k], v)
				}
			}
			out := logs.String()
			for _, chain := range sent.Attestation {
				for _, cert := range chain {
					if strings.Contains(out, cert[:40]) {
						t.Errorf("logs hold a certificate the phone sent:\n%s", out)
					}
				}
			}
			if strings.Contains(out, "Android Keystore Key") {
				t.Errorf("logs hold a certificate's subject:\n%s", out)
			}
		})
	}
}

func TestDeviceEnrollRejectsRevokedCertificate(t *testing.T) {
	f := newFixture(t)
	ca, err := fakephone.SharedCA()
	if err != nil {
		t.Fatal(err)
	}
	f.revocation.set(map[string]string{ca.Intermediate.SerialNumber.Text(16): "REVOKED"}, nil)
	a := f.enroll("alice")
	f.rejectEnroll(must[*http.Request](t)(newPhone(t).EnrollRequest(a, f.now())), a)
}

// Without the revocation list a genuine enrollment is a 503 that leaves the
// code unspent, so the phone can retry once the list is back.
func TestDeviceEnrollWaitsForRevocationList(t *testing.T) {
	f, logs := newLoggedFixture(t)
	f.revocation.set(nil, errors.New("dial tcp: no route to host"))
	a := f.enroll("alice")
	phone := newPhone(t)
	skip := lineCount(logs)
	w := f.serve(must[*http.Request](t)(phone.EnrollRequest(a, f.now())))
	if w.Code != http.StatusServiceUnavailable || strings.TrimSpace(w.Body.String()) != `{"error":"unavailable"}` {
		t.Fatalf("enroll without the list: %d %s, want 503 unavailable", w.Code, w.Body)
	}
	if _, err := f.st.DeviceOf(context.Background(), a.UserID); !errors.Is(err, store.ErrNoDevice) {
		t.Fatalf("enrolled without the revocation list (err %v)", err)
	}
	if lines := securityLines(t, logs, skip); len(lines) != 0 {
		t.Fatalf("an unavailable list is not the phone's fault, yet: %v", lines)
	}
	if !strings.Contains(logs.String(), "no route to host") {
		t.Fatalf("the error isn't logged:\n%s", logs)
	}
	f.revocation.set(map[string]string{}, nil)
	if w := f.serve(must[*http.Request](t)(phone.EnrollRequest(a, f.now()))); w.Code != http.StatusOK {
		t.Fatalf("retry once the list is back: %d %s, want 200", w.Code, w.Body)
	}
}
