package attest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/frict-auth/frict-server/internal/fakephone"
)

var now = time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

const challenge = "ACTIVATIONCODE234567ABCDEF"

// statusFunc serves a fixed revocation list, or err, and counts loads.
type statusFunc struct {
	entries map[string]string
	err     error
	loads   int
}

func (s *statusFunc) Load(context.Context) (map[string]string, error) {
	s.loads++
	return s.entries, s.err
}

// submission is a phone's two keys and what their chains claim.
type submission struct {
	device, approval *ecdsa.PrivateKey
	att              fakephone.Attestation
	// approvalChainKey, when set, is the key the approval_key's chain
	// certifies instead of the approval_key.
	approvalChainKey *ecdsa.PrivateKey
}

func newSubmission(t *testing.T) *submission {
	t.Helper()
	att, err := fakephone.DefaultAttestation()
	if err != nil {
		t.Fatal(err)
	}
	return &submission{device: newKey(t), approval: newKey(t), att: att}
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func (s *submission) keys(t *testing.T) []Key {
	t.Helper()
	spki := func(k *ecdsa.PrivateKey) []byte {
		der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	chain := func(k *ecdsa.PrivateKey, auth int) [][]byte {
		c, err := s.att.Chain(&k.PublicKey, []byte(challenge), auth)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	approvalChainKey := s.approval
	if s.approvalChainKey != nil {
		approvalChainKey = s.approvalChainKey
	}
	return []Key{
		{Name: "device_key", SPKI: spki(s.device), Chain: chain(s.device, 0)},
		{Name: "approval_key", SPKI: spki(s.approval), Chain: chain(approvalChainKey, s.att.ApprovalAuth), UserAuth: true},
	}
}

// strictVerifier pins the shared test CA's root and allows the debug
// build.
func strictVerifier(t *testing.T, status StatusSource) *Verifier {
	t.Helper()
	ca, err := fakephone.SharedCA()
	if err != nil {
		t.Fatal(err)
	}
	roots, err := Digests(ca.RootSPKIHash())
	if err != nil {
		t.Fatal(err)
	}
	certs, err := Digests(fakephone.DebugSigningCert)
	if err != nil {
		t.Fatal(err)
	}
	return &Verifier{Mode: Strict, Roots: roots, Packages: []string{fakephone.DebugPackage}, SigningCerts: certs, Status: status}
}

func wantRejection(t *testing.T, err error, key, reason string) {
	t.Helper()
	var r *Rejection
	if !errors.As(err, &r) || r.Key != key || r.Reason != reason {
		t.Fatalf("Verify = %v, want %s rejected for %s", err, key, reason)
	}
}

func TestAcceptsGenuineSubmission(t *testing.T) {
	for name, auth := range map[string]int{
		"fingerprint or screen lock": fakephone.AuthFingerprintOrScreenLock,
		"fingerprint only":           fakephone.AuthFingerprintOnly,
	} {
		for _, level := range []int{fakephone.TEE, fakephone.StrongBox} {
			t.Run(name, func(t *testing.T) {
				s := newSubmission(t)
				s.att.ApprovalAuth, s.att.SecurityLevel = auth, level
				status := &statusFunc{entries: map[string]string{}}
				if err := strictVerifier(t, status).Verify(context.Background(), now, []byte(challenge), s.keys(t)...); err != nil {
					t.Fatalf("level %d: %v", level, err)
				}
				if status.loads != 1 {
					t.Fatalf("revocation list loaded %d times, want 1", status.loads)
				}
			})
		}
	}
}

func TestRejects(t *testing.T) {
	other, err := fakephone.NewCA(time.Date(2045, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	expiredIntermediate, err := fakephone.NewCA(time.Date(2045, 1, 1, 0, 0, 0, 0, time.UTC), now.Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name        string
		change      func(t *testing.T, s *submission)
		key, reason string
	}{
		{"chain to another root", func(t *testing.T, s *submission) { s.att.CA = other }, "device_key", ReasonUntrustedRoot},
		{"expired intermediate", func(t *testing.T, s *submission) { s.att.CA = expiredIntermediate }, "device_key", ReasonOutsideValidity},
		{"chain certifies another key", func(t *testing.T, s *submission) { s.approvalChainKey = newKey(t) }, "approval_key", ReasonKeyMismatch},
		{"software key", func(t *testing.T, s *submission) { s.att.SecurityLevel = fakephone.Software }, "device_key", ReasonSecurityLevel},
		{"other package", func(t *testing.T, s *submission) { s.att.Package = "app.frict.android.evil" }, "device_key", ReasonPackage},
		{"other signing certificate", func(t *testing.T, s *submission) {
			s.att.SigningCert = "00" + fakephone.DebugSigningCert[2:]
		}, "device_key", ReasonSigningCert},
		{"approval_key without user auth", func(t *testing.T, s *submission) { s.att.ApprovalAuth = 0 }, "approval_key", ReasonUserAuth},
		{"approval_key unlocked by screen lock only", func(t *testing.T, s *submission) { s.att.ApprovalAuth = 1 }, "approval_key", ReasonUserAuth},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := newSubmission(t)
			c.change(t, s)
			status := &statusFunc{entries: map[string]string{}}
			v := strictVerifier(t, status)
			alsoPinned, _ := Digests(expiredIntermediate.RootSPKIHash())
			v.Roots = append(v.Roots, alsoPinned...)
			wantRejection(t, v.Verify(context.Background(), now, []byte(challenge), s.keys(t)...), c.key, c.reason)
			if status.loads != 0 {
				t.Fatal("loaded the revocation list for a chain that failed an offline check")
			}
		})
	}
}

func TestRejectsOtherChallenge(t *testing.T) {
	keys := newSubmission(t).keys(t)
	err := strictVerifier(t, &statusFunc{}).Verify(context.Background(), now, []byte("ANOTHERCODE"), keys...)
	wantRejection(t, err, "device_key", ReasonChallengeMismatch)
}

func TestRejectsDeviceKeyRequiringUser(t *testing.T) {
	keys := newSubmission(t).keys(t)
	keys[0].Chain = keys[1].Chain
	keys[0].SPKI = keys[1].SPKI
	err := strictVerifier(t, &statusFunc{}).Verify(context.Background(), now, []byte(challenge), keys...)
	wantRejection(t, err, "device_key", ReasonUserAuth)
}

func TestRejectsMalformedChains(t *testing.T) {
	keys := newSubmission(t).keys(t)
	for name, chain := range map[string][][]byte{
		"leaf only":       keys[0].Chain[:1],
		"not DER":         {[]byte("leaf"), []byte("root")},
		"out of order":    {keys[0].Chain[0], keys[0].Chain[2], keys[0].Chain[1]},
		"no key attested": {keys[0].Chain[1], keys[0].Chain[2]},
	} {
		t.Run(name, func(t *testing.T) {
			k := keys[0]
			k.Chain = chain
			if name == "no key attested" {
				k.SPKI = mustParse(t, chain[0]).RawSubjectPublicKeyInfo
			}
			var r *Rejection
			if err := strictVerifier(t, &statusFunc{}).Verify(context.Background(), now, []byte(challenge), k); !errors.As(err, &r) {
				t.Fatalf("Verify = %v, want a rejection", err)
			}
		})
	}
}

func mustParse(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Google's guidance: keep trusting a pinned root's key whatever its
// certificate's validity period says.
func TestAcceptsExpiredRootCertificate(t *testing.T) {
	ca, err := fakephone.NewCA(now.Add(-time.Hour), time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	s := newSubmission(t)
	s.att.CA = ca
	v := strictVerifier(t, &statusFunc{entries: map[string]string{}})
	v.Roots, _ = Digests(ca.RootSPKIHash())
	if err := v.Verify(context.Background(), now, []byte(challenge), s.keys(t)...); err != nil {
		t.Fatal(err)
	}
}

func TestRejectsRevokedCertificate(t *testing.T) {
	ca, err := fakephone.SharedCA()
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range []string{"REVOKED", "SUSPENDED"} {
		status := &statusFunc{entries: map[string]string{ca.Intermediate.SerialNumber.Text(16): st}}
		err := strictVerifier(t, status).Verify(context.Background(), now, []byte(challenge), newSubmission(t).keys(t)...)
		wantRejection(t, err, "device_key", ReasonRevoked)
	}
}

func TestStatusUnavailableIsNotARejection(t *testing.T) {
	err := strictVerifier(t, &statusFunc{err: errors.New("no route")}).Verify(context.Background(), now, []byte(challenge), newSubmission(t).keys(t)...)
	var r *Rejection
	if !errors.Is(err, ErrStatusUnavailable) || errors.As(err, &r) {
		t.Fatalf("Verify = %v, want ErrStatusUnavailable", err)
	}
}

func TestEmulatorModeAcceptsSoftwareKeysUnderAnyRoot(t *testing.T) {
	other, err := fakephone.NewCA(now.Add(-time.Hour), now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	s := newSubmission(t)
	s.att.CA, s.att.SecurityLevel = other, fakephone.Software
	status := &statusFunc{err: errors.New("must not be loaded")}
	v := strictVerifier(t, status)
	v.Mode = Emulator
	if err := v.Verify(context.Background(), now, []byte(challenge), s.keys(t)...); err != nil {
		t.Fatal(err)
	}
	s.att.Package = "app.frict.android.evil"
	wantRejection(t, v.Verify(context.Background(), now, []byte(challenge), s.keys(t)...), "device_key", ReasonPackage)
	if status.loads != 0 {
		t.Fatal("emulator mode loaded the revocation list")
	}
}

func TestEmptySigningCertsRejectEverything(t *testing.T) {
	v := strictVerifier(t, &statusFunc{entries: map[string]string{}})
	v.SigningCerts = nil
	wantRejection(t, v.Verify(context.Background(), now, []byte(challenge), newSubmission(t).keys(t)...), "device_key", ReasonSigningCert)
}

func TestParseMode(t *testing.T) {
	for in, want := range map[string]struct {
		mode  Mode
		known bool
	}{
		"":          {Strict, true},
		"strict":    {Strict, true},
		"emulator":  {Emulator, true},
		"Emulator":  {Strict, false},
		"off":       {Strict, false},
		"emulator ": {Strict, false},
	} {
		if m, known := ParseMode(in); m != want.mode || known != want.known {
			t.Errorf("ParseMode(%q) = %s, %v, want %s, %v", in, m, known, want.mode, want.known)
		}
	}
}

func TestGoogleRootsDecode(t *testing.T) {
	if d, err := Digests(GoogleRoots...); err != nil || len(d) != 2 {
		t.Fatalf("GoogleRoots: %d digests, %v", len(d), err)
	}
}

// TestGoogleChains verifies genuine chains (testdata/README.md) to
// Google's pinned roots, at a time inside their short-lived
// certificates' validity.
func TestGoogleChains(t *testing.T) {
	const sampleApp = "com.google.android.attestation"
	sampleCert := "103938ee4537e59e8ee792f654504fb8346fc6b346d0bbc4415fc339fcfc8ec1"
	for _, c := range []struct {
		file, challenge string
		at              time.Time
	}{
		{"caiman_sdk36_TEE_EC_RKP", "d688d763-6118-4ca6-94b2-e6cd9ed7e4e4", time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC)},
		{"caiman_sdk36_SB_EC_RKP", "7ccac1ea-4845-482e-858d-f6fa9aa8c295", time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC)},
		{"frankel_sdk37_TEE_EC_2026", "146aaf16-7814-4e44-acdb-e5d652a7b602", time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)},
	} {
		t.Run(c.file, func(t *testing.T) {
			chain := readPEMChain(t, "testdata/"+c.file+".pem")
			roots, err := Digests(GoogleRoots...)
			if err != nil {
				t.Fatal(err)
			}
			certs, _ := Digests(sampleCert)
			k := Key{Name: "device_key", SPKI: mustParse(t, chain[0]).RawSubjectPublicKeyInfo, Chain: chain}
			v := &Verifier{Mode: Strict, Roots: roots, Packages: []string{sampleApp}, SigningCerts: certs, Status: &statusFunc{entries: map[string]string{}}}
			if err := v.Verify(context.Background(), c.at, []byte(c.challenge), k); err != nil {
				t.Fatalf("genuine chain: %v", err)
			}
			wantRejection(t, v.Verify(context.Background(), now, []byte(c.challenge), k), "device_key", ReasonOutsideValidity)
			v.Packages = []string{"app.frict.android"}
			wantRejection(t, v.Verify(context.Background(), c.at, []byte(c.challenge), k), "device_key", ReasonPackage)
			k.UserAuth = true
			v.Packages = []string{sampleApp}
			wantRejection(t, v.Verify(context.Background(), c.at, []byte(c.challenge), k), "device_key", ReasonUserAuth)
		})
	}
}

func readPEMChain(t *testing.T, path string) [][]byte {
	t.Helper()
	rest, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var chain [][]byte
	for {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		chain = append(chain, b.Bytes)
	}
	if len(chain) < 2 {
		t.Fatalf("%s: %d certificates", path, len(chain))
	}
	return chain
}
