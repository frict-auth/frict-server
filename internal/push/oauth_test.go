package push

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

const testClientEmail = "fcm-sender@frict-test.iam.gserviceaccount.com"

// tokenEndpoint is a fake OAuth token_uri for the JWT bearer grant. It
// verifies each assertion against the service account's public key and
// answers with access tokens tok-1, tok-2, … that expire in expiresIn
// seconds.
type tokenEndpoint struct {
	t         *testing.T
	url       string
	pub       *rsa.PublicKey
	expiresIn int

	mu     sync.Mutex
	mints  int
	claims []map[string]any
}

func (e *tokenEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		e.t.Errorf("token request form: %v", err)
	}
	if g := r.PostForm.Get("grant_type"); g != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		e.t.Errorf("grant_type %q, want the JWT bearer grant", g)
	}
	claims, err := verifyRS256(r.PostForm.Get("assertion"), e.pub)
	if err != nil {
		e.t.Errorf("assertion: %v", err)
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
		return
	}
	e.mu.Lock()
	e.mints++
	n := e.mints
	e.claims = append(e.claims, claims)
	e.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"access_token":"tok-%d","token_type":"Bearer","expires_in":%d}`, n, e.expiresIn)
}

func (e *tokenEndpoint) minted() (int, []map[string]any) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.mints, append([]map[string]any(nil), e.claims...)
}

// verifyRS256 checks a compact JWS is RS256-signed by pub and returns its
// claims.
func verifyRS256(jws string, pub *rsa.PublicKey) (map[string]any, error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%d parts, want 3", len(parts))
	}
	var header struct{ Alg, Typ string }
	if err := decodeSegment(parts[0], &header); err != nil || header.Alg != "RS256" {
		return nil, fmt.Errorf("header %+v (%v), want alg RS256", header, err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		return nil, fmt.Errorf("signature: %w", err)
	}
	var claims map[string]any
	return claims, decodeSegment(parts[1], &claims)
}

func decodeSegment(seg string, v any) error {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// serviceAccount generates a throwaway service-account key whose token_uri
// is a fresh tokenEndpoint, and returns the key's JSON and the endpoint.
func serviceAccount(t *testing.T, expiresIn int) ([]byte, *tokenEndpoint) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	e := &tokenEndpoint{t: t, pub: &priv.PublicKey, expiresIn: expiresIn}
	srv := httptest.NewServer(e)
	t.Cleanup(srv.Close)
	e.url = srv.URL + "/token"
	key, err := json.Marshal(map[string]string{
		"type":           "service_account",
		"project_id":     "frict-test",
		"private_key_id": "test-key",
		"private_key":    string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"client_email":   testClientEmail,
		"token_uri":      e.url,
	})
	if err != nil {
		t.Fatal(err)
	}
	return key, e
}

// fcmRecorder is a fake FCM endpoint that accepts every send and records
// its Authorization header.
func fcmRecorder(t *testing.T) (string, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var auth []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		auth = append(auth, r.Header.Get("Authorization"))
		mu.Unlock()
		io.WriteString(w, `{"name":"projects/frict-test/messages/1"}`)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), auth...)
	}
}

// sendTwice sends two messages through a real FCM sender authorized by
// ServiceAccountTokens over key, and returns the bearer headers FCM saw.
func sendTwice(t *testing.T, key []byte) []string {
	t.Helper()
	fcmURL, auth := fcmRecorder(t)
	client := &http.Client{Timeout: 5 * time.Second}
	tokens, err := ServiceAccountTokens(key, client)
	if err != nil {
		t.Fatalf("ServiceAccountTokens: %v", err)
	}
	f := NewFCM(fcmURL, "frict-test", tokens, client)
	for i := range 2 {
		if _, err := f.Send(context.Background(), Message{FID: "the-fid", Data: map[string]string{"challenge_id": "AAAA"}}); err != nil {
			t.Fatalf("send %d: %v", i+1, err)
		}
	}
	return auth()
}

func TestServiceAccountTokenReusedUntilNearExpiry(t *testing.T) {
	for _, tc := range []struct {
		name      string
		expiresIn int
		wantMints int
		wantAuth  string
	}{
		{"valid for an hour", 3600, 1, "Bearer tok-1,Bearer tok-1"},
		// oauth2 treats a token as expired 10 s before its expiry.
		{"within 10 s of expiry", 5, 2, "Bearer tok-1,Bearer tok-2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, tokenURI := serviceAccount(t, tc.expiresIn)
			auth := sendTwice(t, key)
			if mints, _ := tokenURI.minted(); mints != tc.wantMints {
				t.Fatalf("two sends minted %d tokens, want %d", mints, tc.wantMints)
			}
			if got := strings.Join(auth, ","); got != tc.wantAuth {
				t.Fatalf("FCM saw Authorization %q, want %q", got, tc.wantAuth)
			}
		})
	}
}

func TestServiceAccountAssertion(t *testing.T) {
	key, tokenURI := serviceAccount(t, 3600)
	sendTwice(t, key)
	_, claims := tokenURI.minted()
	if len(claims) != 1 {
		t.Fatalf("%d verified assertions, want 1", len(claims))
	}
	c := claims[0]
	if c["iss"] != testClientEmail || c["scope"] != "https://www.googleapis.com/auth/firebase.messaging" || c["aud"] != tokenURI.url {
		t.Fatalf("assertion claims %v, want iss %s, scope firebase.messaging, aud %s", c, testClientEmail, tokenURI.url)
	}
	iat, _ := c["iat"].(float64)
	exp, _ := c["exp"].(float64)
	if now := float64(time.Now().Unix()); iat < now-60 || iat > now+60 || exp <= iat {
		t.Fatalf("assertion iat %v exp %v, want issued now and expiring after", iat, exp)
	}
}

func TestServiceAccountTokensRejectOtherCredentials(t *testing.T) {
	for name, key := range map[string]string{
		"authorized user":  `{"type":"authorized_user","client_id":"x","client_secret":"y","refresh_token":"z"}`,
		"external account": `{"type":"external_account","audience":"x","subject_token_type":"y","token_url":"https://sts.googleapis.com/v1/token"}`,
		"no type":          `{"client_email":"x","private_key":"y"}`,
		"not JSON":         `not json`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ServiceAccountTokens([]byte(key), http.DefaultClient); err == nil {
				t.Fatal("accepted a key that is not a service account")
			}
		})
	}
}

// TestServiceAccountTokensIgnoreAmbientCredentials: with
// GOOGLE_APPLICATION_CREDENTIALS and HOME pointing at another valid key,
// tokens still come from the key passed in.
func TestServiceAccountTokensIgnoreAmbientCredentials(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	ambient, ambientURI := serviceAccount(t, 3600)
	path := home + "/ambient.json"
	if err := os.WriteFile(path, ambient, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", path)

	key, tokenURI := serviceAccount(t, 3600)
	sendTwice(t, key)
	if mints, _ := tokenURI.minted(); mints != 1 {
		t.Fatalf("given key minted %d tokens, want 1", mints)
	}
	if mints, _ := ambientURI.minted(); mints != 0 {
		t.Fatalf("ambient key minted %d tokens, want 0", mints)
	}
}
