package crossreview

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
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	appID     = 5557312
	owner     = "frict-auth"
	repo      = "frict-server"
	sha       = "0123456789abcdef0123456789abcdef01234567"
	instID    = 4242
	instToken = "ghs_test-installation-token"
)

var fixedNow = time.Unix(1_800_000_000, 0)

var (
	keyOnce sync.Once
	testKey *rsa.PrivateKey
)

func key(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	keyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		testKey = k
	})
	return testKey
}

// verifyJWT checks header, claims and signature and returns the claims.
func verifyJWT(t *testing.T, tok string, pub *rsa.PublicKey) map[string]any {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT has %d parts, want 3", len(parts))
	}
	dec := func(s string) []byte {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("JWT segment is not raw base64url: %v", err)
		}
		return b
	}
	var header map[string]any
	if err := json.Unmarshal(dec(parts[0]), &header); err != nil {
		t.Fatal(err)
	}
	if want := map[string]any{"alg": "RS256", "typ": "JWT"}; !reflect.DeepEqual(header, want) {
		t.Errorf("JWT header = %v, want %v", header, want)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], dec(parts[2])); err != nil {
		t.Errorf("JWT signature does not verify over header.payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(dec(parts[1]), &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

func TestAppJWT(t *testing.T) {
	k := key(t)
	tok, err := AppJWT(appID, k, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	claims := verifyJWT(t, tok, &k.PublicKey)
	if claims["iss"] != "5557312" {
		t.Errorf("iss = %v, want \"5557312\"", claims["iss"])
	}
	iat, exp := int64(claims["iat"].(float64)), int64(claims["exp"].(float64))
	if want := fixedNow.Unix() - 60; iat != want {
		t.Errorf("iat = %d, want now-60 = %d", iat, want)
	}
	if exp <= fixedNow.Unix() || exp > fixedNow.Unix()+600 {
		t.Errorf("exp = %d, want in (now, now+600] = (%d, %d]", exp, fixedNow.Unix(), fixedNow.Unix()+600)
	}
	if len(claims) != 3 {
		t.Errorf("claims = %v, want only iat, exp, iss", claims)
	}
}

func TestAppJWTRejectsOtherKey(t *testing.T) {
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := AppJWT(appID, key(t), fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(&other.PublicKey, crypto.SHA256, digest[:], sig) == nil {
		t.Fatal("signature verified under an unrelated key")
	}
}

type recorded struct {
	method, path, auth string
	body               map[string]any
}

// fakeGitHub stands in for api.github.com. Handlers not overridden in
// replies behave like the real API on success.
type fakeGitHub struct {
	t       *testing.T
	pub     *rsa.PublicKey
	replies map[string]func(w http.ResponseWriter)
	mu      sync.Mutex
	calls   []recorded
}

const (
	installationPath = "/repos/" + owner + "/" + repo + "/installation"
	tokenPath        = "/app/installations/4242/access_tokens"
	statusPath       = "/repos/" + owner + "/" + repo + "/statuses/" + sha
)

func (f *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	rec := recorded{method: r.Method, path: r.URL.Path, auth: r.Header.Get("Authorization")}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &rec.body); err != nil {
			f.t.Errorf("%s %s: body is not JSON: %q", r.Method, r.URL.Path, raw)
		}
	}
	f.mu.Lock()
	f.calls = append(f.calls, rec)
	f.mu.Unlock()

	if got := r.Header.Get("Accept"); got != "application/vnd.github+json" {
		f.t.Errorf("%s: Accept = %q", r.URL.Path, got)
	}
	if reply, ok := f.replies[r.Method+" "+r.URL.Path]; ok {
		reply(w)
		return
	}
	switch r.Method + " " + r.URL.Path {
	case "GET " + installationPath:
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `{"id":4242,"app_id":5557312}`)
	case "POST " + tokenPath:
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, `{"token":"`+instToken+`","expires_at":"2027-01-15T08:00:00Z"}`)
	case "POST " + statusPath:
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, `{"id":99,"url":"https://api.github.test/s/99","state":"pending","context":"cross-review","creator":{"login":"frict-cross-review[bot]"}}`)
	default:
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, `{"message":"Not Found"}`)
	}
}

func reply(code int, body string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.WriteHeader(code)
		io.WriteString(w, body)
	}
}

func setup(t *testing.T, replies map[string]func(http.ResponseWriter)) (*fakeGitHub, *Client) {
	t.Helper()
	k := key(t)
	f := &fakeGitHub{t: t, pub: &k.PublicKey, replies: replies}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, &Client{BaseURL: srv.URL, HTTP: srv.Client(), AppID: appID, Key: k, Now: func() time.Time { return fixedNow }}
}

func (f *fakeGitHub) paths() []string {
	var out []string
	for _, c := range f.calls {
		out = append(out, c.method+" "+c.path)
	}
	return out
}

func TestPostStatusFlow(t *testing.T) {
	f, c := setup(t, nil)
	got, err := c.PostStatus(context.Background(), owner, repo, sha, Status{
		State: "pending", Description: "registers the app", TargetURL: "https://example.test/review/1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != 99 || got.Creator.Login != "frict-cross-review[bot]" {
		t.Errorf("created = %+v", got)
	}

	want := []string{"GET " + installationPath, "POST " + tokenPath, "POST " + statusPath}
	if !reflect.DeepEqual(f.paths(), want) {
		t.Fatalf("calls = %v, want %v", f.paths(), want)
	}
	inst, tokReq, status := f.calls[0], f.calls[1], f.calls[2]

	for _, call := range []recorded{inst, tokReq} {
		jwt, ok := strings.CutPrefix(call.auth, "Bearer ")
		if !ok {
			t.Fatalf("%s: Authorization = %q, want Bearer <jwt>", call.path, call.auth)
		}
		if claims := verifyJWT(t, jwt, f.pub); claims["iss"] != "5557312" {
			t.Errorf("%s: JWT iss = %v", call.path, claims["iss"])
		}
	}
	if inst.body != nil {
		t.Errorf("installation lookup sent a body: %v", inst.body)
	}

	wantTokReq := map[string]any{
		"repositories": []any{repo},
		"permissions":  map[string]any{"statuses": "write"},
	}
	if !reflect.DeepEqual(tokReq.body, wantTokReq) {
		t.Errorf("token request body = %v, want exactly %v", tokReq.body, wantTokReq)
	}

	if status.auth != "Bearer "+instToken {
		t.Errorf("status POST Authorization = %q, want the installation token", status.auth)
	}
	wantStatus := map[string]any{
		"state": "pending", "context": "cross-review",
		"description": "registers the app", "target_url": "https://example.test/review/1",
	}
	if !reflect.DeepEqual(status.body, wantStatus) {
		t.Errorf("status body = %v, want %v", status.body, wantStatus)
	}
}

func TestPostStatusOmitsEmptyOptionalFields(t *testing.T) {
	f, c := setup(t, nil)
	if _, err := c.PostStatus(context.Background(), owner, repo, sha, Status{State: "success"}); err != nil {
		t.Fatal(err)
	}
	if want := map[string]any{"state": "success", "context": "cross-review"}; !reflect.DeepEqual(f.calls[2].body, want) {
		t.Errorf("status body = %v, want %v", f.calls[2].body, want)
	}
}

func TestPostStatusAPIErrors(t *testing.T) {
	cases := []struct {
		name      string
		replies   map[string]func(http.ResponseWriter)
		wantCalls int
		wantErr   []string
	}{
		{
			name: "installation 404",
			replies: map[string]func(http.ResponseWriter){
				"GET " + installationPath: reply(404, `{"message":"Not Found","documentation_url":"https://docs.github.com"}`),
			},
			wantCalls: 1,
			wantErr:   []string{"installation", "HTTP 404", "Not Found"},
		},
		{
			name: "token endpoint 401",
			replies: map[string]func(http.ResponseWriter){
				"POST " + tokenPath: reply(401, `{"message":"A JSON web token could not be decoded"}`),
			},
			wantCalls: 2,
			wantErr:   []string{"installation token", "HTTP 401", "A JSON web token could not be decoded"},
		},
		{
			name: "status endpoint 422",
			replies: map[string]func(http.ResponseWriter){
				"POST " + statusPath: reply(422, `{"message":"No commit found for SHA: `+sha+`"}`),
			},
			wantCalls: 3,
			wantErr:   []string{"posting cross-review status", "HTTP 422", "No commit found"},
		},
		{
			name: "non-JSON error body",
			replies: map[string]func(http.ResponseWriter){
				"POST " + tokenPath: reply(502, `<html>bad gateway</html>`),
			},
			wantCalls: 2,
			wantErr:   []string{"HTTP 502", "no message in response"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, c := setup(t, tc.replies)
			_, err := c.PostStatus(context.Background(), owner, repo, sha, Status{State: "pending"})
			if err == nil {
				t.Fatal("want error")
			}
			for _, w := range tc.wantErr {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q does not mention %q", err, w)
				}
			}
			if strings.Contains(err.Error(), instToken) || strings.Contains(err.Error(), "eyJ") {
				t.Errorf("error leaks a credential: %q", err)
			}
			if len(f.calls) != tc.wantCalls {
				t.Errorf("calls = %v, want %d", f.paths(), tc.wantCalls)
			}
		})
	}
}

func TestPostStatusRejectsBadInputBeforeNetwork(t *testing.T) {
	cases := map[string]struct{ sha, state, wantErr string }{
		"short sha":     {"0123456", "pending", "40-character"},
		"41 chars":      {sha + "0", "pending", "40-character"},
		"branch name":   {"main", "pending", "40-character"},
		"bad state":     {sha, "approved", "not one of"},
		"empty state":   {sha, "", "not one of"},
		"uppercase st.": {sha, "SUCCESS", "not one of"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f, c := setup(t, nil)
			_, err := c.PostStatus(context.Background(), owner, repo, tc.sha, Status{State: tc.state})
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("err = %v, want mention of %q", err, tc.wantErr)
			}
			if len(f.calls) != 0 {
				t.Errorf("made requests %v despite invalid input", f.paths())
			}
		})
	}
}

func TestValidateSHA(t *testing.T) {
	for _, ok := range []string{sha, strings.ToUpper(sha)} {
		if err := ValidateSHA(ok); err != nil {
			t.Errorf("ValidateSHA(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"", "0123456", sha[:39], sha + "a", "g" + sha[1:], " " + sha[1:], sha[:39] + "\n", "HEAD"} {
		if err := ValidateSHA(bad); err == nil {
			t.Errorf("ValidateSHA(%q) accepted", bad)
		}
	}
}

func TestValidateState(t *testing.T) {
	for _, ok := range []string{"pending", "success", "failure", "error"} {
		if err := ValidateState(ok); err != nil {
			t.Errorf("ValidateState(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"", "Pending", "approved", "neutral", "success "} {
		if err := ValidateState(bad); err == nil {
			t.Errorf("ValidateState(%q) accepted", bad)
		}
	}
}

func TestParseRepo(t *testing.T) {
	o, n, err := ParseRepo("frict-auth/frict-server")
	if err != nil || o != "frict-auth" || n != "frict-server" {
		t.Errorf("ParseRepo = %q, %q, %v", o, n, err)
	}
	for _, bad := range []string{"", "frict-server", "/x", "x/", "a/b/c", "a/../b", "a/..", "./b", "a/b?x=1", "a b/c"} {
		if _, _, err := ParseRepo(bad); err == nil {
			t.Errorf("ParseRepo(%q) accepted", bad)
		}
	}
}

func writeKey(t *testing.T, block *pem.Block, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil { // WriteFile's mode is subject to umask
		t.Fatal(err)
	}
	return path
}

func TestLoadKey(t *testing.T) {
	k := key(t)
	pkcs1 := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	p8, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8 := &pem.Block{Type: "PRIVATE KEY", Bytes: p8}

	for name, block := range map[string]*pem.Block{"pkcs1": pkcs1, "pkcs8": pkcs8} {
		for _, mode := range []os.FileMode{0o600, 0o400} {
			got, err := LoadKey(writeKey(t, block, mode))
			if err != nil {
				t.Errorf("%s mode %04o: %v", name, mode, err)
			} else if !got.Equal(k) {
				t.Errorf("%s mode %04o: loaded a different key", name, mode)
			}
		}
	}

	for _, mode := range []os.FileMode{0o644, 0o604, 0o640, 0o660, 0o606, 0o601, 0o610} {
		_, err := LoadKey(writeKey(t, pkcs1, mode))
		if err == nil {
			t.Errorf("mode %04o accepted", mode)
		} else if !strings.Contains(err.Error(), "group or other") {
			t.Errorf("mode %04o: error %q does not explain the refusal", mode, err)
		}
	}
}

func TestLoadKeyBadContent(t *testing.T) {
	dir := t.TempDir()
	notPEM := filepath.Join(dir, "garbage")
	if err := os.WriteFile(notPEM, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"missing file": filepath.Join(dir, "absent"),
		"not PEM":      notPEM,
		"wrong type":   writeKey(t, &pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}}, 0o600),
		"bad pkcs1":    writeKey(t, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte{1, 2, 3}}, 0o600),
	}
	for name, path := range cases {
		if _, err := LoadKey(path); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := LoadKey(dir); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Errorf("directory: err = %v", err)
	}
}
