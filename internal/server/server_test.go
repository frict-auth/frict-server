package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/frict-auth/frict-server/internal/duosig"
	"github.com/frict-auth/frict-server/internal/fakephone"
	"github.com/frict-auth/frict-server/internal/push"
	"github.com/frict-auth/frict-server/internal/store"
)

const (
	host     = "api.frict.test"
	clientID = "DIXXXXXXXXXXXXXXXXXX"
	secret   = "client-secret"
)

var t0 = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

// fixture is a Server on a fresh SQLite store whose clock the test moves.
type fixture struct {
	t      *testing.T
	dbPath string
	st     *store.Store
	srv    *Server
	h      http.Handler

	mu    sync.Mutex
	clock time.Time
}

// testSafeguards are loose enough that tests not about them never hit one.
var testSafeguards = Safeguards{
	PushCap:         100,
	PushCooldown:    time.Minute,
	MaxFailed:       100,
	Pause:           10 * time.Minute,
	AlertRecipients: []string{"admin"},
	AlertTTL:        24 * time.Hour,
	AuthentikURL:    "https://auth.example",
}

// newFixture's pushes expire after 60 s.
func newFixture(t *testing.T) *fixture { return newFixtureWith(t, 60*time.Second, testSafeguards) }

func newFixtureTTL(t *testing.T, challengeTTL time.Duration) *fixture {
	return newFixtureWith(t, challengeTTL, testSafeguards)
}

// newFixtureWith sends no pushes, so its devices find challenges only by
// polling.
func newFixtureWith(t *testing.T, challengeTTL time.Duration, sg Safeguards) *fixture {
	return newFixtureSender(t, challengeTTL, sg, nil, slog.New(slog.DiscardHandler))
}

func newFixtureSender(t *testing.T, challengeTTL time.Duration, sg Safeguards, sender push.Sender, log *slog.Logger) *fixture {
	t.Helper()
	f := &fixture{t: t, dbPath: filepath.Join(t.TempDir(), "frict.db"), clock: t0}
	st, err := store.Open(f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	f.st = st
	f.srv = New(f.verifier(), st, challengeTTL, sg, sender, log)
	t.Cleanup(f.srv.Close)
	f.h = f.srv.Handler()
	return f
}

func (f *fixture) now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.clock
}

func (f *fixture) setClock(t time.Time) {
	f.mu.Lock()
	f.clock = t
	f.mu.Unlock()
}

func (f *fixture) verifier() duosig.Verifier {
	return duosig.Verifier{IKey: clientID, SKey: secret, Host: host, MaxSkew: 5 * time.Minute, Now: f.now}
}

func (f *fixture) serve(r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	return w
}

// duo sends a POST signed the way duo_client signs it, with skey.
func (f *fixture) duo(path, body, skey string) *httptest.ResponseRecorder {
	f.t.Helper()
	r := httptest.NewRequest(http.MethodPost, "https://"+host+path, strings.NewReader(body))
	r.Header.Set("Date", f.now().Format(time.RFC1123Z))
	r.Header.Set("Content-Type", "application/json")
	if err := duosig.Sign(r, []byte(body), clientID, skey, host); err != nil {
		f.t.Fatalf("Sign: %v", err)
	}
	return f.serve(r)
}

type enrollResponse struct {
	Stat     string `json:"stat"`
	Response struct {
		ActivationBarcode string `json:"activation_barcode"`
		ActivationCode    string `json:"activation_code"`
		UserID            string `json:"user_id"`
		Username          string `json:"username"`
		ValidSecs         int    `json:"valid_secs"`
	} `json:"response"`
}

// enroll calls /auth/v2/enroll as Authentik does and returns the activation
// the user's phone would scan.
func (f *fixture) enroll(username string) fakephone.Activation {
	f.t.Helper()
	w := f.duo("/auth/v2/enroll", `{"username":"`+username+`"}`, secret)
	if w.Code != http.StatusOK {
		f.t.Fatalf("enroll: %d %s", w.Code, w.Body)
	}
	var resp enrollResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		f.t.Fatal(err)
	}
	a, err := fakephone.ParseActivation(resp.Response.ActivationCode)
	if err != nil {
		f.t.Fatal(err)
	}
	return a
}

// status calls /auth/v2/enroll_status as Authentik does for a.
func (f *fixture) status(a fakephone.Activation) string {
	f.t.Helper()
	params, err := json.Marshal(map[string]string{"user_id": a.UserID, "activation_code": ActivationLink(a.Host, a.UserID, a.Code)})
	if err != nil {
		f.t.Fatal(err)
	}
	w := f.duo("/auth/v2/enroll_status", string(params), secret)
	if w.Code != http.StatusOK {
		f.t.Fatalf("enroll_status: %d %s", w.Code, w.Body)
	}
	var resp struct{ Stat, Response string }
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.Stat != "OK" {
		f.t.Fatalf("enroll_status body %s: %v", w.Body, err)
	}
	return resp.Response
}

func newPhone(t *testing.T) *fakephone.Phone {
	t.Helper()
	p, err := fakephone.New()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func must[T any](t *testing.T) func(T, error) T {
	return func(v T, err error) T {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
}

func spki(t *testing.T, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	return must[[]byte](t)(x509.MarshalPKIXPublicKey(pub))
}

func TestAuthAPIRequiresDuoSignature(t *testing.T) {
	f := newFixture(t)
	unsigned := func(path string) *http.Request {
		return httptest.NewRequest(http.MethodPost, "https://"+host+path, strings.NewReader(`{}`))
	}
	tests := []struct {
		name string
		w    func() *httptest.ResponseRecorder
		want int
	}{
		{"enroll signed", func() *httptest.ResponseRecorder { return f.duo("/auth/v2/enroll", `{"username":"alice"}`, secret) }, http.StatusOK},
		{"auth signed, unknown user", func() *httptest.ResponseRecorder {
			return f.duo("/auth/v2/auth", `{"factor":"auto","user_id":"DU1"}`, secret)
		}, http.StatusBadRequest},
		{"enroll unsigned", func() *httptest.ResponseRecorder { return f.serve(unsigned("/auth/v2/enroll")) }, http.StatusUnauthorized},
		{"enroll_status unsigned", func() *httptest.ResponseRecorder { return f.serve(unsigned("/auth/v2/enroll_status")) }, http.StatusUnauthorized},
		{"auth unsigned", func() *httptest.ResponseRecorder { return f.serve(unsigned("/auth/v2/auth")) }, http.StatusUnauthorized},
		{"enroll wrong secret", func() *httptest.ResponseRecorder { return f.duo("/auth/v2/enroll", `{"username":"alice"}`, "wrong") }, http.StatusUnauthorized},
		{"unknown endpoint", func() *httptest.ResponseRecorder { return f.duo("/auth/v2/ping", `{}`, secret) }, http.StatusNotFound},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := tc.w()
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d; body %s", w.Code, tc.want, w.Body)
			}
			if tc.want/100 != 2 && tc.want != http.StatusNotFound && !strings.Contains(w.Body.String(), `"stat":"FAIL"`) {
				t.Fatalf("body %q is not a Duo FAIL response", w.Body)
			}
		})
	}
}

func TestDuoSignedPassesBodyThrough(t *testing.T) {
	const body = `{"username":"élodie"}`
	f := newFixture(t)
	var got string
	h := New(f.verifier(), f.st, time.Minute, testSafeguards, nil, slog.New(slog.DiscardHandler)).duoSigned(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		got = string(b)
	})
	r := httptest.NewRequest(http.MethodPost, "https://"+host+"/auth/v2/enroll", strings.NewReader(body))
	r.Header.Set("Date", t0.Format(time.RFC1123Z))
	if err := duosig.Sign(r, []byte(body), clientID, secret, host); err != nil {
		t.Fatal(err)
	}
	h.ServeHTTP(httptest.NewRecorder(), r)
	if got != body {
		t.Fatalf("handler saw body %q, want %q", got, body)
	}
}

// The fields Authentik reads are activation_barcode and activation_code
// (stage.py:75-76) and user_id (stage.py:86, 96); duo_client documents the
// rest (auth.py:47-54).
func TestDuoEnrollResponse(t *testing.T) {
	f := newFixture(t)
	w := f.duo("/auth/v2/enroll", `{"username":"élodie"}`, secret)
	if w.Code != http.StatusOK {
		t.Fatalf("enroll: %d %s", w.Code, w.Body)
	}
	var resp enrollResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	r := resp.Response
	if resp.Stat != "OK" || r.Username != "élodie" || r.ValidSecs != 900 {
		t.Fatalf("enroll response %s", w.Body)
	}
	a, err := fakephone.ParseActivation(r.ActivationCode)
	if err != nil {
		t.Fatal(err)
	}
	if a.Host != host || a.UserID != r.UserID || len(a.Code) != 26 {
		t.Fatalf("activation link %q: %+v", r.ActivationCode, a)
	}
	want, err := qrDataURL(r.ActivationCode)
	if err != nil {
		t.Fatal(err)
	}
	if r.ActivationBarcode != want {
		t.Fatalf("activation_barcode %.60q..., want the QR code of the activation link", r.ActivationBarcode)
	}
	if other := f.enroll("élodie"); other.UserID == a.UserID || other.Code == a.Code {
		t.Fatalf("second enroll reused user_id or code: %+v %+v", a, other)
	}
}

func TestDuoEnrollRequiresUsername(t *testing.T) {
	f := newFixture(t)
	for _, body := range []string{`{}`, `{"username":""}`, `not json`} {
		if w := f.duo("/auth/v2/enroll", body, secret); w.Code != http.StatusBadRequest {
			t.Errorf("enroll %s: %d %s, want 400", body, w.Code, w.Body)
		}
	}
}

func TestEnrollStatusInvalid(t *testing.T) {
	f := newFixture(t)
	a, b := f.enroll("alice"), f.enroll("bob")
	for name, act := range map[string]fakephone.Activation{
		"other user's code": {Host: host, UserID: a.UserID, Code: b.Code},
		"unknown user":      {Host: host, UserID: "DUCCCCCCCCCCCCCCCCCCCCCCCCCC", Code: a.Code},
		"unknown code":      {Host: host, UserID: a.UserID, Code: "NOPE"},
	} {
		if got := f.status(act); got != "invalid" {
			t.Errorf("%s: %q, want invalid", name, got)
		}
	}
	params := `{"user_id":"` + a.UserID + `","activation_code":"` + a.Code + `"}`
	if w := f.duo("/auth/v2/enroll_status", params, secret); !strings.Contains(w.Body.String(), `"response":"invalid"`) {
		t.Errorf("bare code instead of link: %d %s, want invalid", w.Code, w.Body)
	}
	if w := f.duo("/auth/v2/enroll_status", `{"user_id":"`+a.UserID+`"}`, secret); w.Code != http.StatusBadRequest {
		t.Errorf("missing activation_code: %d, want 400", w.Code)
	}
}

func TestDeviceEnrollThenStatusSuccess(t *testing.T) {
	f := newFixture(t)
	a := f.enroll("alice")
	if got := f.status(a); got != "waiting" {
		t.Fatalf("before enroll: %q, want waiting", got)
	}
	phone := newPhone(t)
	f.setClock(t0.Add(time.Minute))
	w := f.serve(must[*http.Request](t)(phone.EnrollRequest(a, f.now())))
	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != "{}" {
		t.Fatalf("enroll: %d %s, want 200 {}", w.Code, w.Body)
	}
	if got := f.status(a); got != "success" {
		t.Fatalf("after enroll: %q, want success", got)
	}

	dev, err := f.st.DeviceOf(context.Background(), a.UserID)
	if err != nil {
		t.Fatal(err)
	}
	var sent struct{ Attestation json.RawMessage }
	if err := json.Unmarshal(must[[]byte](t)(phone.EnrollBody(a.Code)), &sent); err != nil {
		t.Fatal(err)
	}
	if string(dev.DeviceKey) != string(spki(t, &phone.DeviceKey.PublicKey)) ||
		string(dev.ApprovalKey) != string(spki(t, &phone.ApprovalKey.PublicKey)) ||
		string(dev.Attestation) != string(sent.Attestation) || dev.FID != phone.FID || !dev.EnrolledAt.Equal(f.now()) {
		t.Fatalf("stored device %+v does not match the phone's enrollment", dev)
	}
}

// rejectEnroll sends r and requires a 401 that leaves a's enrollment waiting.
func (f *fixture) rejectEnroll(r *http.Request, a fakephone.Activation) {
	f.t.Helper()
	w := f.serve(r)
	if w.Code != http.StatusUnauthorized || strings.TrimSpace(w.Body.String()) != `{"error":"unauthorized"}` {
		f.t.Fatalf("enroll: %d %s, want 401 unauthorized", w.Code, w.Body)
	}
	if _, err := f.st.DeviceOf(context.Background(), a.UserID); !errors.Is(err, store.ErrNoDevice) {
		f.t.Fatalf("rejected enroll left a device for %s (err %v)", a.UserID, err)
	}
}

func TestDeviceEnrollTakesUserFromActivationCode(t *testing.T) {
	f := newFixture(t)
	alice, bob := f.enroll("alice"), f.enroll("bob")
	phone := newPhone(t)
	claimBob := fakephone.Activation{Host: host, UserID: bob.UserID, Code: alice.Code}
	f.rejectEnroll(must[*http.Request](t)(phone.EnrollRequest(claimBob, f.now())), alice)
	if _, err := f.st.DeviceOf(context.Background(), bob.UserID); !errors.Is(err, store.ErrNoDevice) {
		t.Fatalf("bob has a device enrolled with alice's code (err %v)", err)
	}
	if got := f.status(alice); got != "waiting" {
		t.Fatalf("alice after mismatched claim: %q, want waiting", got)
	}
}

func TestDeviceEnrollRejectsReusedCode(t *testing.T) {
	f := newFixture(t)
	a := f.enroll("alice")
	first, second := newPhone(t), newPhone(t)
	if w := f.serve(must[*http.Request](t)(first.EnrollRequest(a, f.now()))); w.Code != http.StatusOK {
		t.Fatalf("first enroll: %d %s", w.Code, w.Body)
	}
	w := f.serve(must[*http.Request](t)(second.EnrollRequest(a, f.now())))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("second enroll with the same code: %d %s, want 401", w.Code, w.Body)
	}
	dev, err := f.st.DeviceOf(context.Background(), a.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if string(dev.DeviceKey) != string(spki(t, &first.DeviceKey.PublicKey)) {
		t.Fatal("reused code replaced the first phone's device_key")
	}
}

func TestDeviceEnrollRejectsExpiredCode(t *testing.T) {
	f := newFixture(t)
	a := f.enroll("alice")
	f.setClock(t0.Add(ActivationValidity))
	f.rejectEnroll(must[*http.Request](t)(newPhone(t).EnrollRequest(a, f.now())), a)
	if got := f.status(a); got != "invalid" {
		t.Fatalf("expired, unenrolled: %q, want invalid", got)
	}
}

func TestDeviceEnrollRejectsTimestampOutsideWindow(t *testing.T) {
	for _, offset := range []time.Duration{-5*time.Minute - time.Second, 5*time.Minute + time.Second} {
		t.Run(offset.String(), func(t *testing.T) {
			f := newFixture(t)
			a := f.enroll("alice")
			f.rejectEnroll(must[*http.Request](t)(newPhone(t).EnrollRequest(a, f.now().Add(offset))), a)
		})
	}
}

func TestDeviceEnrollRejectsSignatureByWrongKey(t *testing.T) {
	f := newFixture(t)
	a := f.enroll("alice")
	phone, thief := newPhone(t), newPhone(t)
	body := must[[]byte](t)(phone.EnrollBody(a.Code))
	r := must[*http.Request](t)(fakephone.SignedRequest("https://"+host, fakephone.EnrollPath, a.UserID, f.now().Unix(), body, thief.DeviceKey))
	f.rejectEnroll(r, a)
}

func TestDeviceEnrollRejectsSignatureForAnotherPath(t *testing.T) {
	f := newFixture(t)
	a := f.enroll("alice")
	phone := newPhone(t)
	body := must[[]byte](t)(phone.EnrollBody(a.Code))
	sig := must[string](t)(fakephone.Sign(phone.DeviceKey, a.UserID, f.now().Unix(), "/device/v1/fid", body))
	r := httptest.NewRequest(http.MethodPost, "https://"+host+fakephone.EnrollPath, strings.NewReader(string(body)))
	r.Header.Set("Authorization", "Frict-P256 "+a.UserID+":"+strconv.FormatInt(f.now().Unix(), 10)+":"+sig)
	f.rejectEnroll(r, a)
}

func TestDeviceEnrollRejectsMalformedUserID(t *testing.T) {
	f := newFixture(t)
	a := f.enroll("alice")
	phone := newPhone(t)
	for _, id := range []string{strings.ToLower(a.UserID), a.UserID + "\n", a.UserID[:27] + "0"} {
		f.rejectEnroll(must[*http.Request](t)(phone.EnrollRequest(fakephone.Activation{Host: host, UserID: id, Code: a.Code}, f.now())), a)
	}
}

func TestDeviceEnrollRejectsMalformedBody(t *testing.T) {
	f := newFixture(t)
	a := f.enroll("alice")
	phone := newPhone(t)
	good := map[string]any{}
	if err := json.Unmarshal(must[[]byte](t)(phone.EnrollBody(a.Code)), &good); err != nil {
		t.Fatal(err)
	}
	garbage := "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMmV"
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(m map[string]any){
		"unknown field":        func(m map[string]any) { m["user_id"] = a.UserID },
		"no fid":               func(m map[string]any) { delete(m, "fid") },
		"no activation_code":   func(m map[string]any) { delete(m, "activation_code") },
		"approval_key garbage": func(m map[string]any) { m["approval_key"] = garbage },
		"approval_key P-384": func(m map[string]any) {
			m["approval_key"] = base64.RawURLEncoding.EncodeToString(spki(t, &p384.PublicKey))
		},
		"no attestation": func(m map[string]any) { delete(m, "attestation") },
		"empty attestation chain": func(m map[string]any) {
			m["attestation"] = map[string]any{"device_key": []string{}, "approval_key": []string{"AA"}}
		},
		"attestation not base64url": func(m map[string]any) {
			m["attestation"] = map[string]any{"device_key": []string{"+/=="}, "approval_key": []string{"AA"}}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			m := map[string]any{}
			for k, v := range good {
				m[k] = v
			}
			mutate(m)
			body := must[[]byte](t)(json.Marshal(m))
			f.rejectEnroll(must[*http.Request](t)(fakephone.SignedRequest("https://"+host, fakephone.EnrollPath, a.UserID, f.now().Unix(), body, phone.DeviceKey)), a)
		})
	}
}

func TestDeviceEnrollOnlyPOST(t *testing.T) {
	f := newFixture(t)
	if w := f.serve(httptest.NewRequest(http.MethodGet, "https://"+host+fakephone.EnrollPath, nil)); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET enroll: %d, want 405", w.Code)
	}
}

type downStore struct{ *store.Store }

func (downStore) Ping(context.Context) error { return errors.New("database is closed") }

func TestHealthz(t *testing.T) {
	f := newFixture(t)
	tests := []struct {
		name  string
		store Store
		want  int
	}{
		{"store up", f.st, http.StatusOK},
		{"store down", downStore{f.st}, http.StatusServiceUnavailable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			New(f.verifier(), tc.store, time.Minute, testSafeguards, nil, slog.New(slog.DiscardHandler)).Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d", w.Code, tc.want)
			}
		})
	}
}
