package duosig

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

type vectorFile struct {
	DuoClientVersion string   `json:"duo_client_version"`
	IKey             string   `json:"ikey"`
	SKey             string   `json:"skey"`
	Host             string   `json:"host"`
	UnixTime         int64    `json:"unix_time"`
	Vectors          []vector `json:"vectors"`
}

type vector struct {
	Name    string            `json:"name"`
	Method  string            `json:"method"`
	URI     string            `json:"uri"`
	Body    string            `json:"body"`
	Headers map[string]string `json:"headers"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile("testdata/duo_client_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vf vectorFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatal(err)
	}
	if len(vf.Vectors) == 0 {
		t.Fatal("no vectors in fixture")
	}
	return vf
}

func (vf vectorFile) verifier(now time.Time) Verifier {
	return Verifier{IKey: vf.IKey, SKey: vf.SKey, Host: vf.Host, MaxSkew: 5 * time.Minute,
		Now: func() time.Time { return now }}
}

func (vf vectorFile) signedAt() time.Time { return time.Unix(vf.UnixTime, 0) }

func (v vector) request() (*http.Request, []byte) {
	r := httptest.NewRequest(v.Method, v.URI, strings.NewReader(v.Body))
	for k, val := range v.Headers {
		r.Header.Set(k, val)
	}
	return r, []byte(v.Body)
}

func (vf vectorFile) find(t *testing.T, name string) vector {
	t.Helper()
	for _, v := range vf.Vectors {
		if v.Name == name {
			return v
		}
	}
	t.Fatalf("vector %q not in fixture", name)
	return vector{}
}

func TestVerifyAcceptsDuoClientVectors(t *testing.T) {
	vf := loadVectors(t)
	for _, v := range vf.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			r, body := v.request()
			if err := vf.verifier(vf.signedAt()).Verify(r, body); err != nil {
				t.Fatalf("duo_client %s vector rejected: %v", vf.DuoClientVersion, err)
			}
		})
	}
}

func TestVerifyAcceptsWithinSkew(t *testing.T) {
	vf := loadVectors(t)
	v := vf.find(t, "enroll")
	for _, d := range []time.Duration{-5 * time.Minute, 5 * time.Minute} {
		r, body := v.request()
		if err := vf.verifier(vf.signedAt().Add(d)).Verify(r, body); err != nil {
			t.Errorf("now = signed%+v: %v", d, err)
		}
	}
}

func TestVerifyRejects(t *testing.T) {
	vf := loadVectors(t)
	basicCred := func(s string) string { return "Basic " + base64.StdEncoding.EncodeToString([]byte(s)) }

	cases := []struct {
		name   string
		vector string
		mutate func(r *http.Request, body *[]byte, ver *Verifier)
		want   error
	}{
		{"wrong secret", "enroll", func(_ *http.Request, _ *[]byte, ver *Verifier) { ver.SKey += "x" }, ErrBadSignature},
		{"wrong host", "enroll", func(_ *http.Request, _ *[]byte, ver *Verifier) { ver.Host = "other.frict.test" }, ErrBadSignature},
		{"unknown ikey", "enroll", func(_ *http.Request, _ *[]byte, ver *Verifier) { ver.IKey = "DIOTHER" }, ErrUnknownIKey},
		{"tampered body", "auth_authentik_params", func(_ *http.Request, b *[]byte, _ *Verifier) {
			*b = bytes.Replace(*b, []byte("DU123"), []byte("DU124"), 1)
		}, ErrBadSignature},
		{"tampered path", "enroll", func(r *http.Request, _ *[]byte, _ *Verifier) { r.URL.Path = "/auth/v2/auth" }, ErrBadSignature},
		{"tampered method", "get_with_query_params", func(r *http.Request, _ *[]byte, _ *Verifier) { r.Method = "POST" }, ErrBadSignature},
		{"tampered query value", "get_with_query_params", func(r *http.Request, _ *[]byte, _ *Verifier) {
			r.URL.RawQuery = strings.Replace(r.URL.RawQuery, "Zeta=1", "Zeta=3", 1)
		}, ErrBadSignature},
		{"added query param", "enroll", func(r *http.Request, _ *[]byte, _ *Verifier) { r.URL.RawQuery = "x=1" }, ErrBadSignature},
		{"tampered X-Duo header", "post_with_x_duo_header", func(r *http.Request, _ *[]byte, _ *Verifier) {
			r.Header.Set("X-Duo-Test-Header", "changed")
		}, ErrBadSignature},
		{"added X-Duo header", "enroll", func(r *http.Request, _ *[]byte, _ *Verifier) { r.Header.Set("X-Duo-Injected", "1") }, ErrBadSignature},
		{"removed X-Duo header", "post_with_x_duo_header", func(r *http.Request, _ *[]byte, _ *Verifier) {
			r.Header.Del("X-Duo-Another")
		}, ErrBadSignature},
		{"repeated X-Duo header", "post_with_x_duo_header", func(r *http.Request, _ *[]byte, _ *Verifier) {
			r.Header.Add("X-Duo-Test-Header", "v")
		}, ErrBadXDuoHeader},
		{"date altered by one second", "enroll", func(r *http.Request, _ *[]byte, _ *Verifier) {
			r.Header.Set("Date", "Wed, 04 Nov 2026 12:00:01 -0000")
		}, ErrBadSignature},
		{"missing Authorization", "enroll", func(r *http.Request, _ *[]byte, _ *Verifier) { r.Header.Del("Authorization") }, ErrMissingCredentials},
		{"non-Basic scheme", "enroll", func(r *http.Request, _ *[]byte, _ *Verifier) {
			r.Header.Set("Authorization", strings.Replace(r.Header.Get("Authorization"), "Basic", "Bearer", 1))
		}, ErrMalformedHeader},
		{"bad base64", "enroll", func(r *http.Request, _ *[]byte, _ *Verifier) { r.Header.Set("Authorization", "Basic !!!") }, ErrMalformedHeader},
		{"no colon", "enroll", func(r *http.Request, _ *[]byte, _ *Verifier) {
			r.Header.Set("Authorization", basicCred(vf.IKey))
		}, ErrMalformedHeader},
		{"empty signature", "enroll", func(r *http.Request, _ *[]byte, _ *Verifier) {
			r.Header.Set("Authorization", basicCred(vf.IKey+":"))
		}, ErrBadSignature},
		{"uppercase hex signature", "enroll", func(r *http.Request, _ *[]byte, _ *Verifier) {
			raw, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(r.Header.Get("Authorization"), "Basic "))
			ikey, sig, _ := strings.Cut(string(raw), ":")
			r.Header.Set("Authorization", basicCred(ikey+":"+strings.ToUpper(sig)))
		}, ErrBadSignature},
		{"missing Date", "enroll", func(r *http.Request, _ *[]byte, _ *Verifier) { r.Header.Del("Date") }, ErrMissingDate},
		{"malformed Date", "enroll", func(r *http.Request, _ *[]byte, _ *Verifier) { r.Header.Set("Date", "yesterday") }, ErrMalformedDate},
		{"stale", "enroll", func(_ *http.Request, _ *[]byte, ver *Verifier) {
			ver.Now = func() time.Time { return vf.signedAt().Add(5*time.Minute + time.Second) }
		}, ErrStaleDate},
		{"from the future", "enroll", func(_ *http.Request, _ *[]byte, ver *Verifier) {
			ver.Now = func() time.Time { return vf.signedAt().Add(-5*time.Minute - time.Second) }
		}, ErrStaleDate},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, body := vf.find(t, tc.vector).request()
			ver := vf.verifier(vf.signedAt())
			tc.mutate(r, &body, &ver)
			err := ver.Verify(r, body)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestSignRoundTripsThroughVerify(t *testing.T) {
	vf := loadVectors(t)
	for _, v := range vf.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			want := v.Headers["Authorization"]
			r, body := v.request()
			r.Header.Del("Authorization")
			if err := Sign(r, body, vf.IKey, vf.SKey, vf.Host); err != nil {
				t.Fatal(err)
			}
			if got := r.Header.Get("Authorization"); got != want {
				t.Fatalf("Sign differs from duo_client:\n got %s\nwant %s", got, want)
			}
		})
	}
}
