// Package fakephone is a scripted Frict app for tests: it holds its own
// P-256 device_key and approval_key and signs device API requests as
// docs/device-protocol.md describes. It shares no code with the server's
// verifier, so a change to one side's signed bytes breaks the other.
package fakephone

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

const EnrollPath = "/device/v1/enroll"

type Phone struct {
	DeviceKey   *ecdsa.PrivateKey
	ApprovalKey *ecdsa.PrivateKey
	FID         string
}

func New() (*Phone, error) {
	dk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	ak, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Phone{DeviceKey: dk, ApprovalKey: ak, FID: "fake-fid-" + rand.Text()}, nil
}

// Activation is what the app reads from an enrollment QR code or link.
type Activation struct {
	Host   string
	UserID string
	Code   string
}

// ParseActivation reads frict://enroll?host=…&user_id=…&code=….
func ParseActivation(link string) (Activation, error) {
	u, err := url.Parse(link)
	if err != nil {
		return Activation{}, err
	}
	if u.Scheme != "frict" || u.Host != "enroll" {
		return Activation{}, fmt.Errorf("%q is not a frict://enroll link", link)
	}
	q := u.Query()
	a := Activation{Host: q.Get("host"), UserID: q.Get("user_id"), Code: q.Get("code")}
	if a.Host == "" || a.UserID == "" || a.Code == "" {
		return Activation{}, fmt.Errorf("%q lacks host, user_id or code", link)
	}
	return a, nil
}

// EnrollBody is the JSON body of an enroll request for code. The attestation
// chains are placeholders: the server stores them unverified.
func (p *Phone) EnrollBody(code string) ([]byte, error) {
	dk, err := spki(&p.DeviceKey.PublicKey)
	if err != nil {
		return nil, err
	}
	ak, err := spki(&p.ApprovalKey.PublicKey)
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{
		"activation_code": code,
		"device_key":      dk,
		"approval_key":    ak,
		"attestation": map[string][]string{
			"device_key":   {b64("fake device_key attestation leaf"), b64("fake root")},
			"approval_key": {b64("fake approval_key attestation leaf"), b64("fake root")},
		},
		"fid": p.FID,
	})
}

// EnrollRequest is a signed POST to https://<a.Host>/device/v1/enroll
// claiming a for this phone, signed with its device_key at now.
func (p *Phone) EnrollRequest(a Activation, now time.Time) (*http.Request, error) {
	body, err := p.EnrollBody(a.Code)
	if err != nil {
		return nil, err
	}
	return SignedRequest("https://"+a.Host, EnrollPath, a.UserID, now.Unix(), body, p.DeviceKey)
}

// SignedRequest builds a POST to base+path whose Authorization header claims
// userID and unix and carries key's signature over the protocol's signed
// bytes for exactly those values.
func SignedRequest(base, path, userID string, unix int64, body []byte, key *ecdsa.PrivateKey) (*http.Request, error) {
	sig, err := Sign(key, userID, unix, path, body)
	if err != nil {
		return nil, err
	}
	r, err := http.NewRequest(http.MethodPost, base+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", fmt.Sprintf("Frict-P256 %s:%d:%s", userID, unix, sig))
	return r, nil
}

// Sign returns the base64url DER ECDSA-SHA256 signature over
// "frict-device-v1\n<user_id>\n<unix>\n<path>\n<body>".
func Sign(key *ecdsa.PrivateKey, userID string, unix int64, path string, body []byte) (string, error) {
	var msg bytes.Buffer
	fmt.Fprintf(&msg, "frict-device-v1\n%s\n%d\n%s\n", userID, unix, path)
	msg.Write(body)
	digest := sha256.Sum256(msg.Bytes())
	der, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		return "", err
	}
	return b64(string(der)), nil
}

func spki(pub *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	return b64(string(der)), nil
}

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
