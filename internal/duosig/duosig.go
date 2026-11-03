// Package duosig verifies Duo Auth API request signatures (sig version 5),
// as produced by duo_client_python's Client.api_call.
package duosig

import (
	"crypto/hmac"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"net/url"
	"sort"
	"strings"
	"time"
)

var (
	ErrMissingCredentials = errors.New("missing Authorization header")
	ErrMalformedHeader    = errors.New("malformed Authorization header")
	ErrUnknownIKey        = errors.New("unknown integration key")
	ErrMissingDate        = errors.New("missing Date header")
	ErrMalformedDate      = errors.New("malformed Date header")
	ErrStaleDate          = errors.New("Date header outside allowed clock skew")
	ErrBadXDuoHeader      = errors.New("X-Duo-* header repeated")
	ErrBadSignature       = errors.New("signature mismatch")
)

// Verifier checks requests signed for one integration.
type Verifier struct {
	IKey    string
	SKey    string
	Host    string // API hostname as configured in the client, e.g. "api.frict.app"
	MaxSkew time.Duration
	Now     func() time.Time
}

// Verify returns nil only if r carries a valid sig v5 signature over its
// method, path, query, body and X-Duo-* headers, made with v.SKey within
// v.MaxSkew of v.Now. body is the full request body already read from r.
func (v Verifier) Verify(r *http.Request, body []byte) error {
	ikey, sig, err := parseAuthorization(r.Header.Get("Authorization"))
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(ikey), []byte(v.IKey)) != 1 {
		return ErrUnknownIKey
	}

	date := r.Header.Get("Date")
	if date == "" {
		return ErrMissingDate
	}
	t, err := mail.ParseDate(date)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMalformedDate, err)
	}
	if skew := v.Now().Sub(t); skew > v.MaxSkew || skew < -v.MaxSkew {
		return fmt.Errorf("%w: %s", ErrStaleDate, skew)
	}

	canon, err := canonical(r, body, date, v.Host)
	if err != nil {
		return err
	}
	if !hmac.Equal([]byte(sig), []byte(signature(v.SKey, canon))) {
		return ErrBadSignature
	}
	return nil
}

// Sign sets r's Authorization header to a sig v5 signature, using the Date
// header already on r. It is the inverse of Verify.
func Sign(r *http.Request, body []byte, ikey, skey, host string) error {
	canon, err := canonical(r, body, r.Header.Get("Date"), host)
	if err != nil {
		return err
	}
	cred := base64.StdEncoding.EncodeToString([]byte(ikey + ":" + signature(skey, canon)))
	r.Header.Set("Authorization", "Basic "+cred)
	return nil
}

func parseAuthorization(h string) (ikey, sig string, err error) {
	if h == "" {
		return "", "", ErrMissingCredentials
	}
	b64, ok := strings.CutPrefix(h, "Basic ")
	if !ok {
		return "", "", ErrMalformedHeader
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", "", ErrMalformedHeader
	}
	ikey, sig, ok = strings.Cut(string(raw), ":")
	if !ok {
		return "", "", ErrMalformedHeader
	}
	return ikey, sig, nil
}

func signature(skey, canon string) string {
	mac := hmac.New(sha512.New, []byte(skey))
	mac.Write([]byte(canon))
	return hex.EncodeToString(mac.Sum(nil))
}

func canonical(r *http.Request, body []byte, date, host string) (string, error) {
	xduo, err := canonXDuoHeaders(r.Header)
	if err != nil {
		return "", err
	}
	bodyHash := sha512.Sum512(body)
	return strings.Join([]string{
		date,
		strings.ToUpper(r.Method),
		strings.ToLower(host),
		r.URL.Path,
		canonParams(r.URL.Query()),
		hex.EncodeToString(bodyHash[:]),
		xduo,
	}, "\n"), nil
}

// canonParams matches duo_client's canon_params: keys and values
// percent-encoded leaving only RFC 3986 unreserved characters, sorted by
// encoded key then encoded value.
func canonParams(q url.Values) string {
	keys := make([]string, 0, len(q))
	enc := make(map[string][]string, len(q))
	for k, vs := range q {
		ek := quote(k)
		keys = append(keys, ek)
		for _, v := range vs {
			enc[ek] = append(enc[ek], quote(v))
		}
	}
	sort.Strings(keys)
	var args []string
	for _, k := range keys {
		vs := enc[k]
		sort.Strings(vs)
		for _, v := range vs {
			args = append(args, k+"="+v)
		}
	}
	return strings.Join(args, "&")
}

func quote(s string) string {
	const hexdigits = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' ||
			c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexdigits[c>>4])
		b.WriteByte(hexdigits[c&0xf])
	}
	return b.String()
}

// canonXDuoHeaders matches duo_client's canon_x_duo_headers: lower-cased
// X-Duo-* names sorted, joined with their values by NUL, then SHA-512.
func canonXDuoHeaders(h http.Header) (string, error) {
	var names []string
	for name, vals := range h {
		lname := strings.ToLower(name)
		if !strings.HasPrefix(lname, "x-duo-") {
			continue
		}
		if len(vals) != 1 {
			return "", ErrBadXDuoHeader
		}
		names = append(names, lname)
	}
	sort.Strings(names)
	parts := make([]string, 0, 2*len(names))
	for _, n := range names {
		parts = append(parts, n, h.Get(n))
	}
	sum := sha512.Sum512([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:]), nil
}
