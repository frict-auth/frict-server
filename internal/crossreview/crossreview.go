// Package crossreview posts the `cross-review` commit status as the
// frict-cross-review GitHub App: App JWT -> installation token scoped to one
// repo with statuses:write -> commit status.
package crossreview

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Context is the commit status context the ruleset requires.
const Context = "cross-review"

const maxResponseBytes = 1 << 20

var (
	shaRE  = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
	nameRE = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
)

// ValidateSHA accepts only a full 40-hex commit SHA.
func ValidateSHA(sha string) error {
	if !shaRE.MatchString(sha) {
		return fmt.Errorf("sha %q is not a full 40-character hex commit SHA", sha)
	}
	return nil
}

// ValidateState accepts the four states GitHub's status API defines.
func ValidateState(state string) error {
	switch state {
	case "pending", "success", "failure", "error":
		return nil
	}
	return fmt.Errorf("state %q is not one of pending, success, failure, error", state)
}

// ParseRepo splits "owner/name".
func ParseRepo(s string) (owner, name string, err error) {
	owner, name, ok := strings.Cut(s, "/")
	if !ok || !validName(owner) || !validName(name) {
		return "", "", fmt.Errorf("repo %q is not of the form owner/name", s)
	}
	return owner, name, nil
}

func validName(s string) bool {
	return nameRE.MatchString(s) && s != "." && s != ".."
}

// LoadKey reads a PEM RSA private key (PKCS#1 or PKCS#8), refusing files that
// grant any permission to group or other.
func LoadKey(path string) (*rsa.PrivateKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening key file: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat key file %s: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("key file %s is not a regular file", path)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("key file %s has mode %04o; it must not be accessible by group or other (chmod 600)", path, perm)
	}
	data, err := io.ReadAll(io.LimitReader(f, 64<<10))
	if err != nil {
		return nil, fmt.Errorf("reading key file %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("key file %s contains no PEM block", path)
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("key file %s: parsing PKCS#1 key: %w", path, err)
		}
		return k, nil
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("key file %s: parsing PKCS#8 key: %w", path, err)
		}
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key file %s holds a %T, want an RSA key", path, k)
		}
		return rk, nil
	}
	return nil, fmt.Errorf("key file %s has PEM type %q, want RSA PRIVATE KEY or PRIVATE KEY", path, block.Type)
}

// AppJWT signs the App's RS256 JWT: iat backdated 60 s for clock drift, exp
// 9 min ahead (GitHub caps it at 10).
func AppJWT(appID int64, key *rsa.PrivateKey, now time.Time) (string, error) {
	enc := base64.RawURLEncoding
	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(map[string]any{
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": strconv.FormatInt(appID, 10),
	})
	if err != nil {
		return "", err
	}
	signingInput := enc.EncodeToString(header) + "." + enc.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("signing app JWT: %w", err)
	}
	return signingInput + "." + enc.EncodeToString(sig), nil
}

// Status is what gets posted under Context.
type Status struct {
	State       string
	Description string
	TargetURL   string
}

// Created is the subset of GitHub's status response worth reporting.
type Created struct {
	ID      int64  `json:"id"`
	URL     string `json:"url"`
	State   string `json:"state"`
	Context string `json:"context"`
	Creator struct {
		Login string `json:"login"`
	} `json:"creator"`
}

// APIError is a non-2xx GitHub response.
type APIError struct {
	Op      string
	Code    int
	Message string
}

func (e *APIError) Error() string {
	msg := e.Message
	if msg == "" {
		msg = "(no message in response)"
	}
	return fmt.Sprintf("%s: HTTP %d %s: %s", e.Op, e.Code, http.StatusText(e.Code), msg)
}

// Client talks to the GitHub REST API as the App.
type Client struct {
	BaseURL string // e.g. https://api.github.com
	HTTP    *http.Client
	AppID   int64
	Key     *rsa.PrivateKey
	Now     func() time.Time
}

// PostStatus validates sha and status, then posts the status as the App.
func (c *Client) PostStatus(ctx context.Context, owner, repo, sha string, st Status) (*Created, error) {
	if err := ValidateSHA(sha); err != nil {
		return nil, err
	}
	if err := ValidateState(st.State); err != nil {
		return nil, err
	}
	jwt, err := AppJWT(c.AppID, c.Key, c.Now())
	if err != nil {
		return nil, err
	}

	var inst struct {
		ID int64 `json:"id"`
	}
	if err := c.do(ctx, "looking up App installation for "+owner+"/"+repo, "GET",
		"/repos/"+owner+"/"+repo+"/installation", jwt, nil, http.StatusOK, &inst); err != nil {
		return nil, err
	}
	if inst.ID == 0 {
		return nil, errors.New("installation lookup returned no installation id")
	}

	tokenReq := map[string]any{
		"repositories": []string{repo},
		"permissions":  map[string]string{"statuses": "write"},
	}
	var tok struct {
		Token string `json:"token"`
	}
	if err := c.do(ctx, "creating installation token", "POST",
		"/app/installations/"+strconv.FormatInt(inst.ID, 10)+"/access_tokens", jwt, tokenReq, http.StatusCreated, &tok); err != nil {
		return nil, err
	}
	if tok.Token == "" {
		return nil, errors.New("installation token response held no token")
	}

	body := map[string]string{"state": st.State, "context": Context}
	if st.Description != "" {
		body["description"] = st.Description
	}
	if st.TargetURL != "" {
		body["target_url"] = st.TargetURL
	}
	var created Created
	if err := c.do(ctx, "posting "+Context+" status on "+sha, "POST",
		"/repos/"+owner+"/"+repo+"/statuses/"+sha, tok.Token, body, http.StatusCreated, &created); err != nil {
		return nil, err
	}
	return &created, nil
}

func (c *Client) do(ctx context.Context, op, method, path, bearer string, reqBody any, want int, out any) error {
	var rd io.Reader
	if reqBody != nil {
		b, err := json.Marshal(reqBody)
		if err != nil {
			return fmt.Errorf("%s: encoding request: %w", op, err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.BaseURL, "/")+path, rd)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "frict-cross-review-status")
	req.Header.Set("Authorization", "Bearer "+bearer)
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("%s: reading response: %w", op, err)
	}
	if resp.StatusCode != want {
		var e struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(data, &e) // a non-JSON error body leaves Message empty
		return &APIError{Op: op, Code: resp.StatusCode, Message: e.Message}
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%s: decoding HTTP %d response: %w", op, resp.StatusCode, err)
	}
	return nil
}
