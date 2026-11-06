//go:build e2e

// Package e2e logs in through a real Authentik using its flow-executor API,
// with frict-server as its Duo API and a fake phone that enrolls, polls for
// challenges and answers them. Run it via e2e/run.sh.
package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/frict-auth/frict-server/internal/fakephone"
)

const (
	frictHostname = "frict.frict.test"
	duoClientID   = "DIFRICTE2E0000000000"
)

var env struct {
	baseURL      string
	composeFile  string
	adminToken   string
	duoSecret    string
	answerDelay  time.Duration // how long the phone takes to answer a push in the slow-human tests
	challengeTTL time.Duration // frict-server's FRICT_CHALLENGE_TTL
	suffix       string
	flowSlug     string
	badDuoPK     string
	frictDuoPK   string
	phoneClient  *http.Client
	userPass     string
	adminClient  *http.Client
}

func TestMain(m *testing.M) {
	if err := setup(); err != nil {
		fmt.Fprintln(os.Stderr, "e2e setup:", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func readSecret(name string) (string, error) {
	b, err := os.ReadFile(filepath.Join(os.Getenv("FRICT_E2E_SECRETS_DIR"), name))
	return strings.TrimSpace(string(b)), err
}

func setup() error {
	env.baseURL = os.Getenv("FRICT_E2E_AUTHENTIK_URL")
	env.composeFile = os.Getenv("FRICT_E2E_COMPOSE_FILE")
	if env.baseURL == "" || env.composeFile == "" || os.Getenv("FRICT_E2E_SECRETS_DIR") == "" {
		return fmt.Errorf("FRICT_E2E_AUTHENTIK_URL, FRICT_E2E_COMPOSE_FILE and FRICT_E2E_SECRETS_DIR must be set (use e2e/run.sh)")
	}
	var err error
	if env.answerDelay, err = time.ParseDuration(os.Getenv("FRICT_E2E_ANSWER_DELAY")); err != nil {
		return fmt.Errorf("FRICT_E2E_ANSWER_DELAY: %w", err)
	}
	if env.challengeTTL, err = time.ParseDuration(os.Getenv("FRICT_CHALLENGE_TTL")); err != nil {
		return fmt.Errorf("FRICT_CHALLENGE_TTL: %w", err)
	}
	if env.answerDelay+10*time.Second > env.challengeTTL {
		return fmt.Errorf("FRICT_E2E_ANSWER_DELAY=%s leaves under 10s before FRICT_CHALLENGE_TTL=%s", env.answerDelay, env.challengeTTL)
	}
	if env.adminToken, err = readSecret("akadmin-token"); err != nil {
		return err
	}
	if env.duoSecret, err = readSecret("duo-client-secret"); err != nil {
		return err
	}
	env.adminClient = &http.Client{Timeout: 30 * time.Second}
	if env.phoneClient, err = newPhoneClient(os.Getenv("FRICT_E2E_FRICT_ADDR")); err != nil {
		return err
	}
	env.suffix = fmt.Sprintf("%d", time.Now().Unix())
	env.flowSlug = "frict-m0-" + env.suffix
	env.userPass = "pw-" + env.suffix + "-not-secret"

	if err := waitForAPI(3 * time.Minute); err != nil {
		return err
	}

	name := func(s string) string { return "frict-m0-" + s + "-" + env.suffix }
	stage := func(kind string, body map[string]any) (string, error) {
		var out struct{ PK string }
		err := admin("POST", "/api/v3/stages/"+kind+"/", body, &out)
		return out.PK, err
	}
	if env.frictDuoPK, err = stage("authenticator/duo", map[string]any{
		"name": name("frict"), "client_id": duoClientID, "client_secret": env.duoSecret, "api_hostname": frictHostname,
	}); err != nil {
		return err
	}
	if env.badDuoPK, err = stage("authenticator/duo", map[string]any{
		"name": name("duo-wrong-secret"), "client_id": duoClientID, "client_secret": env.duoSecret + "-wrong", "api_hostname": frictHostname,
	}); err != nil {
		return err
	}
	ident, err := stage("identification", map[string]any{"name": name("ident"), "user_fields": []string{"username"}})
	if err != nil {
		return err
	}
	pass, err := stage("password", map[string]any{"name": name("password"), "backends": []string{"authentik.core.auth.InbuiltBackend"}})
	if err != nil {
		return err
	}
	validate, err := stage("authenticator/validate", map[string]any{
		"name": name("validate"), "device_classes": []string{"duo"},
		"not_configured_action": "configure", "configuration_stages": []string{env.frictDuoPK},
	})
	if err != nil {
		return err
	}
	login, err := stage("user_login", map[string]any{"name": name("login")})
	if err != nil {
		return err
	}

	var flow struct{ PK string }
	if err := admin("POST", "/api/v3/flows/instances/", map[string]any{
		"name": name("flow"), "slug": env.flowSlug, "title": "Frict M0", "designation": "authentication",
	}, &flow); err != nil {
		return err
	}
	if err := bindStages(flow.PK, ident, pass, validate, login); err != nil {
		return err
	}
	return setupLDAP(stage, ident, pass, login)
}

// newPhoneClient returns the fake phone's HTTPS client: it trusts only the
// test CA and reaches frict.frict.test at addr, the TLS front's published
// port, since the host cannot resolve compose names.
func newPhoneClient(addr string) (*http.Client, error) {
	if addr == "" {
		return nil, fmt.Errorf("FRICT_E2E_FRICT_ADDR must be set (use e2e/run.sh)")
	}
	caPEM, err := os.ReadFile(filepath.Join(os.Getenv("FRICT_E2E_SECRETS_DIR"), "ca.pem"))
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("no certificates in ca.pem")
	}
	var d net.Dialer
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: roots},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return d.DialContext(ctx, network, addr)
			},
		},
	}, nil
}

func bindStages(flowPK string, stages ...string) error {
	for i, st := range stages {
		if err := admin("POST", "/api/v3/flows/bindings/", map[string]any{
			"target": flowPK, "stage": st, "order": (i + 1) * 10,
		}, nil); err != nil {
			return err
		}
	}
	return nil
}

func waitForAPI(limit time.Duration) error {
	deadline := time.Now().Add(limit)
	var last error
	for time.Now().Before(deadline) {
		var me struct{ User struct{ Username string } }
		if last = admin("GET", "/api/v3/core/users/me/", nil, &me); last == nil {
			if me.User.Username != "akadmin" {
				return fmt.Errorf("bootstrap token belongs to %q, want akadmin", me.User.Username)
			}
			return nil
		}
		time.Sleep(3 * time.Second)
	}
	return fmt.Errorf("authentik API not ready after %s: %w", limit, last)
}

// admin calls the Authentik API with the bootstrap token and decodes a 2xx
// JSON reply into out (if non-nil).
func admin(method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, env.baseURL+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+env.adminToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := env.adminClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s %s: %d %s", method, path, resp.StatusCode, raw)
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

func createUser(t *testing.T, prefix string) (username string, pk int) {
	t.Helper()
	username = prefix + "-" + env.suffix
	pk, err := newUser(map[string]any{"username": username, "name": username}, env.userPass)
	if err != nil {
		t.Fatal(err)
	}
	return username, pk
}

// newUser creates a user from the given API fields and sets its password.
func newUser(fields map[string]any, password string) (int, error) {
	var u struct{ PK int }
	if err := admin("POST", "/api/v3/core/users/", fields, &u); err != nil {
		return 0, err
	}
	return u.PK, admin("POST", fmt.Sprintf("/api/v3/core/users/%d/set_password/", u.PK), map[string]any{"password": password}, nil)
}

// challenge is the subset of Authentik's flow challenge JSON the tests read.
type challenge struct {
	Component         string `json:"component"`
	To                string `json:"to"`
	ActivationBarcode string `json:"activation_barcode"`
	ActivationCode    string `json:"activation_code"`
	StageUUID         string `json:"stage_uuid"`
	DeviceChallenges  []struct {
		DeviceClass string          `json:"device_class"`
		DeviceUID   json.RawMessage `json:"device_uid"`
	} `json:"device_challenges"`
	ResponseErrors map[string][]struct {
		String string `json:"string"`
		Code   string `json:"code"`
	} `json:"response_errors"`
	raw string
}

// browser is one login session against the flow executor API.
type browser struct {
	t      *testing.T
	client *http.Client
	url    string
}

func newBrowser(t *testing.T) *browser {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &browser{
		t:      t,
		client: &http.Client{Jar: jar, Timeout: 10 * time.Minute},
		url:    env.baseURL + "/api/v3/flows/executor/" + env.flowSlug + "/?query=" + url.QueryEscape("next=/"),
	}
}

func (b *browser) do(method string, body any) challenge {
	b.t.Helper()
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			b.t.Fatal(err)
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, b.url, rd)
	if err != nil {
		b.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	start := time.Now()
	resp, err := b.client.Do(req)
	if err != nil {
		b.t.Fatalf("%s flow executor after %s: %v", method, time.Since(start), err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		b.t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		b.t.Fatalf("%s flow executor after %s: %d %s", method, time.Since(start), resp.StatusCode, raw)
	}
	var c challenge
	if err := json.Unmarshal(raw, &c); err != nil {
		b.t.Fatalf("flow executor returned non-JSON: %s", raw)
	}
	c.raw = string(raw)
	return c
}

func (b *browser) expect(c challenge, component string) challenge {
	b.t.Helper()
	if c.Component != component {
		b.t.Fatalf("got component %q, want %q; full challenge: %s", c.Component, component, c.raw)
	}
	return c
}

// passwordStep runs identification and password and returns the challenge
// that follows them.
func (b *browser) passwordStep(username string) challenge {
	b.t.Helper()
	b.expect(b.do("GET", nil), "ak-stage-identification")
	b.expect(b.do("POST", map[string]any{"component": "ak-stage-identification", "uid_field": username}), "ak-stage-password")
	return b.do("POST", map[string]any{"component": "ak-stage-password", "password": env.userPass})
}

func (b *browser) whoami() (status int, username string) {
	b.t.Helper()
	resp, err := b.client.Get(env.baseURL + "/api/v3/core/users/me/")
	if err != nil {
		b.t.Fatal(err)
	}
	defer resp.Body.Close()
	var me struct{ User struct{ Username string } }
	if resp.StatusCode == 200 {
		if err := json.NewDecoder(resp.Body).Decode(&me); err != nil {
			b.t.Fatal(err)
		}
	}
	return resp.StatusCode, me.User.Username
}

func duoDeviceUID(t *testing.T, c challenge) json.RawMessage {
	t.Helper()
	for _, dc := range c.DeviceChallenges {
		if dc.DeviceClass == "duo" {
			return dc.DeviceUID
		}
	}
	t.Fatalf("no duo device challenge offered: %s", c.raw)
	return nil
}

// TestEnrollThroughFrictServer: Authentik's Duo setup stage enrolls against
// frict-server, the setup page's QR code scans as the activation link, a fake
// phone claims the activation over TLS, enroll_status turns from waiting to
// success, and Authentik saves the device. A second phone replaying the same
// activation is refused.
func TestEnrollThroughFrictServer(t *testing.T) {
	username, userPK := createUser(t, "erin")

	b := newBrowser(t)
	c := b.expect(b.passwordStep(username), "ak-stage-authenticator-duo")
	act, err := fakephone.ParseActivation(c.ActivationCode)
	if err != nil {
		t.Fatalf("activation_code from frict-server: %v; challenge %s", err, c.raw)
	}
	if act.Host != frictHostname {
		t.Fatalf("activation host %q, want %q", act.Host, frictHostname)
	}
	if got := scanQR(t, c.ActivationBarcode); got != c.ActivationCode {
		t.Fatalf("activation_barcode scans as %q, want the activation link %q", got, c.ActivationCode)
	}
	if got := b.enrollmentStatus(c.StageUUID); got != "waiting" {
		t.Fatalf("enroll_status before the phone enrolled: %q, want waiting", got)
	}

	phone, err := fakephone.New()
	if err != nil {
		t.Fatal(err)
	}
	if status, body := enrollPhone(phone, act); status != http.StatusOK {
		t.Fatalf("phone enroll: %d %s", status, body)
	}
	if got := b.enrollmentStatus(c.StageUUID); got != "success" {
		t.Fatalf("enroll_status after the phone enrolled: %q, want success", got)
	}
	b.expect(b.do("POST", map[string]any{"component": "ak-stage-authenticator-duo"}), "xak-flow-redirect")
	if n := duoDevices(t, userPK); n != 1 {
		t.Fatalf("user has %d Duo devices after enrollment, want 1", n)
	}

	replay, err := fakephone.New()
	if err != nil {
		t.Fatal(err)
	}
	if status, body := enrollPhone(replay, act); status != http.StatusUnauthorized {
		t.Fatalf("second phone with the same activation: %d %s, want 401", status, body)
	}
}

// scanQR checks that barcode, as the setup page puts it in <img src>, is a
// PNG data URL, and returns what zbarimg reads from the image.
func scanQR(t *testing.T, barcode string) string {
	t.Helper()
	b64, ok := strings.CutPrefix(barcode, "data:image/png;base64,")
	if !ok {
		t.Fatalf("activation_barcode %.80q is not a PNG data URL", barcode)
	}
	img, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("activation_barcode base64: %v", err)
	}
	cmd := composeCmd("run", "--rm", "-T", "zbar")
	cmd.Stdin = bytes.NewReader(img)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("zbarimg: %v; stdout %q; stderr %s", err, stdout.String(), stderr.String())
	}
	return strings.TrimSuffix(stdout.String(), "\n")
}

// enrollmentStatus asks Authentik for the enrollment status, as the setup
// page's script does every 3 s; Authentik relays frict-server's
// enroll_status answer.
func (b *browser) enrollmentStatus(stageUUID string) string {
	b.t.Helper()
	resp, err := b.client.Post(env.baseURL+"/api/v3/stages/authenticator/duo/"+stageUUID+"/enrollment_status/", "application/json", nil)
	if err != nil {
		b.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		b.t.Fatal(err)
	}
	var out struct {
		DuoResponse string `json:"duo_response"`
	}
	if resp.StatusCode != 200 || json.Unmarshal(raw, &out) != nil {
		b.t.Fatalf("enrollment_status: %d %s", resp.StatusCode, raw)
	}
	return out.DuoResponse
}

// duoDevices counts userPK's Duo devices. The admin device list has no user
// filter.
func duoDevices(t *testing.T, userPK int) int {
	t.Helper()
	var devices struct {
		Results []struct{ User struct{ PK int } }
	}
	if err := admin("GET", "/api/v3/authenticators/admin/duo/?page_size=1000", nil, &devices); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, d := range devices.Results {
		if d.User.PK == userPK {
			n++
		}
	}
	return n
}
