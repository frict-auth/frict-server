//go:build e2e

// Package e2e logs in through a real Authentik whose Duo stages point at the
// duo-stub, using Authentik's flow-executor API. Run it via e2e/run.sh.
package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	duoHostname = "duo.frict.test"
	duoClientID = "DIFRICTE2E0000000000"
)

var env struct {
	baseURL     string
	adminToken  string
	duoSecret   string
	stubDelay   time.Duration
	suffix      string
	flowSlug    string
	goodDuoPK   string
	badDuoPK    string
	userPass    string
	adminClient *http.Client
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
	if env.baseURL == "" || os.Getenv("FRICT_E2E_SECRETS_DIR") == "" {
		return fmt.Errorf("FRICT_E2E_AUTHENTIK_URL and FRICT_E2E_SECRETS_DIR must be set (use e2e/run.sh)")
	}
	var err error
	if env.stubDelay, err = time.ParseDuration(os.Getenv("FRICT_STUB_AUTH_DELAY")); err != nil {
		return fmt.Errorf("FRICT_STUB_AUTH_DELAY: %w", err)
	}
	if env.adminToken, err = readSecret("akadmin-token"); err != nil {
		return err
	}
	if env.duoSecret, err = readSecret("duo-client-secret"); err != nil {
		return err
	}
	env.adminClient = &http.Client{Timeout: 30 * time.Second}
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
	if env.goodDuoPK, err = stage("authenticator/duo", map[string]any{
		"name": name("duo"), "client_id": duoClientID, "client_secret": env.duoSecret, "api_hostname": duoHostname,
	}); err != nil {
		return err
	}
	if env.badDuoPK, err = stage("authenticator/duo", map[string]any{
		"name": name("duo-wrong-secret"), "client_id": duoClientID, "client_secret": env.duoSecret + "-wrong", "api_hostname": duoHostname,
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
		"not_configured_action": "configure", "configuration_stages": []string{env.goodDuoPK},
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
	for i, st := range []string{ident, pass, validate, login} {
		if err := admin("POST", "/api/v3/flows/bindings/", map[string]any{
			"target": flow.PK, "stage": st, "order": (i + 1) * 10,
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
	var u struct{ PK int }
	if err := admin("POST", "/api/v3/core/users/", map[string]any{"username": username, "name": username}, &u); err != nil {
		t.Fatal(err)
	}
	if err := admin("POST", fmt.Sprintf("/api/v3/core/users/%d/set_password/", u.PK), map[string]any{"password": env.userPass}, nil); err != nil {
		t.Fatal(err)
	}
	return username, u.PK
}

// challenge is the subset of Authentik's flow challenge JSON the tests read.
type challenge struct {
	Component         string `json:"component"`
	To                string `json:"to"`
	ActivationBarcode string `json:"activation_barcode"`
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

// TestDuoPushSurvivesStubDelay proves M0 (c): Authentik waits for a /auth
// call that blocks for FRICT_STUB_AUTH_DELAY and then logs the user in.
// The first login enrolls through the Duo setup stage (enroll + enroll_status
// against the stub); the second performs the push.
func TestDuoPushSurvivesStubDelay(t *testing.T) {
	username, userPK := createUser(t, "alice")

	enrollment := newBrowser(t)
	c := enrollment.expect(enrollment.passwordStep(username), "ak-stage-authenticator-duo")
	if !strings.Contains(c.ActivationBarcode, duoHostname) {
		t.Fatalf("activation barcode did not come from the stub: %s", c.raw)
	}
	enrollment.expect(enrollment.do("POST", map[string]any{"component": "ak-stage-authenticator-duo"}), "xak-flow-redirect")

	var devices struct{ Results []struct{ PK int } }
	if err := admin("GET", fmt.Sprintf("/api/v3/authenticators/admin/duo/?user=%d", userPK), nil, &devices); err != nil {
		t.Fatal(err)
	}
	if len(devices.Results) != 1 {
		t.Fatalf("user has %d Duo devices after enrollment, want 1", len(devices.Results))
	}

	login := newBrowser(t)
	c = login.expect(login.passwordStep(username), "ak-stage-authenticator-validate")
	uid := duoDeviceUID(t, c)

	start := time.Now()
	c = login.do("POST", map[string]any{"component": "ak-stage-authenticator-validate", "duo": uid})
	elapsed := time.Since(start)
	t.Logf("Duo push round trip through Authentik: %s (stub delay %s)", elapsed.Round(time.Millisecond), env.stubDelay)

	login.expect(c, "xak-flow-redirect")
	if elapsed < env.stubDelay {
		t.Fatalf("push returned after %s, before the stub's %s delay: Authentik did not wait for /auth", elapsed, env.stubDelay)
	}
	if status, who := login.whoami(); status != 200 || who != username {
		t.Fatalf("after push login, users/me = %d %q, want 200 %q", status, who, username)
	}
}

// TestWrongClientSecretFailsLogin proves M0 (a) end to end: a Duo stage
// configured with the wrong client secret signs requests the stub rejects,
// and Authentik refuses the login.
func TestWrongClientSecretFailsLogin(t *testing.T) {
	username, _ := createUser(t, "mallory")
	if err := admin("POST", "/api/v3/stages/authenticator/duo/"+env.badDuoPK+"/import_device_manual/",
		map[string]any{"duo_user_id": "DUMALLORY", "username": username}, nil); err != nil {
		t.Fatal(err)
	}

	login := newBrowser(t)
	c := login.expect(login.passwordStep(username), "ak-stage-authenticator-validate")
	uid := duoDeviceUID(t, c)

	start := time.Now()
	c = login.do("POST", map[string]any{"component": "ak-stage-authenticator-validate", "duo": uid})
	elapsed := time.Since(start)

	login.expect(c, "ak-stage-authenticator-validate")
	if errs := c.ResponseErrors["duo"]; len(errs) == 0 || errs[0].String != "Duo denied access" {
		t.Fatalf("want 'Duo denied access' on the duo field: %s", c.raw)
	}
	if elapsed >= env.stubDelay {
		t.Fatalf("rejection took %s, at least the stub's push delay: the stub ran /auth instead of rejecting", elapsed)
	}
	if status, who := login.whoami(); status == 200 {
		t.Fatalf("login with a wrong Duo secret produced a session for %q", who)
	}

	var events struct {
		Results []struct {
			Context map[string]any `json:"context"`
		} `json:"results"`
	}
	if err := admin("GET", "/api/v3/events/events/?action=configuration_error&username="+url.QueryEscape(username), nil, &events); err != nil {
		t.Fatal(err)
	}
	const want = "Failed to DUO authenticate user: Received 401 Invalid signature in request credentials"
	for _, e := range events.Results {
		if e.Context["message"] == want {
			return
		}
	}
	t.Fatalf("no configuration_error event %q for %s; got %+v", want, username, events.Results)
}
