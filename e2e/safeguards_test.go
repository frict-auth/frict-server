//go:build e2e

package e2e

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestNotMeTwicePauses: with the default FRICT_NOT_ME_COUNT of 2, one "I
// didn't start this" leaves pushes on; a second pauses them, so Authentik's
// next login attempt is denied at once, without a push.
func TestNotMeTwicePauses(t *testing.T) {
	username, d := enrolledUser(t, "fiona")
	for range 2 {
		b, c, _ := pushLogin(t, username, d, func(id string) { answerOrError(t, d, id, "deny", "not_me", http.StatusOK) })
		expectDenied(t, b, c, username, "fraud")
	}

	retry := newBrowser(t)
	c := retry.expect(retry.passwordStep(username), "ak-stage-authenticator-validate")
	uid := duoDeviceUID(t, c)
	start := time.Now()
	c = retry.do("POST", map[string]any{"component": "ak-stage-authenticator-validate", "duo": uid})
	elapsed := time.Since(start)
	resp := expectDenied(t, retry, c, username, "locked_out")
	if msg, _ := resp["status_msg"].(string); !strings.Contains(msg, "paused") {
		t.Fatalf("locked_out status_msg %q does not say pushes are paused", msg)
	}
	if elapsed > 10*time.Second {
		t.Fatalf("paused login took %s: frict-server waited on a push", elapsed)
	}
	if ids, err := d.pending(); err != nil || len(ids) != 0 {
		t.Fatalf("phone after the paused login: %v (err %v), want no challenge", ids, err)
	}
}

// TestRemovedPhoneIsUnknownToAuthentik: after the phone removes itself,
// Authentik's next push login gets Duo's unknown-user answer (400, 40002),
// which Authentik records as a configuration error, and frict-server logs
// the rejected /auth as a security event.
func TestRemovedPhoneIsUnknownToAuthentik(t *testing.T) {
	username, d := enrolledUser(t, "remy")
	if status, body := d.remove(); status != http.StatusOK || body != "{}" {
		t.Fatalf("remove: %d %s, want 200 {}", status, body)
	}
	if status, body := d.remove(); status != http.StatusUnauthorized || body != `{"error":"unauthorized"}` {
		t.Fatalf("second remove: %d %s, want 401 unauthorized", status, body)
	}

	login := newBrowser(t)
	c := login.expect(login.passwordStep(username), "ak-stage-authenticator-validate")
	c = login.do("POST", map[string]any{"component": "ak-stage-authenticator-validate", "duo": duoDeviceUID(t, c)})
	login.expect(c, "ak-stage-authenticator-validate")
	if errs := c.ResponseErrors["duo"]; len(errs) == 0 || errs[0].String != "Duo denied access" {
		t.Fatalf("want 'Duo denied access' on the duo field: %s", c.raw)
	}
	if status, who := login.whoami(); status == 200 {
		t.Fatalf("login for a removed phone produced a session for %q", who)
	}

	var events struct {
		Results []struct {
			Context map[string]any `json:"context"`
		} `json:"results"`
	}
	if err := admin("GET", "/api/v3/events/events/?action=configuration_error&username="+url.QueryEscape(username), nil, &events); err != nil {
		t.Fatal(err)
	}
	const want = "Failed to DUO authenticate user: Received 400 Invalid request parameters: user_id"
	found := false
	for _, e := range events.Results {
		found = found || e.Context["message"] == want
	}
	if !found {
		t.Fatalf("no configuration_error event %q for %s; got %+v", want, username, events.Results)
	}

	out, err := composeCmd("logs", "--no-color", "frict-server").CombinedOutput()
	if err != nil {
		t.Fatalf("frict-server logs: %v\n%s", err, out)
	}
	line := "msg=security event=duo_request_rejected endpoint=/auth/v2/auth reason=unknown_user user_id=" + d.act.UserID + " client_ip="
	if !strings.Contains(string(out), line) {
		t.Fatalf("frict-server logged no %q", line)
	}
}
