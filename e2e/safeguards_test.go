//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/frict-auth/frict-server/internal/fakephone"
)

// TestNotMePausesAndAlertsAdmin: "I didn't start this" pauses the user's
// pushes, so Authentik's next login attempt is denied without a push, and
// the admin's phone, enrolled as akadmin (the default alert recipient),
// receives an alert about it on its next poll.
func TestNotMePausesAndAlertsAdmin(t *testing.T) {
	adminPhone, err := enrollViaDuoAPI("akadmin")
	if err != nil {
		t.Fatal(err)
	}
	username, d := enrolledUser(t, "fiona")
	b, c, _ := pushLogin(t, username, d, func(id string) { answerOrError(t, d, id, "deny", "not_me", http.StatusOK) })
	expectDenied(t, b, c, username, "fraud")

	retry := newBrowser(t)
	c = retry.expect(retry.passwordStep(username), "ak-stage-authenticator-validate")
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
	if p, err := d.poll(); err != nil || len(p.ChallengeIDs) != 0 || len(p.Alerts) != 0 {
		t.Fatalf("user's phone after the paused login: %+v (err %v), want no challenge and no alert", p, err)
	}

	p, err := adminPhone.poll()
	if err != nil {
		t.Fatal(err)
	}
	var found []fakephone.Alert
	for _, a := range p.Alerts {
		if a.Username == username {
			found = append(found, a)
		}
	}
	if len(found) != 1 {
		t.Fatalf("admin alerts for %s: %+v, want 1 (all alerts %+v)", username, found, p.Alerts)
	}
	a := found[0]
	t.Logf("alert as the admin's phone sees it: %+v", a)
	if a.IPAddr == "" || !strings.Contains(a.PushInfo, "Domain=") || a.Type == "" || a.Attempted == 0 || a.Reported < a.Attempted {
		t.Fatalf("alert %+v lacks Authentik's sign-in fields", a)
	}
	for name, link := range map[string]string{"reset_password_url": a.ResetPasswordURL, "revoke_sessions_url": a.RevokeSessionsURL} {
		frag, ok := strings.CutPrefix(link, env.baseURL+"/if/admin/#/identity/users;")
		if !ok {
			t.Fatalf("%s %q does not open %s's admin user list", name, link, env.baseURL)
		}
		raw, err := url.PathUnescape(frag)
		var params map[string]string
		if err != nil || json.Unmarshal([]byte(raw), &params) != nil || params["ak-user-list-search"] != username {
			t.Fatalf("%s %q does not search for %s", name, link, username)
		}
	}
	var users struct {
		Results []struct{ Username string } `json:"results"`
	}
	if err := admin("GET", "/api/v3/core/users/?search="+url.QueryEscape(username), nil, &users); err != nil {
		t.Fatal(err)
	}
	if len(users.Results) != 1 || users.Results[0].Username != username {
		t.Fatalf("Authentik's user search for %q, the one the admin link sets, found %+v", username, users.Results)
	}
}
