//go:build e2e

package e2e

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/frict-auth/frict-server/internal/fakephone"
)

const updateRequired = `{"error":"app_update_required","min_version":1000}`

// TestOutdatedAppGetsNoPush: frict-server runs with FRICT_MIN_APP_VERSION
// 1000. A phone whose last request carried 999 gets 426, and Authentik's
// next push login is denied at once, without a push, with a status_msg
// asking for an update. Once the updated app makes a request, logins push
// again.
func TestOutdatedAppGetsNoPush(t *testing.T) {
	username, d := enrolledUser(t, "olga")
	d.phone.AppVersion = fakephone.AppVersion - 1
	if _, err := d.poll(); err == nil || !strings.Contains(err.Error(), "426 "+updateRequired) {
		t.Fatalf("poll from version 999: %v, want 426 %s", err, updateRequired)
	}

	login := newBrowser(t)
	c := login.expect(login.passwordStep(username), "ak-stage-authenticator-validate")
	start := time.Now()
	c = login.do("POST", map[string]any{"component": "ak-stage-authenticator-validate", "duo": duoDeviceUID(t, c)})
	elapsed := time.Since(start)
	resp := expectDenied(t, login, c, username, "deny")
	if msg, _ := resp["status_msg"].(string); !strings.Contains(msg, "update it from Google Play") {
		t.Fatalf("status_msg %q does not ask for an update", msg)
	}
	if elapsed > 10*time.Second {
		t.Fatalf("outdated login took %s: frict-server waited on a push", elapsed)
	}

	d.phone.AppVersion = fakephone.AppVersion
	if ids, err := d.pending(); err != nil || len(ids) != 0 {
		t.Fatalf("updated phone after the refused login: %v (err %v), want no challenge", ids, err)
	}
	b, c, _ := pushLogin(t, username, d, func(id string) { answerOrError(t, d, id, "approve", "", http.StatusOK) })
	expectLoggedIn(t, b, c, username)

	out, err := composeCmd("logs", "--no-color", "frict-server").CombinedOutput()
	if err != nil {
		t.Fatalf("frict-server logs: %v\n%s", err, out)
	}
	for _, line := range []string{
		`msg="app update required" endpoint=/device/v1/pending reason=below_minimum app_version=999 min_app_version=1000 user_id=` + d.act.UserID,
		`msg="push refused" user_id=` + d.act.UserID + ` lock=outdated min_app_version=1000`,
	} {
		if !strings.Contains(string(out), line) {
			t.Errorf("frict-server logged no %q", line)
		}
	}
}

// TestOutdatedAppEnrollsAfterUpdate: an enrollment without a version header,
// the app before this check, gets 426 and leaves the activation code unspent,
// so the updated app enrolls with the same code.
func TestOutdatedAppEnrollsAfterUpdate(t *testing.T) {
	username, _ := createUser(t, "otto")
	b := newBrowser(t)
	c := b.expect(b.passwordStep(username), "ak-stage-authenticator-duo")
	act, err := fakephone.ParseActivation(c.ActivationCode)
	if err != nil {
		t.Fatalf("activation_code: %v; challenge %s", err, c.raw)
	}
	phone, err := fakephone.New()
	if err != nil {
		t.Fatal(err)
	}
	phone.AppVersion = 0
	if status, body := enrollPhone(phone, act); status != http.StatusUpgradeRequired || body != updateRequired {
		t.Fatalf("enroll without a version: %d %s, want 426 %s", status, body, updateRequired)
	}
	phone.AppVersion = fakephone.AppVersion
	if status, body := enrollPhone(phone, act); status != http.StatusOK {
		t.Fatalf("enroll after update: %d %s", status, body)
	}
	b.expect(b.do("POST", map[string]any{"component": "ak-stage-authenticator-duo"}), "xak-flow-redirect")
}
