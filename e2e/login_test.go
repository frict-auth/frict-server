//go:build e2e

package e2e

import (
	"crypto/ecdsa"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/frict-auth/frict-server/internal/fakephone"
)

// enrolledUser creates a user and enrolls a fake phone for it through
// Authentik's Duo setup stage, which ends logged in.
func enrolledUser(t *testing.T, prefix string) (string, device) {
	t.Helper()
	username, _ := createUser(t, prefix)
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
	if status, body := enrollPhone(phone, act); status != http.StatusOK {
		t.Fatalf("phone enroll: %d %s", status, body)
	}
	b.expect(b.do("POST", map[string]any{"component": "ak-stage-authenticator-duo"}), "xak-flow-redirect")
	return username, device{phone: phone, act: act}
}

// pushLogin logs username in with a new browser up to the Duo push and
// submits it. While Authentik waits on frict-server, onPush gets the push's
// challenge ID as the phone first sees it. pushLogin returns once both are
// done, with the flow's answer and how long the push took.
func pushLogin(t *testing.T, username string, d device, onPush func(id string)) (*browser, challenge, time.Duration) {
	t.Helper()
	b := newBrowser(t)
	c := b.expect(b.passwordStep(username), "ak-stage-authenticator-validate")
	uid := duoDeviceUID(t, c)

	phoneDone := make(chan struct{})
	go func() {
		defer close(phoneDone)
		id, err := d.waitChallenge(30 * time.Second)
		if err != nil {
			t.Error(err)
			return
		}
		onPush(id)
	}()
	start := time.Now()
	c = b.do("POST", map[string]any{"component": "ak-stage-authenticator-validate", "duo": uid})
	elapsed := time.Since(start)
	<-phoneDone
	return b, c, elapsed
}

func expectLoggedIn(t *testing.T, b *browser, c challenge, username string) {
	t.Helper()
	b.expect(c, "xak-flow-redirect")
	if status, who := b.whoami(); status != 200 || who != username {
		t.Fatalf("after push login, users/me = %d %q, want 200 %q", status, who, username)
	}
}

// expectDenied requires Authentik to have refused the push, and its
// login_failed event to carry frict-server's /auth response with
// duoStatus. It returns that response.
func expectDenied(t *testing.T, b *browser, c challenge, username, duoStatus string) map[string]any {
	t.Helper()
	b.expect(c, "ak-stage-authenticator-validate")
	if errs := c.ResponseErrors["duo"]; len(errs) == 0 || errs[0].String != "Duo denied access" {
		t.Fatalf("want 'Duo denied access' on the duo field: %s", c.raw)
	}
	if status, who := b.whoami(); status == 200 {
		t.Fatalf("denied push produced a session for %q", who)
	}
	var seen []map[string]any
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		var events struct {
			Results []struct {
				Context map[string]any `json:"context"`
			} `json:"results"`
		}
		if err := admin("GET", "/api/v3/events/events/?action=login_failed&username="+url.QueryEscape(username), nil, &events); err != nil {
			t.Fatal(err)
		}
		seen = seen[:0]
		for _, e := range events.Results {
			seen = append(seen, e.Context)
			args, _ := e.Context["auth_method_args"].(map[string]any)
			resp, _ := args["duo_response"].(map[string]any)
			if resp["result"] == "deny" && resp["status"] == duoStatus {
				return resp
			}
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("no login_failed event for %s with duo_response status %q; got %v", username, duoStatus, seen)
	return nil
}

func answerOrError(t *testing.T, d device, id, decision, reason string, want int) {
	if status, body := d.answer(id, decision, reason); status != want {
		t.Errorf("answer %s %s: %d %s, want %d", decision, reason, status, body, want)
	}
}

// TestPushApprovedAfterHumanDelay: the phone sees the push, fetches what it
// is for, and approves after FRICT_E2E_ANSWER_DELAY; Authentik waits for it
// and logs the user in.
func TestPushApprovedAfterHumanDelay(t *testing.T) {
	username, d := enrolledUser(t, "alice")
	b, c, elapsed := pushLogin(t, username, d, func(id string) {
		details, err := d.details(id)
		if err != nil {
			t.Error(err)
			return
		}
		if details.Username != username || details.IPAddr == "" || !strings.Contains(details.PushInfo, "Domain=") || details.Type == "" {
			t.Errorf("challenge details %+v lack Authentik's display fields", details)
		}
		time.Sleep(env.answerDelay)
		answerOrError(t, d, id, "approve", "", http.StatusOK)
	})
	t.Logf("approved push round trip through Authentik: %s (answer delay %s)", elapsed.Round(time.Millisecond), env.answerDelay)
	expectLoggedIn(t, b, c, username)
	if elapsed < env.answerDelay {
		t.Fatalf("push returned after %s, before the phone answered at %s", elapsed, env.answerDelay)
	}
}

func TestPushDeniedNotMe(t *testing.T) {
	username, d := enrolledUser(t, "nina")
	b, c, _ := pushLogin(t, username, d, func(id string) { answerOrError(t, d, id, "deny", "not_me", http.StatusOK) })
	expectDenied(t, b, c, username, "fraud")
}

func TestPushDeniedCancel(t *testing.T) {
	username, d := enrolledUser(t, "carl")
	b, c, _ := pushLogin(t, username, d, func(id string) { answerOrError(t, d, id, "deny", "cancel", http.StatusOK) })
	expectDenied(t, b, c, username, "deny")
}

// TestPushTimesOut: nobody answers, so frict-server ends the push at
// FRICT_CHALLENGE_TTL and Authentik refuses the login. An answer after that
// is rejected.
func TestPushTimesOut(t *testing.T) {
	username, d := enrolledUser(t, "tim")
	var id string
	b, c, elapsed := pushLogin(t, username, d, func(got string) { id = got })
	t.Logf("unanswered push returned after %s (challenge TTL %s)", elapsed.Round(time.Millisecond), env.challengeTTL)
	expectDenied(t, b, c, username, "timeout")
	if elapsed < env.challengeTTL || elapsed > env.challengeTTL+30*time.Second {
		t.Fatalf("unanswered push returned after %s, want about the %s challenge TTL", elapsed, env.challengeTTL)
	}
	if status, body := d.answer(id, "approve", ""); status != http.StatusConflict {
		t.Fatalf("approve after timeout: %d %s, want 409", status, body)
	}
}

// TestReplayedAnswerRejected: the phone's approval, sent again byte for byte
// after it logged the user in, gets 409.
func TestReplayedAnswerRejected(t *testing.T) {
	username, d := enrolledUser(t, "rita")
	var replay *http.Request
	b, c, _ := pushLogin(t, username, d, func(id string) {
		body, err := fakephone.AnswerBody(id, "approve", "")
		if err != nil {
			t.Error(err)
			return
		}
		req, err := fakephone.SignedRequest("https://"+frictHostname, fakephone.AnswerPath, d.act.UserID, time.Now().Unix(), body, d.phone.ApprovalKey)
		if err != nil {
			t.Error(err)
			return
		}
		replay = replayable(req, body)
		if status, resp := send(req); status != http.StatusOK {
			t.Errorf("approve: %d %s", status, resp)
		}
	})
	expectLoggedIn(t, b, c, username)
	if replay == nil {
		t.Fatal("phone never approved")
	}
	if status, body := send(replay); status != http.StatusConflict || body != `{"error":"not_pending"}` {
		t.Fatalf("replayed approval: %d %s, want 409 not_pending", status, body)
	}
}

// TestBadSignatureAnswerRejected: answers signed with the device_key, or by
// another phone's approval_key, get 401 and leave the push pending; the
// real approval then logs the user in.
func TestBadSignatureAnswerRejected(t *testing.T) {
	username, d := enrolledUser(t, "bert")
	thief, err := fakephone.New()
	if err != nil {
		t.Fatal(err)
	}
	b, c, _ := pushLogin(t, username, d, func(id string) {
		body, err := fakephone.AnswerBody(id, "approve", "")
		if err != nil {
			t.Error(err)
			return
		}
		for _, signer := range []struct {
			name string
			key  *ecdsa.PrivateKey
		}{{"device_key", d.phone.DeviceKey}, {"another phone's approval_key", thief.ApprovalKey}} {
			req, err := fakephone.SignedRequest("https://"+frictHostname, fakephone.AnswerPath, d.act.UserID, time.Now().Unix(), body, signer.key)
			if err != nil {
				t.Error(err)
				return
			}
			if status, resp := send(req); status != http.StatusUnauthorized {
				t.Errorf("answer signed with %s: %d %s, want 401", signer.name, status, resp)
			}
		}
		if ids, err := d.pending(); err != nil || len(ids) != 1 || ids[0] != id {
			t.Errorf("after rejected answers, pending = %v (err %v), want [%s]", ids, err, id)
		}
		answerOrError(t, d, id, "approve", "", http.StatusOK)
	})
	expectLoggedIn(t, b, c, username)
}

// TestWrongClientSecretFailsLogin: a Duo stage configured with the wrong
// client secret signs requests frict-server rejects, and Authentik refuses
// the login without waiting for a push.
func TestWrongClientSecretFailsLogin(t *testing.T) {
	username, _ := createUser(t, "mallory")
	d, err := enrollViaDuoAPI(username)
	if err != nil {
		t.Fatal(err)
	}
	if err := admin("POST", "/api/v3/stages/authenticator/duo/"+env.badDuoPK+"/import_device_manual/",
		map[string]any{"duo_user_id": d.act.UserID, "username": username}, nil); err != nil {
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
	if elapsed >= env.challengeTTL {
		t.Fatalf("rejection took %s, at least the challenge TTL: frict-server ran /auth instead of rejecting", elapsed)
	}
	if status, who := login.whoami(); status == 200 {
		t.Fatalf("login with a wrong Duo secret produced a session for %q", who)
	}
	if ids, err := d.pending(); err != nil || len(ids) != 0 {
		t.Fatalf("pending after a rejected /auth = %v (err %v), want none", ids, err)
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
