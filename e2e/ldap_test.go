//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Names shared with compose.yaml and e2e/sssd/*.conf.
const (
	ldapURI     = "ldaps://ldap.frict.test:6636"
	ldapBaseDN  = "dc=frict,dc=test"
	ldapSvcUser = "ldap-svc"
	sssdDefault = "sssd-default"
	sssdTuned   = "sssd-tuned"
	// sssdDefaultOptTimeout is SSSD's ldap_opt_timeout default, which bounds
	// the user's simple bind (sssd-ldap(5); ldap_auth.c auth_do_bind).
	sssdDefaultOptTimeout = 8 * time.Second
)

// One LDAP user per test, so each test can count its own pushes in
// frict-server's log. Every user's password is env.userPass.
var ldapUsers = []string{
	"ldap-alice",   // plain LDAP bind, approved
	"ldap-bob",     // PAM via default SSSD
	"ldap-carol",   // PAM via tuned SSSD
	"ldap-mallory", // denied: LDAP bind and PAM via tuned SSSD
}

// ldapDevices holds each LDAP user's phone, enrolled on frict-server by
// setupLDAP.
var ldapDevices = map[string]device{}

func userDN(username string) string { return "cn=" + username + ",ou=users," + ldapBaseDN }

// setupLDAP adds an LDAP provider whose bind flow is
// identification -> password -> Duo validation -> login, an outpost for it,
// the service account SSSD searches with, and users whose phones are
// enrolled on frict-server; then starts the outpost and both SSSD clients and
// waits for them.
func setupLDAP(stage func(string, map[string]any) (string, error), ident, pass, login string) error {
	validate, err := stage("authenticator/validate", map[string]any{
		"name": "frict-m0-ldap-validate", "device_classes": []string{"duo"},
		// The service account has no device and must bind without MFA.
		"not_configured_action": "skip",
	})
	if err != nil {
		return err
	}
	var flow struct{ PK string }
	if err := admin("POST", "/api/v3/flows/instances/", map[string]any{
		"name": "frict-m0-ldap", "slug": "frict-m0-ldap", "title": "Frict M0 LDAP", "designation": "authentication",
	}, &flow); err != nil {
		return err
	}
	if err := bindStages(flow.PK, ident, pass, validate, login); err != nil {
		return err
	}
	logout, err := stage("user_logout", map[string]any{"name": "frict-m0-ldap-logout"})
	if err != nil {
		return err
	}
	var unbind struct{ PK string }
	if err := admin("POST", "/api/v3/flows/instances/", map[string]any{
		"name": "frict-m0-ldap-unbind", "slug": "frict-m0-ldap-unbind", "title": "Frict M0 LDAP unbind", "designation": "invalidation",
	}, &unbind); err != nil {
		return err
	}
	if err := bindStages(unbind.PK, logout); err != nil {
		return err
	}

	certPEM, err := readSecret("ldap.pem")
	if err != nil {
		return err
	}
	keyPEM, err := readSecret("ldap.key")
	if err != nil {
		return err
	}
	var kp struct{ PK string }
	if err := admin("POST", "/api/v3/crypto/certificatekeypairs/", map[string]any{
		"name": "frict-m0-ldap", "certificate_data": certPEM, "key_data": keyPEM,
	}, &kp); err != nil {
		return err
	}
	var provider struct{ PK int }
	if err := admin("POST", "/api/v3/providers/ldap/", map[string]any{
		"name": "frict-m0-ldap", "authorization_flow": flow.PK, "invalidation_flow": unbind.PK,
		"base_dn": ldapBaseDN, "certificate": kp.PK, "tls_server_name": "ldap.frict.test",
		"bind_mode": "direct", "search_mode": "direct", "mfa_support": true,
	}, &provider); err != nil {
		return err
	}
	if err := admin("POST", "/api/v3/core/applications/", map[string]any{
		"name": "frict-m0-ldap", "slug": "frict-m0-ldap", "provider": provider.PK,
	}, nil); err != nil {
		return err
	}
	var outpost struct{ PK string }
	if err := admin("POST", "/api/v3/outposts/instances/", map[string]any{
		"name": "frict-m0-ldap", "type": "ldap", "providers": []int{provider.PK},
		"config": map[string]any{"authentik_host": "http://server:9000"},
	}, &outpost); err != nil {
		return err
	}
	var token struct{ Key string }
	if err := admin("GET", "/api/v3/core/tokens/ak-outpost-"+outpost.PK+"-api/view_key/", nil, &token); err != nil {
		return err
	}

	var role struct{ PK string }
	if err := admin("POST", "/api/v3/rbac/roles/", map[string]any{"name": "frict-m0-ldap-search"}, &role); err != nil {
		return err
	}
	if err := admin("POST", "/api/v3/rbac/permissions/assigned_by_roles/"+role.PK+"/assign/", map[string]any{
		"permissions": []string{"authentik_providers_ldap.search_full_directory"},
		"model":       "authentik_providers_ldap.ldapprovider", "object_pk": fmt.Sprint(provider.PK),
	}, nil); err != nil {
		return err
	}
	svcPass, err := readSecret("ldap-svc-password")
	if err != nil {
		return err
	}
	if _, err := newUser(map[string]any{"username": ldapSvcUser, "name": ldapSvcUser, "roles": []string{role.PK}}, svcPass); err != nil {
		return err
	}
	for _, username := range ldapUsers {
		if _, err := newUser(map[string]any{"username": username, "name": username}, env.userPass); err != nil {
			return err
		}
		d, err := enrollViaDuoAPI(username)
		if err != nil {
			return err
		}
		if err := admin("POST", "/api/v3/stages/authenticator/duo/"+env.frictDuoPK+"/import_device_manual/",
			map[string]any{"duo_user_id": d.act.UserID, "username": username}, nil); err != nil {
			return err
		}
		ldapDevices[username] = d
	}

	up := composeCmd("up", "--detach", "--no-deps", "--wait", "--wait-timeout", "120", "ldap")
	up.Env = append(os.Environ(), "FRICT_LDAP_OUTPOST_TOKEN="+token.Key)
	if out, err := up.CombinedOutput(); err != nil {
		return fmt.Errorf("starting ldap outpost: %v\n%s", err, out)
	}
	if out, err := composeCmd("up", "--detach", "--no-deps", sssdDefault, sssdTuned).CombinedOutput(); err != nil {
		return fmt.Errorf("starting sssd clients: %v\n%s", err, out)
	}
	if err := retry(2*time.Minute, func() error {
		r := ldapSearch(sssdTuned, ldapSvcUser, svcPass, userDN("ldap-alice"))
		if r.exit != 0 {
			return fmt.Errorf("service account search: exit %d: %s", r.exit, r.out)
		}
		return nil
	}); err != nil {
		return err
	}
	for _, svc := range []string{sssdDefault, sssdTuned} {
		if err := retry(2*time.Minute, func() error {
			if r := inContainer(svc, "", "id", "ldap-alice"); r.exit != 0 {
				return fmt.Errorf("%s: id ldap-alice: exit %d: %s", svc, r.exit, r.out)
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}

func retry(limit time.Duration, f func() error) error {
	deadline := time.Now().Add(limit)
	for {
		err := f()
		if err == nil || time.Now().After(deadline) {
			return err
		}
		time.Sleep(2 * time.Second)
	}
}

func composeCmd(args ...string) *exec.Cmd {
	return exec.Command("docker", append([]string{"compose", "-f", env.composeFile}, args...)...)
}

type result struct {
	exit    int
	out     string
	elapsed time.Duration
}

// inContainer runs argv in a compose service with stdin and reports its exit
// code, combined output and wall time.
func inContainer(svc, stdin string, argv ...string) result {
	cmd := composeCmd(append([]string{"exec", "-T", svc}, argv...)...)
	cmd.Stdin = strings.NewReader(stdin)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	start := time.Now()
	err := cmd.Run()
	r := result{out: out.String(), elapsed: time.Since(start)}
	var exitErr *exec.ExitError
	switch {
	case errors.As(err, &exitErr):
		r.exit = exitErr.ExitCode()
	case err != nil:
		r.exit, r.out = -1, err.Error()
	}
	return r
}

// ldapSearch binds as username over LDAPS through the outpost and reads base.
func ldapSearch(svc, username, password, base string) result {
	return inContainer(svc, "", "env", "LDAPTLS_CACERT=/secrets/ca.pem",
		"ldapsearch", "-x", "-LLL", "-H", ldapURI, "-D", userDN(username), "-w", password, "-b", base, "-s", "base", "cn")
}

// pamAuth runs one PAM authentication for username through pam_sss in svc.
func pamAuth(svc, username string) result {
	return inContainer(svc, env.userPass+"\n", "pamtester", "-v", "frict-test", username, "authenticate")
}

// pushesSince counts the challenges frict-server created for username's
// phone since t.
func pushesSince(t *testing.T, username string, since time.Time) int {
	t.Helper()
	out, err := composeCmd("logs", "--no-color", "--since", since.UTC().Format(time.RFC3339Nano), "frict-server").CombinedOutput()
	if err != nil {
		t.Fatalf("frict-server logs: %v\n%s", err, out)
	}
	return strings.Count(string(out), `msg="challenge created" user_id=`+ldapDevices[username].act.UserID+" ")
}

// answerPushes has username's phone answer each of its pushes
// FRICT_E2E_ANSWER_DELAY after first seeing it, until the test ends.
func answerPushes(t *testing.T, username, decision, reason string) {
	t.Helper()
	d := ldapDevices[username]
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		seen := map[string]time.Time{}
		answered := map[string]bool{}
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
			ids, err := d.pending()
			if err != nil {
				t.Errorf("%s's phone: %v", username, err)
				return
			}
			for _, id := range ids {
				if _, ok := seen[id]; !ok {
					seen[id] = time.Now()
				}
			}
			for id, at := range seen {
				if answered[id] || time.Since(at) < env.answerDelay {
					continue
				}
				answered[id] = true
				if status, body := d.answer(id, decision, reason); status != 200 {
					t.Errorf("%s's phone: answer %s: %d %s", username, decision, status, body)
				}
			}
		}
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}

func requireDelayAbove(t *testing.T, d time.Duration) {
	t.Helper()
	if env.answerDelay <= d+2*time.Second {
		t.Fatalf("FRICT_E2E_ANSWER_DELAY=%s must exceed %s by more than 2s for this test to mean anything", env.answerDelay, d)
	}
}

// TestLDAPBindWaitsForPush proves M0 (d): a plain simple bind (no TOTP
// suffix) through the outpost runs the bind flow, which sends one push to
// frict-server, waits for the phone's approval, and succeeds.
func TestLDAPBindWaitsForPush(t *testing.T) {
	const user = "ldap-alice"
	answerPushes(t, user, "approve", "")
	start := time.Now()
	r := ldapSearch(sssdTuned, user, env.userPass, userDN(user))
	t.Logf("bind+search as %s: exit %d after %s (answer delay %s)\n%s", user, r.exit, r.elapsed.Round(time.Millisecond), env.answerDelay, r.out)
	if r.exit != 0 || !strings.Contains(r.out, "cn: "+user) {
		t.Fatalf("bind as %s failed: exit %d\n%s", user, r.exit, r.out)
	}
	if r.elapsed < env.answerDelay {
		t.Fatalf("bind returned after %s, before the phone's %s answer delay: no push was waited for", r.elapsed, env.answerDelay)
	}
	if n := pushesSince(t, user, start); n != 1 {
		t.Fatalf("frict-server created %d challenges for %s, want 1", n, user)
	}
}

// TestLDAPBindFailsWhenPushDenied: mallory's phone denies the push after the
// delay, and the bind must fail with invalidCredentials (49).
func TestLDAPBindFailsWhenPushDenied(t *testing.T) {
	const user = "ldap-mallory"
	answerPushes(t, user, "deny", "cancel")
	start := time.Now()
	r := ldapSearch(sssdTuned, user, env.userPass, userDN(user))
	t.Logf("bind+search as %s: exit %d after %s (answer delay %s)\n%s", user, r.exit, r.elapsed.Round(time.Millisecond), env.answerDelay, r.out)
	if r.exit != 49 {
		t.Fatalf("bind with denied push: exit %d, want 49 (invalidCredentials)\n%s", r.exit, r.out)
	}
	if r.elapsed < env.answerDelay {
		t.Fatalf("bind failed after %s, before the phone's %s answer delay: it failed before the push was answered", r.elapsed, env.answerDelay)
	}
	if n := pushesSince(t, user, start); n != 1 {
		t.Fatalf("frict-server created %d challenges for %s, want 1", n, user)
	}
}

// TestSSSDDefaultTimeoutsLosePush documents M0 (e)'s baseline: with SSSD's
// default timeouts the user's bind times out after ldap_opt_timeout (8 s),
// SSSD reconnects and binds again, and each new bind sends another push.
// PAM auth fails even though the phone approves every push.
func TestSSSDDefaultTimeoutsLosePush(t *testing.T) {
	const user = "ldap-bob"
	requireDelayAbove(t, sssdDefaultOptTimeout)
	answerPushes(t, user, "approve", "")
	// The backend keeps re-binding after pamtester gives up; stopping the
	// container ends that so it doesn't load the rest of the run.
	t.Cleanup(func() {
		if out, err := composeCmd("stop", sssdDefault).CombinedOutput(); err != nil {
			t.Errorf("stopping %s: %v\n%s", sssdDefault, err, out)
		}
	})
	start := time.Now()
	r := pamAuth(sssdDefault, user)
	n := pushesSince(t, user, start)
	t.Logf("pam auth (%s) as %s: exit %d after %s, %d pushes (answer delay %s)\n%s", sssdDefault, user, r.exit, r.elapsed.Round(time.Millisecond), n, env.answerDelay, r.out)
	if r.exit == 0 {
		t.Fatalf("PAM auth with default SSSD timeouts succeeded; expected it to lose a push answered after %s", env.answerDelay)
	}
	if want := int(r.elapsed / sssdDefaultOptTimeout); n < 2 || n > want+1 {
		t.Fatalf("frict-server created %d challenges for %s in %s; want about one per %s (%d)", n, user, r.elapsed, sssdDefaultOptTimeout, want)
	}
}

// TestSSSDTunedSurvivesPush proves M0 (e): with the tuned reference sssd.conf
// PAM auth waits for one push and succeeds.
func TestSSSDTunedSurvivesPush(t *testing.T) {
	const user = "ldap-carol"
	requireDelayAbove(t, sssdDefaultOptTimeout)
	answerPushes(t, user, "approve", "")
	start := time.Now()
	r := pamAuth(sssdTuned, user)
	n := pushesSince(t, user, start)
	t.Logf("pam auth (%s) as %s: exit %d after %s, %d pushes (answer delay %s)\n%s", sssdTuned, user, r.exit, r.elapsed.Round(time.Millisecond), n, env.answerDelay, r.out)
	if r.exit != 0 || !strings.Contains(r.out, "successfully authenticated") {
		t.Fatalf("PAM auth with tuned SSSD failed: exit %d\n%s", r.exit, r.out)
	}
	if r.elapsed < env.answerDelay {
		t.Fatalf("PAM auth returned after %s, before the phone's %s answer delay", r.elapsed, env.answerDelay)
	}
	if n != 1 {
		t.Fatalf("frict-server created %d challenges for %s, want 1", n, user)
	}
}

// TestSSSDTunedFailsWhenPushDenied: same config, denied push; PAM must
// report an authentication failure once the push is answered.
func TestSSSDTunedFailsWhenPushDenied(t *testing.T) {
	const user = "ldap-mallory"
	requireDelayAbove(t, sssdDefaultOptTimeout)
	answerPushes(t, user, "deny", "cancel")
	start := time.Now()
	r := pamAuth(sssdTuned, user)
	n := pushesSince(t, user, start)
	t.Logf("pam auth (%s) as %s: exit %d after %s, %d pushes (answer delay %s)\n%s", sssdTuned, user, r.exit, r.elapsed.Round(time.Millisecond), n, env.answerDelay, r.out)
	if r.exit == 0 || !strings.Contains(r.out, "Authentication failure") {
		t.Fatalf("PAM auth with a denied push: exit %d, want PAM_AUTH_ERR (Authentication failure)\n%s", r.exit, r.out)
	}
	if r.elapsed < env.answerDelay {
		t.Fatalf("PAM auth failed after %s, before the phone's %s answer delay: not the denial", r.elapsed, env.answerDelay)
	}
	if n != 1 {
		t.Fatalf("frict-server created %d challenges for %s, want 1", n, user)
	}
}
