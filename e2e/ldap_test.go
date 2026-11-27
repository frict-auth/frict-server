//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
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

// ldapNoDevice may log in over LDAP but has no Frict device.
const ldapNoDevice = "ldap-dave"

// ldapSvcPass is the service account's password, read by setupLDAP.
var ldapSvcPass string

// ldapDevices holds each LDAP user's phone, enrolled on frict-server by
// setupLDAP.
var ldapDevices = map[string]device{}

func userDN(username string) string { return "cn=" + username + ",ou=users," + ldapBaseDN }

// setupLDAP builds the M5 design (docs/ldap.md): one LDAP provider whose bind
// flow, run only by the outpost, is identification -> password -> Frict
// validation -> login, where the validation stage denies users without a
// device and a negated user binding lets only the service account skip it.
// browserFlow gets a deny stage for the service account. It then starts the
// outpost and both SSSD clients.
func setupLDAP(stage func(string, map[string]any) (string, error), browserFlow, login string) error {
	var err error
	if ldapSvcPass, err = readSecret("ldap-svc-password"); err != nil {
		return err
	}
	svcPK, err := newUser(map[string]any{"username": ldapSvcUser, "name": ldapSvcUser, "type": "service_account"}, ldapSvcPass)
	if err != nil {
		return err
	}

	denySvc, err := stage("deny", map[string]any{"name": "deny-ldap-svc"})
	if err != nil {
		return err
	}
	denyBinding, err := bindReevaluated(browserFlow, denySvc, 15)
	if err != nil {
		return err
	}
	if err := bindUser(denyBinding, svcPK, false); err != nil {
		return err
	}

	ident, err := stage("identification", map[string]any{"name": "ldap-identification", "user_fields": []string{"username"}})
	if err != nil {
		return err
	}
	pass, err := stage("password", map[string]any{"name": "ldap-password", "backends": []string{"authentik.core.auth.InbuiltBackend"}})
	if err != nil {
		return err
	}
	validate, err := stage("authenticator/validate", map[string]any{
		"name": "ldap-frict-validate", "device_classes": []string{"duo"}, "not_configured_action": "deny",
	})
	if err != nil {
		return err
	}
	var flow struct{ PK string }
	if err := admin("POST", "/api/v3/flows/instances/", map[string]any{
		"name": "ldap-bind", "slug": "ldap-bind", "title": "LDAP bind", "designation": "authentication",
		"authentication": "require_outpost",
	}, &flow); err != nil {
		return err
	}
	if err := bindStages(flow.PK, ident, pass); err != nil {
		return err
	}
	validateBinding, err := bindReevaluated(flow.PK, validate, 30)
	if err != nil {
		return err
	}
	if err := bindUser(validateBinding, svcPK, true); err != nil {
		return err
	}
	if err := admin("POST", "/api/v3/flows/bindings/", map[string]any{"target": flow.PK, "stage": login, "order": 40}, nil); err != nil {
		return err
	}

	logout, err := stage("user_logout", map[string]any{"name": "ldap-logout"})
	if err != nil {
		return err
	}
	var unbind struct{ PK string }
	if err := admin("POST", "/api/v3/flows/instances/", map[string]any{
		"name": "ldap-unbind", "slug": "ldap-unbind", "title": "LDAP unbind", "designation": "invalidation",
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
		"name": "ldap.frict.test", "certificate_data": certPEM, "key_data": keyPEM,
	}, &kp); err != nil {
		return err
	}
	var provider struct{ PK int }
	if err := admin("POST", "/api/v3/providers/ldap/", map[string]any{
		"name": "ldap", "authorization_flow": flow.PK, "invalidation_flow": unbind.PK,
		"base_dn": ldapBaseDN, "certificate": kp.PK, "tls_server_name": "ldap.frict.test",
		"bind_mode": "direct", "search_mode": "direct", "mfa_support": false,
	}, &provider); err != nil {
		return err
	}
	var app struct{ PK string }
	if err := admin("POST", "/api/v3/core/applications/", map[string]any{
		"name": "ldap", "slug": "ldap", "provider": provider.PK,
	}, &app); err != nil {
		return err
	}

	var role struct{ PK string }
	if err := admin("POST", "/api/v3/rbac/roles/", map[string]any{"name": "ldap-search"}, &role); err != nil {
		return err
	}
	if err := admin("POST", "/api/v3/rbac/permissions/assigned_by_roles/"+role.PK+"/assign/", map[string]any{
		"permissions": []string{"authentik_providers_ldap.search_full_directory"},
		"model":       "authentik_providers_ldap.ldapprovider", "object_pk": fmt.Sprint(provider.PK),
	}, nil); err != nil {
		return err
	}
	if err := admin("PATCH", fmt.Sprintf("/api/v3/core/users/%d/", svcPK), map[string]any{"roles": []string{role.PK}}, nil); err != nil {
		return err
	}

	var members []int
	for _, username := range append([]string{ldapNoDevice}, ldapUsers...) {
		pk, err := newUser(map[string]any{"username": username, "name": username}, env.userPass)
		if err != nil {
			return err
		}
		members = append(members, pk)
		if username == ldapNoDevice {
			continue
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
	var group struct{ PK string }
	if err := admin("POST", "/api/v3/core/groups/", map[string]any{"name": "ldap-login", "users": members}, &group); err != nil {
		return err
	}
	for i, who := range []map[string]any{{"group": group.PK}, {"user": svcPK}} {
		who["target"], who["order"] = app.PK, i
		if err := admin("POST", "/api/v3/policies/bindings/", who, nil); err != nil {
			return err
		}
	}

	var outpost struct{ PK string }
	if err := admin("POST", "/api/v3/outposts/instances/", map[string]any{
		"name": "ldap", "type": "ldap", "providers": []int{provider.PK},
		"config": map[string]any{"authentik_host": "http://server:9000"},
	}, &outpost); err != nil {
		return err
	}
	var token struct{ Key string }
	if err := admin("GET", "/api/v3/core/tokens/ak-outpost-"+outpost.PK+"-api/view_key/", nil, &token); err != nil {
		return err
	}

	up := composeCmd("up", "--detach", "--no-deps", "--wait", "--wait-timeout", "120", "ldap")
	up.Env = append(os.Environ(), "FRICT_LDAP_OUTPOST_TOKEN="+token.Key)
	if out, err := up.CombinedOutput(); err != nil {
		return fmt.Errorf("starting ldap outpost: %v\n%s", err, out)
	}
	if out, err := composeCmd("up", "--detach", "--no-deps", sssdDefault, sssdTuned).CombinedOutput(); err != nil {
		return fmt.Errorf("starting sssd clients: %v\n%s", err, out)
	}
	// A wrong password answered with invalidCredentials means the outpost
	// serves LDAPS and runs the bind flow. Whether the right one binds is
	// for the tests to say.
	return retry(2*time.Minute, func() error {
		if r := ldapSearch(sssdTuned, ldapSvcUser, ldapSvcPass+"-wrong", ldapBaseDN); r.exit != 49 {
			return fmt.Errorf("outpost readiness: wrong service account password: exit %d, want 49: %s", r.exit, r.out)
		}
		return nil
	})
}

// bindReevaluated binds stage into flow at order, with its policies
// evaluated against the pending user when the flow reaches it, and returns
// the binding's policy target.
func bindReevaluated(flow, stage string, order int) (string, error) {
	var b struct {
		PBM string `json:"policybindingmodel_ptr_id"`
	}
	err := admin("POST", "/api/v3/flows/bindings/", map[string]any{
		"target": flow, "stage": stage, "order": order, "evaluate_on_plan": false, "re_evaluate_policies": true,
	}, &b)
	return b.PBM, err
}

// bindUser binds the user userPK to target as a policy, negated or not.
func bindUser(target string, userPK int, negate bool) error {
	return admin("POST", "/api/v3/policies/bindings/", map[string]any{
		"target": target, "user": userPK, "negate": negate, "order": 0,
	}, nil)
}

// requireNSS waits for svc's SSSD to resolve username, which needs the
// service account's search.
func requireNSS(t *testing.T, svc, username string) {
	t.Helper()
	if err := retry(2*time.Minute, func() error {
		if r := inContainer(svc, "", "id", username); r.exit != 0 {
			return fmt.Errorf("%s: id %s: exit %d: %s", svc, username, r.exit, r.out)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
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

// pamAuth runs one PAM authentication for username through pam_sss in svc,
// as sshd does for a password login, once svc's SSSD resolves username.
func pamAuth(t *testing.T, svc, username string) result {
	t.Helper()
	requireNSS(t, svc, username)
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
	r := pamAuth(t, sssdDefault, user)
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
	r := pamAuth(t, sssdTuned, user)
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
	r := pamAuth(t, sssdTuned, user)
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

// allPushesSince counts every challenge frict-server created since t.
func allPushesSince(t *testing.T, since time.Time) int {
	t.Helper()
	out, err := composeCmd("logs", "--no-color", "--since", since.UTC().Format(time.RFC3339Nano), "frict-server").CombinedOutput()
	if err != nil {
		t.Fatalf("frict-server logs: %v\n%s", err, out)
	}
	return strings.Count(string(out), `msg="challenge created"`)
}

// TestLDAPSvcBindsWithPasswordOnly: the service account SSSD searches with
// binds with its password alone; the negated binding skips Frict for it.
func TestLDAPSvcBindsWithPasswordOnly(t *testing.T) {
	start := time.Now()
	r := ldapSearch(sssdTuned, ldapSvcUser, ldapSvcPass, userDN("ldap-alice"))
	t.Logf("bind+search as %s: exit %d after %s\n%s", ldapSvcUser, r.exit, r.elapsed.Round(time.Millisecond), r.out)
	if r.exit != 0 || !strings.Contains(r.out, "cn: ldap-alice") {
		t.Fatalf("service account bind+search failed: exit %d\n%s", r.exit, r.out)
	}
	if n := allPushesSince(t, start); n != 0 {
		t.Fatalf("frict-server created %d challenges during the service account bind, want 0", n)
	}
	if r := ldapSearch(sssdTuned, ldapSvcUser, ldapSvcPass+"x", userDN("ldap-alice")); r.exit != 49 {
		t.Fatalf("service account bind with a wrong password: exit %d, want 49\n%s", r.exit, r.out)
	}
}

// TestLDAPUserWithoutDeviceCannotBind: a user allowed to log in over LDAP
// but without a Frict device is refused, right password or not, and nothing
// is pushed.
func TestLDAPUserWithoutDeviceCannotBind(t *testing.T) {
	start := time.Now()
	r := ldapSearch(sssdTuned, ldapNoDevice, env.userPass, userDN(ldapNoDevice))
	t.Logf("bind+search as %s (right password, no device): exit %d after %s\n%s", ldapNoDevice, r.exit, r.elapsed.Round(time.Millisecond), r.out)
	if r.exit != 49 {
		t.Fatalf("bind without a device: exit %d, want 49 (invalidCredentials)\n%s", r.exit, r.out)
	}
	if n := allPushesSince(t, start); n != 0 {
		t.Fatalf("frict-server created %d challenges, want 0", n)
	}
}

// appPassword mints an app password token for username, as any user can for
// themselves, and returns its key.
func appPassword(t *testing.T, username string) string {
	t.Helper()
	var users struct{ Results []struct{ PK int } }
	if err := admin("GET", "/api/v3/core/users/?username="+url.QueryEscape(username), nil, &users); err != nil || len(users.Results) != 1 {
		t.Fatalf("looking up %s: %v %+v", username, err, users)
	}
	id := "app-password-" + username
	if err := admin("POST", "/api/v3/core/tokens/", map[string]any{
		"identifier": id, "intent": "app_password", "user": users.Results[0].PK,
	}, nil); err != nil {
		t.Fatal(err)
	}
	var token struct{ Key string }
	if err := admin("GET", "/api/v3/core/tokens/"+id+"/view_key/", nil, &token); err != nil {
		t.Fatal(err)
	}
	return token.Key
}

// TestLDAPCredentialsDontMix: the skip names the service account's user
// object, resolved from the bind DN, and the password stage checks that
// user's own password and nothing else, so neither half of the service
// account's credentials helps anyone else and app passwords don't bind.
func TestLDAPCredentialsDontMix(t *testing.T) {
	svcAppPass, aliceAppPass := appPassword(t, ldapSvcUser), appPassword(t, "ldap-alice")
	start := time.Now()
	for _, c := range []struct{ what, user, password string }{
		{"service account DN, a user's password", ldapSvcUser, env.userPass},
		{"enrolled user's DN, the service account's password", "ldap-alice", ldapSvcPass},
		{"service account DN, its own app password", ldapSvcUser, svcAppPass},
		{"enrolled user's DN, their own app password", "ldap-alice", aliceAppPass},
	} {
		r := ldapSearch(sssdTuned, c.user, c.password, userDN(c.user))
		t.Logf("%s: exit %d after %s\n%s", c.what, r.exit, r.elapsed.Round(time.Millisecond), r.out)
		if r.exit != 49 {
			t.Errorf("%s: exit %d, want 49 (invalidCredentials)", c.what, r.exit)
		}
	}
	if n := allPushesSince(t, start); n != 0 {
		t.Fatalf("frict-server created %d challenges, want 0", n)
	}
}

// TestLDAPSvcDeniedOnBrowserFlow: the service account's password sits on
// every SSSD client, so the browser login flow refuses that account before
// its password, and it never reaches Duo enrollment.
func TestLDAPSvcDeniedOnBrowserFlow(t *testing.T) {
	b := newBrowser(t)
	b.expect(b.do("GET", nil), "ak-stage-identification")
	c := b.do("POST", map[string]any{"component": "ak-stage-identification", "uid_field": ldapSvcUser})
	if c.Component == "ak-stage-password" {
		c = b.do("POST", map[string]any{"component": "ak-stage-password", "password": ldapSvcPass})
	}
	b.expect(c, "ak-stage-access-denied")
	if status, who := b.whoami(); status == 200 {
		t.Fatalf("browser flow produced a session for %q", who)
	}
}

// TestLDAPBindFlowRefusesBrowser: a browser running ldap-bind as the
// service account, which skips Frict there, gets no session; only the
// outpost, authenticated by its token, may run that flow.
func TestLDAPBindFlowRefusesBrowser(t *testing.T) {
	b := newBrowserOn(t, "ldap-bind")
	c := b.do("GET", nil)
	if c.Component == "ak-stage-identification" {
		c = b.do("POST", map[string]any{"component": "ak-stage-identification", "uid_field": ldapSvcUser})
	}
	if c.Component == "ak-stage-password" {
		c = b.do("POST", map[string]any{"component": "ak-stage-password", "password": ldapSvcPass})
	}
	t.Logf("ldap-bind without the outpost token ends at %s", c.raw)
	if status, who := b.whoami(); status == 200 {
		t.Errorf("ldap-bind produced a browser session for %q", who)
	}
	b.expect(c, "ak-stage-access-denied")
}
