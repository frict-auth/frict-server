package server

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/frict-auth/frict-server/internal/fakephone"
	"github.com/frict-auth/frict-server/internal/push"
	"github.com/frict-auth/frict-server/internal/store"
)

const minVersion = 1000

const updateBody = `{"error":"app_update_required","min_version":1000}`

// newMinVersionFixture serves app versions from minVersion, pushes to the
// returned fake and logs JSON to the returned buffer.
func newMinVersionFixture(t *testing.T) (*fixture, *push.Fake, *syncBuffer) {
	t.Helper()
	fake := push.NewFake()
	logs := &syncBuffer{}
	f := newFixtureFull(t, time.Minute, testSafeguards, fake, minVersion, slog.New(slog.NewJSONHandler(logs, nil)))
	return f, fake, logs
}

// signedRequests are one request to each endpoint signed with a stored key,
// as phone sends them for a.
func signedRequests(t *testing.T, a fakephone.Activation, phone *fakephone.Phone, now time.Time) map[string]*http.Request {
	t.Helper()
	id := encodeID(make([]byte, 16))
	r := must[*http.Request](t)
	return map[string]*http.Request{
		"pending":   r(phone.PendingRequest(a, now)),
		"challenge": r(phone.ChallengeRequest(a, id, now)),
		"answer":    r(phone.AnswerRequest(a, id, "approve", "", now)),
		"fid":       r(phone.FIDRequest(a, "fid-2", now)),
		"remove":    r(phone.RemoveRequest(a, now)),
	}
}

// endpoints are those the minimum app version applies to: all but remove.
var endpoints = []string{"pending", "challenge", "answer", "fid"}

func (f *fixture) appVersionOf(userID string) int {
	f.t.Helper()
	d, err := f.st.DeviceOf(context.Background(), userID)
	if err != nil {
		f.t.Fatal(err)
	}
	return d.AppVersion
}

// updateLines returns the "app update required" lines logged.
func updateLines(t *testing.T, logs *syncBuffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	sc := bufio.NewScanner(strings.NewReader(logs.String()))
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("log line %q is not JSON: %v", sc.Text(), err)
		}
		if m["msg"] == "app update required" {
			out = append(out, m)
		}
	}
	return out
}

// TestOutdatedAppRefusedOnEverySignedEndpoint: with a minimum set, a request
// whose version is below it, missing or malformed gets 426 with the minimum
// and does nothing, on every endpoint but remove; the device's stored version becomes
// what the request carried. The refusal logs one line saying why.
func TestOutdatedAppRefusedOnEverySignedEndpoint(t *testing.T) {
	for _, tc := range []struct {
		name    string
		header  []string // nil sends none
		version int      // stored afterwards
		reason  string
	}{
		{"below minimum", []string{"999"}, 999, "below_minimum"},
		{"missing", nil, 0, "missing"},
		{"empty", []string{""}, 0, "malformed"},
		{"not a number", []string{"1.2.0"}, 0, "malformed"},
		{"sign", []string{"+1000"}, 0, "malformed"},
		{"leading zero", []string{"01000"}, 0, "malformed"},
		{"space", []string{"1000 "}, 0, "malformed"},
		{"zero", []string{"0"}, 0, "malformed"},
		{"negative", []string{"-1000"}, 0, "malformed"},
		{"above Play's largest", []string{"2100000001"}, 0, "malformed"},
		{"repeated", []string{"1000", "1000"}, 0, "malformed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, endpoint := range endpoints {
				t.Run(endpoint, func(t *testing.T) {
					f, fake, logs := newMinVersionFixture(t)
					a, phone := f.enrolledPhone("alice")
					r := signedRequests(t, a, phone, f.now())[endpoint]
					r.Header.Del(AppVersionHeader)
					for _, v := range tc.header {
						r.Header.Add(AppVersionHeader, v)
					}
					wantStatus(t, endpoint, f.serve(r), http.StatusUpgradeRequired, updateBody)
					if _, err := f.st.DeviceOf(context.Background(), a.UserID); err != nil {
						t.Fatalf("device after a refused request: %v", err)
					}
					if got := f.fid(a.UserID); got != phone.FID {
						t.Fatalf("FID after a refused request = %q, want %q", got, phone.FID)
					}
					if got := f.appVersionOf(a.UserID); got != tc.version {
						t.Fatalf("stored app version = %d, want %d", got, tc.version)
					}
					lines := updateLines(t, logs)
					if len(lines) != 1 {
						t.Fatalf("logged %d app update lines, want 1: %s", len(lines), logs)
					}
					want := map[string]any{"level": "WARN", "endpoint": r.URL.Path, "reason": tc.reason,
						"app_version": float64(tc.version), "min_app_version": float64(minVersion), "user_id": a.UserID}
					for k, v := range want {
						if lines[0][k] != v {
							t.Errorf("log %s = %v, want %v; line %v", k, lines[0][k], v, lines[0])
						}
					}
					if got := f.settledPushes(fake); len(got) != 0 {
						t.Fatalf("refused request pushed %v", got)
					}
				})
			}
		})
	}
}

// TestCurrentAppServed: at or above the minimum every endpoint answers as
// it would without one.
func TestCurrentAppServed(t *testing.T) {
	for _, version := range []int{minVersion, minVersion + 1} {
		f, _, logs := newMinVersionFixture(t)
		a, phone := f.enrolledPhone("alice")
		phone.AppVersion = version
		want := map[string]int{"pending": http.StatusOK, "challenge": http.StatusNotFound, "answer": http.StatusNotFound, "fid": http.StatusOK}
		for _, endpoint := range endpoints {
			if w := f.serve(signedRequests(t, a, phone, f.now())[endpoint]); w.Code != want[endpoint] {
				t.Errorf("version %d %s: %d %s, want %d", version, endpoint, w.Code, w.Body, want[endpoint])
			}
		}
		if got := f.appVersionOf(a.UserID); got != version {
			t.Errorf("stored app version = %d, want %d", got, version)
		}
		if lines := updateLines(t, logs); len(lines) != 0 {
			t.Errorf("version %d logged %v", version, lines)
		}
	}
}

// TestAppVersionCheckedOnlyAfterSignature: an outdated version on a request
// that fails verification gets the same 401 as any such request, so a
// caller without the device's key learns nothing about the minimum, and the
// stored version is unchanged.
func TestAppVersionCheckedOnlyAfterSignature(t *testing.T) {
	f, _, logs := newMinVersionFixture(t)
	a, phone := f.enrolledPhone("alice")
	thief := newPhone(t)
	thief.AppVersion = 1
	for endpoint, r := range signedRequests(t, a, thief, f.now()) {
		wantStatus(t, endpoint, f.serve(r), http.StatusUnauthorized, `{"error":"unauthorized"}`)
	}
	stale := newPhone(t)
	stale.DeviceKey, stale.ApprovalKey, stale.AppVersion = phone.DeviceKey, phone.ApprovalKey, 1
	for endpoint, r := range signedRequests(t, a, stale, f.now().Add(-10*time.Minute)) {
		wantStatus(t, endpoint+" stale", f.serve(r), http.StatusUnauthorized, `{"error":"unauthorized"}`)
	}
	if got := f.appVersionOf(a.UserID); got != minVersion {
		t.Fatalf("stored app version = %d after unverified requests, want %d", got, minVersion)
	}
	if lines := updateLines(t, logs); len(lines) != 0 {
		t.Fatalf("unverified requests logged %v", lines)
	}
}

// TestEnrollOutdatedAppKeepsCodeUnspent: enrollment checks the version after
// the signature and attestation and before spending the activation code, so
// the user can update and scan the same code again.
func TestEnrollOutdatedAppKeepsCodeUnspent(t *testing.T) {
	f, _, _ := newMinVersionFixture(t)
	a := f.enroll("alice")
	phone := newPhone(t)

	phone.AppVersion = minVersion - 1
	phone.Attestation.Challenge = "not the activation code"
	f.rejectEnroll(must[*http.Request](t)(phone.EnrollRequest(a, f.now())), a)
	phone.Attestation.Challenge = ""
	f.rejectEnroll(must[*http.Request](t)(phone.EnrollRequest(fakephone.Activation{Host: host, UserID: a.UserID, Code: a.Code}, f.now().Add(-10*time.Minute))), a)

	for _, v := range []int{minVersion - 1, 0} {
		phone.AppVersion = v
		wantStatus(t, "enroll", f.serve(must[*http.Request](t)(phone.EnrollRequest(a, f.now()))), http.StatusUpgradeRequired, updateBody)
		if _, err := f.st.DeviceOf(context.Background(), a.UserID); !errors.Is(err, store.ErrNoDevice) {
			t.Fatalf("outdated enroll left a device (err %v)", err)
		}
		if got := f.status(a); got != "waiting" {
			t.Fatalf("after outdated enroll: %q, want waiting", got)
		}
	}

	phone.AppVersion = minVersion
	wantStatus(t, "enroll after update", f.serve(must[*http.Request](t)(phone.EnrollRequest(a, f.now()))), http.StatusOK, "{}")
	if got := f.appVersionOf(a.UserID); got != minVersion {
		t.Fatalf("stored app version = %d, want %d", got, minVersion)
	}
}

// TestAuthDeniesOutdatedDevice: once the phone's last request carried an
// outdated version, /auth denies at once with a status_msg asking for an
// update, creating no challenge and sending no push. A request from the
// updated app restores pushes.
func TestAuthDeniesOutdatedDevice(t *testing.T) {
	f, fake, logs := newMinVersionFixture(t)
	a, phone := f.enrolledPhone("alice")

	phone.AppVersion = minVersion - 1
	wantStatus(t, "outdated poll", f.serve(must[*http.Request](t)(phone.PendingRequest(a, f.now()))), http.StatusUpgradeRequired, updateBody)
	got := f.authResult(f.startAuth(context.Background(), a.UserID))
	if got["result"] != "deny" || got["status"] != "deny" || !strings.Contains(got["status_msg"], "update it") {
		t.Fatalf("/auth for an outdated device = %v, want deny asking for an update", got)
	}
	if n := f.challengeCount(a.UserID); n != 0 {
		t.Fatalf("/auth for an outdated device created %d challenges", n)
	}
	if !strings.Contains(logs.String(), `"msg":"push refused","user_id":"`+a.UserID+`","lock":"outdated","min_app_version":1000`) {
		t.Fatalf("no push refused line for the outdated device:\n%s", logs)
	}

	phone.AppVersion = minVersion
	wantStatus(t, "updated FID", f.serve(must[*http.Request](t)(phone.FIDRequest(a, phone.FID, f.now()))), http.StatusOK, "{}")
	f.wantPushed(a, phone)
	pushes := f.settledPushes(fake)
	if len(pushes) != 1 {
		t.Fatalf("pushes = %v, want only the one after the update", pushes)
	}
}

// TestNoMinimumServesAnyVersion: without a minimum, no version, a malformed
// one and an old one are all served, and the stored version follows them.
func TestNoMinimumServesAnyVersion(t *testing.T) {
	f := newFixture(t)
	a, phone := f.enrolledPhone("alice")
	for _, header := range []string{"", "garbage", "1"} {
		r := must[*http.Request](t)(phone.PendingRequest(a, f.now()))
		r.Header.Del(AppVersionHeader)
		if header != "" {
			r.Header.Set(AppVersionHeader, header)
		}
		if w := f.serve(r); w.Code != http.StatusOK {
			t.Fatalf("pending with version %q: %d %s", header, w.Code, w.Body)
		}
	}
	if got := f.appVersionOf(a.UserID); got != 1 {
		t.Fatalf("stored app version = %d, want 1", got)
	}
	f.wantPushed(a, phone)
}

// TestOutdatedAppCanRemove: removal answers whatever the app version, once
// the signature holds: an outdated app removes itself, and logs no update
// line; an outdated request signed by another key still gets 401 and
// removes nothing.
func TestOutdatedAppCanRemove(t *testing.T) {
	for _, header := range []string{"", "999", "garbage"} {
		t.Run("version "+header, func(t *testing.T) {
			f, _, logs := newMinVersionFixture(t)
			a, phone := f.enrolledPhone("alice")
			thief := newPhone(t)
			for _, p := range []*fakephone.Phone{thief, phone} {
				r := f.remove(a, p)
				r.Header.Del(AppVersionHeader)
				if header != "" {
					r.Header.Set(AppVersionHeader, header)
				}
				if p == thief {
					wantStatus(t, "remove signed by another key", f.serve(r), http.StatusUnauthorized, `{"error":"unauthorized"}`)
					if _, err := f.st.DeviceOf(context.Background(), a.UserID); err != nil {
						t.Fatalf("device after a refused removal: %v", err)
					}
					continue
				}
				wantStatus(t, "remove", f.serve(r), http.StatusOK, "{}")
			}
			f.wantUnknownUser(a.UserID)
			if lines := updateLines(t, logs); len(lines) != 0 {
				t.Fatalf("removal logged %v", lines)
			}
		})
	}
}
