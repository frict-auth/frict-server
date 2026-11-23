package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/frict-auth/frict-server/internal/fakephone"
	"github.com/frict-auth/frict-server/internal/store"
)

// remove sends the phone's signed removal for a.
func (f *fixture) remove(a fakephone.Activation, phone *fakephone.Phone) *http.Request {
	f.t.Helper()
	return must[*http.Request](f.t)(phone.RemoveRequest(a, f.now()))
}

// wantEnrolled requires a to still have its device, and its pushes to work.
func (f *fixture) wantEnrolled(a fakephone.Activation, phone *fakephone.Phone) {
	f.t.Helper()
	if _, err := f.st.DeviceOf(context.Background(), a.UserID); err != nil {
		f.t.Fatalf("%s after a refused removal: %v, want its device kept", a.UserID, err)
	}
	f.wantPushed(a, phone)
}

// wantUnknownUser requires /auth for userID to get Duo's answer for an
// unknown user.
func (f *fixture) wantUnknownUser(userID string) {
	f.t.Helper()
	f.wantDuoFail(f.duo("/auth/v2/auth", authParams(userID), secret), 40002)
}

func (f *fixture) wantDuoFail(w interface {
	Result() *http.Response
}, code int) {
	f.t.Helper()
	resp := w.Result()
	var body struct {
		Stat string
		Code int
	}
	if resp.StatusCode != http.StatusBadRequest || json.NewDecoder(resp.Body).Decode(&body) != nil || body.Stat != "FAIL" || body.Code != code {
		f.t.Fatalf("/auth: %d %+v, want 400 FAIL code %d", resp.StatusCode, body, code)
	}
}

// TestRemoveDeletesEnrollmentAndLoginRecords: removal deletes the user's
// device and every challenge, answered or not; bob's are untouched. After
// it /auth for that user is Duo's unknown user, its activation is invalid,
// and its key verifies nothing, a second removal included.
func TestRemoveDeletesEnrollmentAndLoginRecords(t *testing.T) {
	f := newFixture(t)
	a, phone := f.enrolledPhone("alice")
	b, bobPhone := f.enrolledPhone("bob")
	f.push(a, phone, "approve", "", "allow")
	f.push(a, phone, "deny", "not_me", "fraud")
	f.push(b, bobPhone, "approve", "", "allow")

	wantStatus(t, "remove", f.serve(f.remove(a, phone)), http.StatusOK, "{}")

	if n := f.challengeCount(a.UserID); n != 0 {
		t.Fatalf("alice's challenges after removal = %d, want 0", n)
	}
	if _, err := f.st.DeviceOf(context.Background(), a.UserID); !errors.Is(err, store.ErrNoDevice) {
		t.Fatalf("alice's device after removal: %v, want ErrNoDevice", err)
	}
	f.wantUnknownUser(a.UserID)
	if got := f.status(a); got != "invalid" {
		t.Fatalf("enroll_status after removal = %q, want invalid", got)
	}
	wantStatus(t, "poll after removal", f.serve(must[*http.Request](t)(phone.PendingRequest(a, f.now()))), http.StatusUnauthorized, `{"error":"unauthorized"}`)
	wantStatus(t, "second remove", f.serve(f.remove(a, phone)), http.StatusUnauthorized, `{"error":"unauthorized"}`)

	if n := f.challengeCount(b.UserID); n != 1 {
		t.Fatalf("bob's challenges after alice's removal = %d, want 1", n)
	}
	f.wantEnrolled(b, bobPhone)
}

// TestRemoveDuringPushEndsAuthAsUnknownUser: an /auth waiting on a push
// when its user is removed ends with Duo's unknown user, not an error.
func TestRemoveDuringPushEndsAuthAsUnknownUser(t *testing.T) {
	f := newFixtureTTL(t, time.Second)
	a, phone := f.enrolledPhone("alice")
	done := f.startAuth(context.Background(), a.UserID)
	f.pending(a, phone, 1)
	wantStatus(t, "remove", f.serve(f.remove(a, phone)), http.StatusOK, "{}")
	select {
	case w := <-done:
		f.wantDuoFail(w, 40002)
	case <-time.After(10 * time.Second):
		t.Fatal("/auth did not return within 10s")
	}
}

// TestRemoveNeedsTheDevicesSignature: only the device_key's signature over
// this endpoint removes an enrollment. Nothing else does.
func TestRemoveNeedsTheDevicesSignature(t *testing.T) {
	f := newFixture(t)
	a, phone := f.enrolledPhone("alice")
	thief := newPhone(t)
	signedBy := func(key *fakephone.Phone, approval bool) *http.Request {
		k := key.DeviceKey
		if approval {
			k = key.ApprovalKey
		}
		return must[*http.Request](t)(fakephone.SignedRequest("https://"+host, fakephone.RemovePath, a.UserID, f.now().Unix(), []byte("{}"), k))
	}
	unsigned := f.remove(a, phone)
	unsigned.Header.Del("Authorization")
	bogus := f.remove(a, phone)
	bogus.Header.Set("Authorization", "Frict-P256 "+a.UserID+":"+strconv.FormatInt(f.now().Unix(), 10)+":MEUCIQ")
	for name, r := range map[string]*http.Request{
		"unsigned":               unsigned,
		"bogus signature":        bogus,
		"another phone's key":    signedBy(thief, false),
		"the approval_key":       signedBy(phone, true),
		"signed for pending":     signedForPath(t, phone, a, fakephone.RemovePath, fakephone.PendingPath, []byte("{}"), f.now()),
		"signed for fid":         signedForPath(t, phone, a, fakephone.RemovePath, fakephone.FIDPath, []byte("{}"), f.now()),
		"stale":                  must[*http.Request](t)(phone.RemoveRequest(a, f.now().Add(-6*time.Minute))),
		"for an unenrolled user": must[*http.Request](t)(phone.RemoveRequest(fakephone.Activation{Host: host, UserID: f.enroll("bob").UserID}, f.now())),
	} {
		wantStatus(t, name, f.serve(r), http.StatusUnauthorized, `{"error":"unauthorized"}`)
	}
	f.wantEnrolled(a, phone)
}

func TestRemoveRejectsABody(t *testing.T) {
	f := newFixture(t)
	a, phone := f.enrolledPhone("alice")
	r := must[*http.Request](t)(fakephone.SignedRequest("https://"+host, fakephone.RemovePath, a.UserID, f.now().Unix(), []byte(`{"user_id":"x"}`), phone.DeviceKey))
	wantStatus(t, "remove with a field", f.serve(r), http.StatusBadRequest, `{"error":"bad_request"}`)
	f.wantEnrolled(a, phone)
}
