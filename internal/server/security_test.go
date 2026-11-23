package server

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/frict-auth/frict-server/internal/duosig"
	"github.com/frict-auth/frict-server/internal/fakephone"
)

// newLoggedFixture is a fixture whose server logs JSON to the returned
// buffer.
func newLoggedFixture(t *testing.T) (*fixture, *syncBuffer) {
	t.Helper()
	logs := &syncBuffer{}
	return newFixtureSender(t, time.Minute, testSafeguards, nil, slog.New(slog.NewJSONHandler(logs, nil))), logs
}

// securityLines returns the security events logged after the first skip
// lines.
func securityLines(t *testing.T, logs *syncBuffer, skip int) []map[string]any {
	t.Helper()
	var out []map[string]any
	sc := bufio.NewScanner(strings.NewReader(logs.String()))
	for i := 0; sc.Scan(); i++ {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("log line %q is not JSON: %v", sc.Text(), err)
		}
		if i >= skip && m["msg"] == "security" {
			out = append(out, m)
		}
	}
	return out
}

func lineCount(logs *syncBuffer) int { return strings.Count(logs.String(), "\n") }

// TestRejectedRequestsAreLogged: each rejected request logs exactly one
// security line naming the event, endpoint, reason, claimed user ID when
// there is a well-formed one, and the client's address.
func TestRejectedRequestsAreLogged(t *testing.T) {
	f, logs := newLoggedFixture(t)
	a, phone := f.enrolledPhone("alice")
	other := newPhone(t)
	unenrolled := f.enroll("bob")
	id := encodeID(make([]byte, 16))

	duoAt := func(path, body, skey string, date time.Time) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "https://"+host+path, strings.NewReader(body))
		r.Header.Set("Date", date.Format(time.RFC1123Z))
		if err := duosig.Sign(r, []byte(body), clientID, skey, host); err != nil {
			t.Fatal(err)
		}
		return r
	}
	answered := func() *http.Request {
		done := f.startAuth(context.Background(), a.UserID)
		cid := f.pending(a, phone, 1)[0]
		r := must[*http.Request](t)(phone.AnswerRequest(a, cid, "approve", "", f.now()))
		wantStatus(t, "first answer", f.answer(a, phone, cid, "approve", ""), http.StatusOK, "{}")
		f.authResult(done)
		return r
	}
	unsignedDuo := httptest.NewRequest(http.MethodPost, "https://"+host+"/auth/v2/auth", strings.NewReader(authParams(a.UserID)))
	noAuth := must[*http.Request](t)(phone.PendingRequest(a, f.now()))
	noAuth.Header.Del("Authorization")
	malformedID := must[*http.Request](t)(phone.PendingRequest(fakephone.Activation{Host: host, UserID: strings.ToLower(a.UserID)}, f.now()))
	proxied := must[*http.Request](t)(fakephone.SignedRequest("https://"+host, fakephone.PendingPath, a.UserID, f.now().Unix(), []byte("{}"), other.DeviceKey))
	proxied.RemoteAddr = "127.0.0.1:40000"
	proxied.Header.Set("X-Forwarded-For", "198.51.100.9")
	spoofed := must[*http.Request](t)(fakephone.SignedRequest("https://"+host, fakephone.PendingPath, a.UserID, f.now().Unix(), []byte("{}"), other.DeviceKey))
	spoofed.Header.Set("X-Forwarded-For", "198.51.100.9")
	spoofed.Header.Set("X-Real-IP", "198.51.100.10")
	reused := must[*http.Request](t)(newPhone(t).EnrollRequest(fakephone.Activation{Host: host, UserID: a.UserID, Code: a.Code}, f.now()))

	tests := []struct {
		name     string
		req      *http.Request
		event    string
		reason   string
		userID   string
		clientIP string
	}{
		{"duo unsigned", unsignedDuo, evDuoSignature, "missing_credentials", a.UserID, "192.0.2.1"},
		{"duo wrong secret", duoAt("/auth/v2/auth", authParams(a.UserID), "wrong", f.now()), evDuoSignature, "bad_signature", a.UserID, "192.0.2.1"},
		{"duo stale date", duoAt("/auth/v2/enroll", `{"username":"x"}`, secret, f.now().Add(-6*time.Minute)), evDuoSignature, "stale_date", "", "192.0.2.1"},
		{"duo unknown user", duoAt("/auth/v2/auth", authParams(unenrolled.UserID), secret, f.now()), evDuoRequest, "unknown_user", unenrolled.UserID, "192.0.2.1"},
		{"duo malformed user id", duoAt("/auth/v2/auth", authParams("DU1"), secret, f.now()), evDuoRequest, "unknown_user", "", "192.0.2.1"},
		{"device no header", noAuth, evDeviceSignature, "missing_credentials", "", "192.0.2.1"},
		{"device malformed user id", malformedID, evDeviceSignature, "malformed_user_id", "", "192.0.2.1"},
		{"device stale", must[*http.Request](t)(phone.PendingRequest(a, f.now().Add(-6*time.Minute))), evDeviceSignature, "stale_timestamp", a.UserID, "192.0.2.1"},
		{"device other key", must[*http.Request](t)(fakephone.SignedRequest("https://"+host, fakephone.ChallengePath, a.UserID, f.now().Unix(), []byte(`{"challenge_id":"`+id+`"}`), other.DeviceKey)), evDeviceSignature, "bad_signature", a.UserID, "192.0.2.1"},
		{"device unknown", must[*http.Request](t)(other.PendingRequest(unenrolled, f.now())), evDeviceSignature, "unknown_device", unenrolled.UserID, "192.0.2.1"},
		{"device wrong endpoint", signedForPath(t, phone, a, fakephone.RemovePath, fakephone.PendingPath, []byte("{}"), f.now()), evDeviceSignature, "wrong_endpoint", a.UserID, "192.0.2.1"},
		{"device replayed answer", answered(), evDeviceRequest, "challenge_not_pending", a.UserID, "192.0.2.1"},
		{"device reused activation", reused, evDeviceRequest, "activation_used", a.UserID, "192.0.2.1"},
		{"behind the proxy", proxied, evDeviceSignature, "bad_signature", a.UserID, "198.51.100.9"},
		{"forwarding headers from a non-proxy", spoofed, evDeviceSignature, "bad_signature", a.UserID, "192.0.2.1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			before := lineCount(logs)
			if w := f.serve(tc.req); w.Code/100 != 4 {
				t.Fatalf("status %d %s, want a 4xx", w.Code, w.Body)
			}
			got := securityLines(t, logs, before)
			if len(got) != 1 {
				t.Fatalf("security lines %v, want 1", got)
			}
			l := got[0]
			want := map[string]any{"level": "WARN", "msg": "security", "event": tc.event, "endpoint": tc.req.URL.Path, "reason": tc.reason, "client_ip": tc.clientIP}
			if tc.userID != "" {
				want["user_id"] = tc.userID
			}
			ts, _ := l["time"].(string)
			if _, err := time.Parse(time.RFC3339Nano, ts); err != nil {
				t.Fatalf("line %v has no time", l)
			}
			delete(l, "time")
			if len(l) != len(want) {
				t.Fatalf("line %v, want exactly %v", l, want)
			}
			for k, v := range want {
				if l[k] != v {
					t.Fatalf("line %v: %s = %v, want %v", l, k, l[k], v)
				}
			}
		})
	}
}

func TestClientIP(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128"), netip.MustParsePrefix("172.17.0.1/32")}
	tests := []struct {
		name, peer, xff, realIP, want string
	}{
		{"direct", "203.0.113.5:4000", "", "", "203.0.113.5"},
		{"direct, forged X-Forwarded-For", "203.0.113.5:4000", "198.51.100.9", "", "203.0.113.5"},
		{"direct, forged X-Real-IP", "203.0.113.5:4000", "", "198.51.100.9", "203.0.113.5"},
		{"via loopback proxy", "127.0.0.1:4000", "198.51.100.9", "", "198.51.100.9"},
		{"via docker bridge proxy", "172.17.0.1:4000", "198.51.100.9", "", "198.51.100.9"},
		{"via IPv6 loopback proxy", "[::1]:4000", "2001:db8::7", "", "2001:db8::7"},
		{"client-sent hop before the proxy's", "127.0.0.1:4000", "6.6.6.6, 198.51.100.9", "", "198.51.100.9"},
		{"two proxies", "127.0.0.1:4000", "198.51.100.9, 172.17.0.1", "", "198.51.100.9"},
		{"X-Real-IP from the proxy", "127.0.0.1:4000", "", "198.51.100.9", "198.51.100.9"},
		{"X-Forwarded-For wins over X-Real-IP", "127.0.0.1:4000", "198.51.100.9", "6.6.6.6", "198.51.100.9"},
		{"garbage hop", "127.0.0.1:4000", "not-an-ip", "", "127.0.0.1"},
		{"garbage before a good hop", "127.0.0.1:4000", "not-an-ip, 198.51.100.9", "", "198.51.100.9"},
		{"proxy without headers", "127.0.0.1:4000", "", "", "127.0.0.1"},
		{"v4-mapped peer", "[::ffff:203.0.113.5]:4000", "198.51.100.9", "", "203.0.113.5"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "https://"+host+"/device/v1/pending", nil)
			r.RemoteAddr = tc.peer
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			if tc.realIP != "" {
				r.Header.Set("X-Real-IP", tc.realIP)
			}
			if got := clientIP(r, trusted); got != tc.want {
				t.Fatalf("clientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestLogsCarryNoSecrets runs enrollment, a login, a refused request and a
// removal, and requires that no log line holds a signature, the Duo
// secret, an activation code, a key or a FID.
func TestLogsCarryNoSecrets(t *testing.T) {
	f, logs := newLoggedFixture(t)
	var secrets []string
	sig := func(r *http.Request) *http.Request {
		h := r.Header.Get("Authorization")
		if i := strings.LastIndex(h, ":"); strings.HasPrefix(h, "Frict-P256 ") && i > 0 {
			secrets = append(secrets, h[i+1:])
		} else {
			secrets = append(secrets, strings.TrimPrefix(h, "Basic "))
		}
		return r
	}

	a := f.enroll("alice")
	link := ActivationLink(a.Host, a.UserID, a.Code)
	secrets = append(secrets, a.Code, link, secret)
	f.status(a)
	phone := newPhone(t)
	secrets = append(secrets, phone.FID,
		base64.RawURLEncoding.EncodeToString(spki(t, &phone.DeviceKey.PublicKey)),
		base64.RawURLEncoding.EncodeToString(spki(t, &phone.ApprovalKey.PublicKey)))
	for _, r := range []*http.Request{
		sig(must[*http.Request](t)(newPhone(t).EnrollRequest(fakephone.Activation{Host: host, UserID: a.UserID, Code: "WRONG" + a.Code}, f.now()))),
		sig(must[*http.Request](t)(phone.EnrollRequest(a, f.now()))),
		sig(must[*http.Request](t)(newPhone(t).EnrollRequest(a, f.now()))),
		sig(must[*http.Request](t)(phone.FIDRequest(a, "fid-2-secret", f.now()))),
	} {
		f.serve(r)
	}
	secrets = append(secrets, "fid-2-secret")
	done := f.startAuth(context.Background(), a.UserID)
	cid := f.pending(a, phone, 1)[0]
	f.serve(sig(must[*http.Request](t)(phone.ChallengeRequest(a, cid, f.now()))))
	f.serve(sig(must[*http.Request](t)(phone.AnswerRequest(a, cid, "deny", "not_me", f.now()))))
	f.authResult(done)
	f.serve(sig(must[*http.Request](t)(phone.AnswerRequest(a, cid, "approve", "", f.now()))))
	f.serve(sig(must[*http.Request](t)(newPhone(t).PendingRequest(a, f.now()))))
	f.serve(sig(signedForPath(t, phone, a, fakephone.RemovePath, fakephone.PendingPath, []byte("{}"), f.now())))
	bad := httptest.NewRequest(http.MethodPost, "https://"+host+"/auth/v2/auth", strings.NewReader(authParams(a.UserID)))
	bad.Header.Set("Date", f.now().Format(time.RFC1123Z))
	duosig.Sign(bad, []byte(authParams(a.UserID)), clientID, "wrong", host)
	f.serve(sig(bad))
	f.serve(sig(must[*http.Request](t)(phone.RemoveRequest(a, f.now()))))

	out := logs.String()
	if n := len(securityLines(t, logs, 0)); n < 5 {
		t.Fatalf("only %d security lines; the test did not exercise rejections:\n%s", n, out)
	}
	for _, s := range secrets {
		if s == "" {
			t.Fatal("empty secret: the test lost a value it meant to look for")
		}
		if strings.Contains(out, s) {
			t.Errorf("logs contain %q:\n%s", s, out)
		}
	}
}
