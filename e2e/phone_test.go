//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/frict-auth/frict-server/internal/duosig"
	"github.com/frict-auth/frict-server/internal/fakephone"
)

// device is a fake phone enrolled on frict-server, and the account it
// enrolled for.
type device struct {
	phone *fakephone.Phone
	act   fakephone.Activation
}

// send sends req from the phone over TLS to frict-server. A transport error
// comes back as status 0 with the error as the body.
func send(req *http.Request) (int, string) {
	resp, err := env.phoneClient.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err.Error()
	}
	return resp.StatusCode, strings.TrimSpace(string(body))
}

// replayable returns a copy of a request that has the same headers and body,
// for sending the same bytes again.
func replayable(req *http.Request, body []byte) *http.Request {
	r := req.Clone(req.Context())
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	return r
}

func enrollPhone(phone *fakephone.Phone, act fakephone.Activation) (int, string) {
	req, err := phone.EnrollRequest(act, time.Now())
	if err != nil {
		return 0, err.Error()
	}
	return send(req)
}

func (d device) pending() ([]string, error) {
	req, err := d.phone.PendingRequest(d.act, time.Now())
	if err != nil {
		return nil, err
	}
	status, body := send(req)
	if status != http.StatusOK {
		return nil, fmt.Errorf("pending: %d %s", status, body)
	}
	var p fakephone.Pending
	if err := json.Unmarshal([]byte(body), &p); err != nil {
		return nil, fmt.Errorf("pending body %s: %w", body, err)
	}
	return p.ChallengeIDs, nil
}

// waitChallenge polls until the account has a pending challenge and returns
// the oldest.
func (d device) waitChallenge(limit time.Duration) (string, error) {
	deadline := time.Now().Add(limit)
	for {
		ids, err := d.pending()
		if err != nil {
			return "", err
		}
		if len(ids) > 0 {
			return ids[0], nil
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("no pending challenge for %s within %s", d.act.UserID, limit)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func (d device) details(id string) (fakephone.Challenge, error) {
	req, err := d.phone.ChallengeRequest(d.act, id, time.Now())
	if err != nil {
		return fakephone.Challenge{}, err
	}
	status, body := send(req)
	if status != http.StatusOK {
		return fakephone.Challenge{}, fmt.Errorf("challenge: %d %s", status, body)
	}
	var c fakephone.Challenge
	err = json.Unmarshal([]byte(body), &c)
	return c, err
}

func (d device) answer(id, decision, reason string) (int, string) {
	req, err := d.phone.AnswerRequest(d.act, id, decision, reason, time.Now())
	if err != nil {
		return 0, err.Error()
	}
	return send(req)
}

// enrollViaDuoAPI makes the /auth/v2/enroll call Authentik's setup stage
// makes, signed with the stage's secret, and enrolls a new phone with the
// activation it returns.
func enrollViaDuoAPI(username string) (device, error) {
	body, err := json.Marshal(map[string]string{"username": username})
	if err != nil {
		return device{}, err
	}
	req, err := http.NewRequest(http.MethodPost, "https://"+frictHostname+"/auth/v2/enroll", bytes.NewReader(body))
	if err != nil {
		return device{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Date", time.Now().UTC().Format(time.RFC1123Z))
	if err := duosig.Sign(req, body, duoClientID, env.duoSecret, frictHostname); err != nil {
		return device{}, err
	}
	status, resp := send(req)
	if status != http.StatusOK {
		return device{}, fmt.Errorf("/auth/v2/enroll for %s: %d %s", username, status, resp)
	}
	var out struct {
		Response struct {
			ActivationCode string `json:"activation_code"`
		}
	}
	if err := json.Unmarshal([]byte(resp), &out); err != nil {
		return device{}, err
	}
	act, err := fakephone.ParseActivation(out.Response.ActivationCode)
	if err != nil {
		return device{}, err
	}
	phone, err := fakephone.New()
	if err != nil {
		return device{}, err
	}
	if status, resp := enrollPhone(phone, act); status != http.StatusOK {
		return device{}, fmt.Errorf("phone enroll for %s: %d %s", username, status, resp)
	}
	return device{phone: phone, act: act}, nil
}
