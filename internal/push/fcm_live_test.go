//go:build fcmlive

package push

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"testing"
	"time"
)

// bodyLog keeps a copy of each response body FCM sends back.
type bodyLog struct {
	bodies []string
}

func (l *bodyLog) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	l.bodies = append(l.bodies, string(b))
	resp.Body = io.NopCloser(bytes.NewReader(b))
	return resp, nil
}

// TestFCMLive sends a validate_only message to an FID no device holds,
// with the access token CI minted through workload identity federation.
// FCM rejecting the FID itself proves the token may send for the project;
// an auth or IAM problem surfaces as 401 or 403 instead.
func TestFCMLive(t *testing.T) {
	token, project := os.Getenv("FCM_ACCESS_TOKEN"), os.Getenv("FCM_PROJECT_ID")
	if token == "" || project == "" {
		t.Fatal("FCM_ACCESS_TOKEN and FCM_PROJECT_ID must be set")
	}
	log := &bodyLog{}
	f := NewFCM(FCMBaseURL, project,
		tokenFunc(func(context.Context) (string, error) { return token, nil }),
		&http.Client{Timeout: 30 * time.Second, Transport: log})
	f.ValidateOnly = true

	name, err := f.Send(context.Background(), Message{FID: "cFrictCiNotARealFid00A", Data: map[string]string{"challenge_id": "AAAA"}})
	for _, b := range log.bodies {
		t.Logf("FCM response body: %s", b)
	}
	switch {
	case err == nil:
		t.Logf("FCM accepted the message: %s", name)
	case errors.Is(err, ErrUnregistered):
		t.Logf("FCM rejected the FID, so the token is authorized: %v", err)
	default:
		t.Fatalf("Send = %v; want the FID rejected (400 INVALID_ARGUMENT or 404 UNREGISTERED) or accepted", err)
	}
}
