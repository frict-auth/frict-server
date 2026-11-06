package push

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

const (
	FCMBaseURL = "https://fcm.googleapis.com"
	// FCMScope is the OAuth scope a TokenSource's tokens must carry.
	FCMScope = "https://www.googleapis.com/auth/firebase.messaging"
)

// TokenSource returns an OAuth 2.0 access token for FCMScope. FCM calls it
// before every send, so it caches the token and mints a new one only near
// expiry.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// FCM sends data messages through the FCM HTTP v1 API.
type FCM struct {
	client   *http.Client
	endpoint string
	tokens   TokenSource
}

// NewFCM sends to project projectID at baseURL (FCMBaseURL outside tests),
// authorized by tokens. client's Timeout bounds each send.
func NewFCM(baseURL, projectID string, tokens TokenSource, client *http.Client) *FCM {
	return &FCM{
		client:   client,
		endpoint: baseURL + "/v1/projects/" + url.PathEscape(projectID) + "/messages:send",
		tokens:   tokens,
	}
}

type fcmRequest struct {
	Message fcmMessage `json:"message"`
}

type fcmMessage struct {
	FID     string            `json:"fid"`
	Data    map[string]string `json:"data"`
	Android fcmAndroid        `json:"android"`
}

type fcmAndroid struct {
	Priority string `json:"priority"`
}

type fcmErrorResponse struct {
	Error struct {
		Status  string `json:"status"`
		Details []struct {
			ErrorCode string `json:"errorCode"`
		} `json:"details"`
	} `json:"error"`
}

// Send sends m at Android priority high, so it can wake a device in Doze.
// Errors name the HTTP status and FCM's error code, never the FID or
// the data.
func (f *FCM) Send(ctx context.Context, m Message) (string, error) {
	token, err := f.tokens.Token(ctx)
	if err != nil {
		return "", fmt.Errorf("fcm token: %w", err)
	}
	body, err := json.Marshal(fcmRequest{Message: fcmMessage{
		FID:     m.FID,
		Data:    m.Data,
		Android: fcmAndroid{Priority: "high"},
	}})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := f.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fcm send: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 == 2 {
		// FCM has accepted the message; a broken body loses only its name.
		var ok struct {
			Name string `json:"name"`
		}
		json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&ok)
		return ok.Name, nil
	}

	code := fcmErrorCode(resp.Body)
	switch {
	// Frict's data messages are a few dozen bytes of fixed shape, so
	// INVALID_ARGUMENT can only be about the FID.
	case resp.StatusCode == http.StatusNotFound && code == "UNREGISTERED",
		resp.StatusCode == http.StatusBadRequest && code == "INVALID_ARGUMENT":
		return "", fmt.Errorf("%w (HTTP %d %s)", ErrUnregistered, resp.StatusCode, code)
	default:
		return "", fmt.Errorf("fcm send: HTTP %d %s", resp.StatusCode, code)
	}
}

// fcmErrorCode extracts the FcmError errorCode from an error response,
// falling back to the canonical status. The rest of the body is discarded
// because FCM may echo the request back in its message.
func fcmErrorCode(r io.Reader) string {
	var e fcmErrorResponse
	if err := json.NewDecoder(io.LimitReader(r, 64<<10)).Decode(&e); err != nil {
		return "(unparseable error body)"
	}
	for _, d := range e.Error.Details {
		if d.ErrorCode != "" {
			return d.ErrorCode
		}
	}
	return e.Error.Status
}
