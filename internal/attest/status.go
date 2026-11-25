package attest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// GoogleStatusURL serves Google's attestation revocation list
// (developer.android.com/privacy-and-security/security-key-attestation#certificate_status).
const GoogleStatusURL = "https://android.googleapis.com/attestation/status"

const maxStatusBytes = 16 << 20

// StatusList fetches a revocation list from URL and keeps it for TTL. A
// failed fetch fails the Load: an expired copy is never used.
type StatusList struct {
	URL    string
	Client *http.Client
	TTL    time.Duration
	Now    func() time.Time

	mu      sync.Mutex
	fetched time.Time
	entries map[string]string
}

func (l *StatusList) Load(ctx context.Context) (map[string]string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.Now()
	if l.entries != nil && now.Sub(l.fetched) < l.TTL {
		return l.entries, nil
	}
	entries, err := l.fetch(ctx)
	if err != nil {
		return nil, err
	}
	l.entries, l.fetched = entries, now
	return entries, nil
}

func (l *StatusList) fetch(ctx context.Context) (map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.URL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := l.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", l.URL, resp.Status)
	}
	var list struct {
		Entries map[string]struct {
			Status string `json:"status"`
		} `json:"entries"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxStatusBytes)).Decode(&list); err != nil {
		return nil, fmt.Errorf("GET %s: %w", l.URL, err)
	}
	if list.Entries == nil {
		return nil, fmt.Errorf("GET %s: no entries object", l.URL)
	}
	entries := make(map[string]string, len(list.Entries))
	for serial, e := range list.Entries {
		entries[serial] = e.Status
	}
	return entries, nil
}
