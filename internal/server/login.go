package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/frict-auth/frict-server/internal/devicesig"
	"github.com/frict-auth/frict-server/internal/store"
)

// duoAuth answers duo_client's synchronous Auth.auth: it creates a challenge
// for the user's device and blocks until the device answers it, it expires,
// or the caller goes away. Authentik 2026.8.5 calls it with factor "auto"
// and reads only result (authenticator_validate/challenge.py:276-306).
func (s *Server) duoAuth(w http.ResponseWriter, r *http.Request) {
	p, err := duoParams(r)
	if err != nil {
		duoFail(w, http.StatusBadRequest, 40002, "Invalid request parameters")
		return
	}
	if p["async"] == "1" {
		duoFail(w, http.StatusBadRequest, 40002, "Invalid request parameters: async is not supported")
		return
	}
	if p["factor"] != "auto" && p["factor"] != "push" {
		duoFail(w, http.StatusBadRequest, 40002, "Invalid request parameters: factor must be auto or push")
		return
	}
	userID := p["user_id"]
	if _, err := s.store.DeviceOf(r.Context(), userID); errors.Is(err, store.ErrNoDevice) {
		s.log.Warn("auth for a user without a device", "user_id", userID)
		duoFail(w, http.StatusBadRequest, 40002, "Invalid request parameters: user_id")
		return
	} else if err != nil {
		s.log.Error("auth: store", "err", err)
		duoFail(w, http.StatusInternalServerError, 50000, "Internal error")
		return
	}

	id := make([]byte, 16)
	rand.Read(id)
	now := s.verifier.Now()
	c := store.Challenge{
		ID:              id,
		UserID:          userID,
		DisplayUsername: p["display_username"],
		IPAddr:          p["ipaddr"],
		PushInfo:        p["pushinfo"],
		Type:            p["type"],
		CreatedAt:       now,
		ExpiresAt:       now.Add(s.challengeTTL),
	}
	answered := s.awaitAnswer(id)
	defer s.stopAwaiting(id)
	// Not cancelled with the request: a challenge, once stored, must reach
	// CloseChallenge below, or it stays pending for the device until it
	// expires.
	if err := s.store.CreateChallenge(context.WithoutCancel(r.Context()), c); err != nil {
		s.log.Error("auth: store", "err", err)
		duoFail(w, http.StatusInternalServerError, 50000, "Internal error")
		return
	}
	s.log.Info("challenge created", "user_id", userID, "challenge_id", encodeID(id), "expires_in", s.challengeTTL.String())

	timer := time.NewTimer(s.challengeTTL)
	defer timer.Stop()
	select {
	case <-answered:
	case <-timer.C:
	case <-r.Context().Done():
	}
	out, err := s.store.CloseChallenge(context.WithoutCancel(r.Context()), id)
	if err != nil {
		s.log.Error("auth: store", "err", err)
		duoFail(w, http.StatusInternalServerError, 50000, "Internal error")
		return
	}
	if r.Context().Err() != nil {
		s.log.Info("auth caller gone", "user_id", userID, "challenge_id", encodeID(id), "status", string(out.Status))
		return
	}
	s.log.Info("challenge closed", "user_id", userID, "challenge_id", encodeID(id), "status", string(out.Status), "reason", out.Reason)
	duoOK(w, duoResult(out))
}

// duoResult is the /auth response for a challenge's outcome, in Duo's
// vocabulary (duo.com/docs/authapi, /auth status values). Authentik logs a
// deny's whole response in its login_failed event
// (authenticator_validate/challenge.py:292-305), so the status tells
// "not me" (fraud) apart from cancel (deny) and timeout there.
func duoResult(o store.Outcome) map[string]string {
	switch {
	case o.Status == store.ChallengeApproved:
		return map[string]string{"result": "allow", "status": "allow", "status_msg": "Success. Logging you in..."}
	case o.Status == store.ChallengeDenied && o.Reason == "not_me":
		return map[string]string{"result": "deny", "status": "fraud", "status_msg": "Login request reported as fraudulent."}
	case o.Status == store.ChallengeDenied:
		return map[string]string{"result": "deny", "status": "deny", "status_msg": "Login request denied."}
	default:
		return map[string]string{"result": "deny", "status": "timeout", "status_msg": "Login timed out."}
	}
}

// awaitAnswer returns a channel deviceAnswer closes when challenge id is
// answered.
func (s *Server) awaitAnswer(id []byte) <-chan struct{} {
	ch := make(chan struct{})
	s.mu.Lock()
	s.answered[string(id)] = ch
	s.mu.Unlock()
	return ch
}

func (s *Server) stopAwaiting(id []byte) {
	s.mu.Lock()
	delete(s.answered, string(id))
	s.mu.Unlock()
}

func (s *Server) wakeAuth(id []byte) {
	s.mu.Lock()
	if ch, ok := s.answered[string(id)]; ok {
		close(ch)
		delete(s.answered, string(id))
	}
	s.mu.Unlock()
}

func encodeID(id []byte) string { return base64.RawURLEncoding.EncodeToString(id) }

func decodeID(s string) ([]byte, bool) {
	id, err := base64.RawURLEncoding.Strict().DecodeString(s)
	return id, err == nil && len(id) == 16
}

// deviceSigned reads a device request's body and verifies its signature
// against the header user's stored key that keyOf picks. On failure it has
// already answered the request.
func (s *Server) deviceSigned(w http.ResponseWriter, r *http.Request, keyOf func(store.Device) []byte) (userID string, body []byte, ok bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		deviceFail(w, http.StatusBadRequest, "bad_request")
		return "", nil, false
	}
	userID, err = devicesig.Verify(r, body, s.verifier.Now(), func(userID string) (*ecdsa.PublicKey, error) {
		d, err := s.store.DeviceOf(r.Context(), userID)
		if err != nil {
			return nil, err
		}
		return p256FromDER(keyOf(d))
	})
	if err != nil {
		s.log.Warn("device request rejected", "path", r.URL.Path, "reason", err.Error())
		deviceFail(w, http.StatusUnauthorized, "unauthorized")
		return "", nil, false
	}
	return userID, body, true
}

func deviceKey(d store.Device) []byte   { return d.DeviceKey }
func approvalKey(d store.Device) []byte { return d.ApprovalKey }

// devicePending lists the user's pending challenges.
func (s *Server) devicePending(w http.ResponseWriter, r *http.Request) {
	userID, body, ok := s.deviceSigned(w, r, deviceKey)
	if !ok {
		return
	}
	if err := decodeStrict(body, &struct{}{}); err != nil {
		deviceFail(w, http.StatusBadRequest, "bad_request")
		return
	}
	cs, err := s.store.PendingChallenges(r.Context(), userID, s.verifier.Now())
	if err != nil {
		s.log.Error("pending: store", "err", err)
		deviceFail(w, http.StatusInternalServerError, "internal")
		return
	}
	ids := []string{}
	for _, c := range cs {
		ids = append(ids, encodeID(c.ID))
	}
	writeJSON(w, http.StatusOK, map[string]any{"challenge_ids": ids, "poll_interval": PollInterval})
}

type challengeRequest struct {
	ChallengeID string `json:"challenge_id"`
}

// deviceChallenge returns what a pending challenge asks the user to
// approve.
func (s *Server) deviceChallenge(w http.ResponseWriter, r *http.Request) {
	userID, body, ok := s.deviceSigned(w, r, deviceKey)
	if !ok {
		return
	}
	var req challengeRequest
	id, valid := []byte(nil), false
	if err := decodeStrict(body, &req); err == nil {
		id, valid = decodeID(req.ChallengeID)
	}
	if !valid {
		deviceFail(w, http.StatusBadRequest, "bad_request")
		return
	}
	c, err := s.store.PendingChallenge(r.Context(), id, userID, s.verifier.Now())
	if errors.Is(err, store.ErrChallengeNotFound) {
		deviceFail(w, http.StatusNotFound, "not_found")
		return
	} else if err != nil {
		s.log.Error("challenge: store", "err", err)
		deviceFail(w, http.StatusInternalServerError, "internal")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"challenge_id": encodeID(c.ID),
		"username":     c.DisplayUsername,
		"ipaddr":       c.IPAddr,
		"pushinfo":     c.PushInfo,
		"type":         c.Type,
		"created":      c.CreatedAt.Unix(),
		"expires":      c.ExpiresAt.Unix(),
	})
}

type answerRequest struct {
	ChallengeID string `json:"challenge_id"`
	Decision    string `json:"decision"`
	Reason      string `json:"reason"`
}

// parseAnswer maps an answer body to the challenge it names and the outcome
// it asks for: approve with no reason, or deny with not_me or cancel.
func parseAnswer(body []byte) ([]byte, store.Outcome, bool) {
	var req answerRequest
	if err := decodeStrict(body, &req); err != nil {
		return nil, store.Outcome{}, false
	}
	id, ok := decodeID(req.ChallengeID)
	if !ok {
		return nil, store.Outcome{}, false
	}
	switch {
	case req.Decision == "approve" && req.Reason == "":
		return id, store.Outcome{Status: store.ChallengeApproved}, true
	case req.Decision == "deny" && (req.Reason == "not_me" || req.Reason == "cancel"):
		return id, store.Outcome{Status: store.ChallengeDenied, Reason: req.Reason}, true
	}
	return nil, store.Outcome{}, false
}

// deviceAnswer records the user's approve or deny, signed with the
// approval_key, and wakes the /auth call waiting on it.
func (s *Server) deviceAnswer(w http.ResponseWriter, r *http.Request) {
	userID, body, ok := s.deviceSigned(w, r, approvalKey)
	if !ok {
		return
	}
	id, answer, ok := parseAnswer(body)
	if !ok {
		deviceFail(w, http.StatusBadRequest, "bad_request")
		return
	}
	err := s.store.AnswerChallenge(r.Context(), id, userID, answer, s.verifier.Now())
	switch {
	case errors.Is(err, store.ErrChallengeNotFound):
		deviceFail(w, http.StatusNotFound, "not_found")
		return
	case errors.Is(err, store.ErrChallengeNotPending):
		s.log.Warn("answer for a closed challenge", "user_id", userID, "challenge_id", encodeID(id))
		deviceFail(w, http.StatusConflict, "not_pending")
		return
	case err != nil:
		s.log.Error("answer: store", "err", err)
		deviceFail(w, http.StatusInternalServerError, "internal")
		return
	}
	s.log.Info("challenge answered", "user_id", userID, "challenge_id", encodeID(id), "status", string(answer.Status), "reason", answer.Reason)
	s.wakeAuth(id)
	writeJSON(w, http.StatusOK, struct{}{})
}
