package server

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/frict-auth/frict-server/internal/push"
	"github.com/frict-auth/frict-server/internal/store"
)

// pushTimeout bounds one push, the FID lookup and an FCM send together.
const pushTimeout = 30 * time.Second

// wake pushes data to userID's device in the background. Nothing waits on
// the result: a device that misses a push finds its challenges and alerts
// by polling /device/v1/pending. Close waits for pushes in flight.
func (s *Server) wake(userID string, data map[string]string) {
	if s.sender == nil {
		return
	}
	s.pushes.Add(1)
	go func() {
		defer s.pushes.Done()
		ctx, cancel := context.WithTimeout(context.Background(), pushTimeout)
		defer cancel()
		d, err := s.store.DeviceOf(ctx, userID)
		if err != nil {
			s.log.Error("push: store", "user_id", userID, "err", err)
			return
		}
		if d.FID == "" {
			s.log.Info("push skipped: no FID, device must poll", "user_id", userID)
			return
		}
		name, err := s.sender.Send(ctx, push.Message{FID: d.FID, Data: data})
		switch {
		case errors.Is(err, push.ErrUnregistered):
			s.log.Warn("push failed: FID unregistered, clearing it", "user_id", userID, "err", err)
			if err := s.store.ClearFID(ctx, userID, d.FID); err != nil {
				s.log.Error("push: clear FID", "user_id", userID, "err", err)
			}
		case err != nil:
			s.log.Warn("push failed", "user_id", userID, "err", err)
		default:
			s.log.Info("push sent", "user_id", userID, "fcm_message", name)
		}
	}()
}

// Close waits for pushes in flight. Call it once the HTTP server has stopped
// handling requests.
func (s *Server) Close() { s.pushes.Wait() }

// pushAlerts wakes each recipient of the alerts a not_me deny of
// challengeID created.
func (s *Server) pushAlerts(ctx context.Context, challengeID []byte) {
	rs, err := s.store.AlertRecipients(ctx, challengeID)
	if err != nil {
		s.log.Error("push alerts: store", "challenge_id", encodeID(challengeID), "err", err)
		return
	}
	for _, r := range rs {
		s.wake(r.UserID, map[string]string{"alert_id": encodeID(r.AlertID)})
	}
}

type fidRequest struct {
	FID string `json:"fid"`
}

// deviceFID sets where the user's device is pushed to, signed with the
// device_key.
func (s *Server) deviceFID(w http.ResponseWriter, r *http.Request) {
	userID, body, ok := s.deviceSigned(w, r, deviceKey)
	if !ok {
		return
	}
	var req fidRequest
	if err := decodeStrict(body, &req); err != nil || req.FID == "" {
		deviceFail(w, http.StatusBadRequest, "bad_request")
		return
	}
	err := s.store.SetFID(r.Context(), userID, req.FID)
	switch {
	case errors.Is(err, store.ErrNoDevice):
		deviceFail(w, http.StatusUnauthorized, "unauthorized")
		return
	case err != nil:
		s.log.Error("fid: store", "err", err)
		deviceFail(w, http.StatusInternalServerError, "internal")
		return
	}
	s.log.Info("FID updated", "user_id", userID)
	writeJSON(w, http.StatusOK, struct{}{})
}
