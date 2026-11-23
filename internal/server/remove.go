package server

import (
	"errors"
	"net/http"

	"github.com/frict-auth/frict-server/internal/store"
)

// deviceRemove deletes the user's enrollment and everything stored for it,
// signed with the device_key. From then on /auth/v2/auth for that user_id
// gets Duo's answer for an unknown user, and the device's key verifies
// nothing.
func (s *Server) deviceRemove(w http.ResponseWriter, r *http.Request) {
	userID, body, ok := s.deviceSigned(w, r, deviceKey)
	if !ok {
		return
	}
	if err := decodeStrict(body, &struct{}{}); err != nil {
		s.badRequest(w, r, userID)
		return
	}
	err := s.store.RemoveUser(r.Context(), userID)
	switch {
	case errors.Is(err, store.ErrNoDevice):
		s.security(r, evDeviceSignature, "unknown_device", userID)
		deviceFail(w, http.StatusUnauthorized, "unauthorized")
		return
	case err != nil:
		s.log.Error("remove: store", "err", err)
		deviceFail(w, http.StatusInternalServerError, "internal")
		return
	}
	s.log.Info("device removed", "user_id", userID)
	writeJSON(w, http.StatusOK, struct{}{})
}
