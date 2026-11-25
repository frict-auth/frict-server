package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strings"

	"github.com/frict-auth/frict-server/internal/devicesig"
	"github.com/frict-auth/frict-server/internal/duosig"
	"github.com/frict-auth/frict-server/internal/store"
)

// Security events, one log line each with message "security"
// (docs/PLAN.md "Security log"). The names and reason codes are an
// interface: alerting matches on them.
const (
	evDuoSignature    = "duo_signature_rejected"
	evDuoRequest      = "duo_request_rejected"
	evDeviceSignature = "device_signature_rejected"
	evDeviceRequest   = "device_request_rejected"
	evAttestation     = "attestation_rejected"
)

// LoopbackProxies trusts forwarding headers only from the host itself.
var LoopbackProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}

// security logs a rejected request. userID is what the request claims, and
// is logged only if it has the form Frict issues. extra are more attributes,
// after the reason.
func (s *Server) security(r *http.Request, event, reason, userID string, extra ...any) {
	attrs := append([]any{"event", event, "endpoint", r.URL.Path, "reason", reason}, extra...)
	if devicesig.ValidUserID(userID) {
		attrs = append(attrs, "user_id", userID)
	}
	attrs = append(attrs, "client_ip", clientIP(r, s.trusted))
	s.log.Warn("security", attrs...)
}

// clientIP is the address r came from. Behind a trusted proxy that is the
// last X-Forwarded-For hop not itself a trusted proxy, or X-Real-IP when
// there is no X-Forwarded-For; otherwise the peer's address.
func clientIP(r *http.Request, trusted []netip.Prefix) string {
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	ip := peer.Addr().Unmap()
	if !inAny(ip, trusted) {
		return ip.String()
	}
	if xff := r.Header.Values("X-Forwarded-For"); len(xff) > 0 {
		hops := strings.Split(strings.Join(xff, ","), ",")
		for i := len(hops) - 1; i >= 0; i-- {
			hop, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
			if err != nil {
				break
			}
			ip = hop.Unmap()
			if !inAny(ip, trusted) {
				break
			}
		}
		return ip.String()
	}
	if real, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get("X-Real-IP"))); err == nil {
		return real.Unmap().String()
	}
	return ip.String()
}

func inAny(ip netip.Addr, prefixes []netip.Prefix) bool {
	for _, p := range prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func duoReason(err error) string {
	for _, r := range []struct {
		err  error
		code string
	}{
		{duosig.ErrMissingCredentials, "missing_credentials"},
		{duosig.ErrMalformedHeader, "malformed_header"},
		{duosig.ErrUnknownIKey, "unknown_client_id"},
		{duosig.ErrMissingDate, "missing_date"},
		{duosig.ErrMalformedDate, "malformed_date"},
		{duosig.ErrStaleDate, "stale_date"},
		{duosig.ErrBadXDuoHeader, "repeated_x_duo_header"},
		{duosig.ErrBadSignature, "bad_signature"},
	} {
		if errors.Is(err, r.err) {
			return r.code
		}
	}
	return "invalid"
}

// deviceRejection is the event and reason for a device request that failed
// verification.
func deviceRejection(err error) (event, reason string) {
	for _, r := range []struct {
		err   error
		event string
		code  string
	}{
		{devicesig.ErrMissingCredentials, evDeviceSignature, "missing_credentials"},
		{devicesig.ErrMalformedUserID, evDeviceSignature, "malformed_user_id"},
		{devicesig.ErrMalformedHeader, evDeviceSignature, "malformed_header"},
		{devicesig.ErrStale, evDeviceSignature, "stale_timestamp"},
		{devicesig.ErrWrongEndpoint, evDeviceSignature, "wrong_endpoint"},
		{devicesig.ErrBadSignature, evDeviceSignature, "bad_signature"},
		{store.ErrNoDevice, evDeviceSignature, "unknown_device"},
		{errBadEnroll, evDeviceRequest, "bad_enroll_body"},
		{store.ErrActivationInvalid, evDeviceRequest, "activation_invalid"},
		{store.ErrActivationUsed, evDeviceRequest, "activation_used"},
		{store.ErrUserMismatch, evDeviceRequest, "user_mismatch"},
	} {
		if errors.Is(err, r.err) {
			return r.event, r.code
		}
	}
	return evDeviceSignature, "internal_error"
}

// duoUserID is the user_id a Duo request's body names, if any.
func duoUserID(body []byte) string {
	var p struct {
		UserID string `json:"user_id"`
	}
	json.Unmarshal(body, &p)
	return p.UserID
}
