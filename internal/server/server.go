// Package server routes Frict's HTTP API: Duo's Auth API for Authentik on
// /auth/v2/*, the device API on /device/v1/*, and /healthz.
package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/frict-auth/frict-server/internal/devicesig"
	"github.com/frict-auth/frict-server/internal/duosig"
	"github.com/frict-auth/frict-server/internal/store"
)

const (
	maxBodyBytes = 64 << 10

	// ActivationValidity is how long an activation code from /auth/v2/enroll
	// can enroll a device. Authentik sends no valid_secs.
	ActivationValidity = 15 * time.Minute

	// PollInterval is how many seconds a device waits between polls of
	// /device/v1/pending.
	PollInterval = 5
)

type Store interface {
	Ping(ctx context.Context) error
	CreateEnrollment(ctx context.Context, userID, username, code string, now, expires time.Time) error
	EnrollmentStatusOf(ctx context.Context, userID, code string, now time.Time) (store.EnrollmentStatus, error)
	Enroll(ctx context.Context, code, claimedUserID string, d store.Device) error
	DeviceOf(ctx context.Context, userID string) (store.Device, error)
	CreateChallenge(ctx context.Context, c store.Challenge) error
	PendingChallenges(ctx context.Context, userID string, now time.Time) ([]store.Challenge, error)
	PendingChallenge(ctx context.Context, id []byte, userID string, now time.Time) (store.Challenge, error)
	AnswerChallenge(ctx context.Context, id []byte, userID string, answer store.Outcome, now time.Time) error
	CloseChallenge(ctx context.Context, id []byte) (store.Outcome, error)
}

// Server serves one Authentik Duo stage. The verifier's Host is the API
// hostname devices are sent to, and its Now is the server's clock.
type Server struct {
	verifier     duosig.Verifier
	store        Store
	challengeTTL time.Duration
	log          *slog.Logger

	mu       sync.Mutex
	answered map[string]chan struct{} // challenge ID -> closed when the device answers
}

// New returns a Server whose pushes expire challengeTTL after /auth/v2/auth
// creates them. challengeTTL is whole seconds, since the store keeps
// timestamps in seconds.
func New(v duosig.Verifier, st Store, challengeTTL time.Duration, log *slog.Logger) *Server {
	return &Server{verifier: v, store: st, challengeTTL: challengeTTL, log: log, answered: map[string]chan struct{}{}}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.Handle("POST /auth/v2/enroll", s.duoSigned(s.duoEnroll))
	mux.Handle("POST /auth/v2/enroll_status", s.duoSigned(s.duoEnrollStatus))
	mux.Handle("POST /auth/v2/auth", s.duoSigned(s.duoAuth))
	mux.HandleFunc("POST /device/v1/enroll", s.deviceEnroll)
	mux.HandleFunc("POST /device/v1/pending", s.devicePending)
	mux.HandleFunc("POST /device/v1/challenge", s.deviceChallenge)
	mux.HandleFunc("POST /device/v1/answer", s.deviceAnswer)
	return mux
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
		s.log.Error("healthz: store unavailable", "err", err)
		http.Error(w, "store unavailable", http.StatusServiceUnavailable)
		return
	}
	io.WriteString(w, "ok\n")
}

// duoSigned answers 401 unless the request carries a valid sig v5 signature
// from the configured Authentik Duo stage, then hands next the request with
// its body intact.
func (s *Server) duoSigned(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
		if err != nil {
			duoFail(w, http.StatusBadRequest, 40002, "Invalid request body")
			return
		}
		if err := s.verifier.Verify(r, body); err != nil {
			s.log.Warn("duo signature rejected", "path", r.URL.Path, "reason", err.Error())
			duoFail(w, http.StatusUnauthorized, 40103, "Invalid signature in request credentials")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		next(w, r)
	})
}

// duoParams decodes the JSON object of string parameters duo_client sends.
func duoParams(r *http.Request) (map[string]string, error) {
	p := map[string]string{}
	err := json.NewDecoder(r.Body).Decode(&p)
	return p, err
}

// duoEnroll answers duo_client's Auth.enroll with a new user and a single-use
// activation code for it. activation_code is the app link; Authentik renders
// it as a link and activation_barcode as an image source.
func (s *Server) duoEnroll(w http.ResponseWriter, r *http.Request) {
	p, err := duoParams(r)
	if err != nil || p["username"] == "" {
		duoFail(w, http.StatusBadRequest, 40002, "Missing required request parameters: username")
		return
	}
	userID := "DU" + rand.Text()
	code := rand.Text()
	now := s.verifier.Now()
	if err := s.store.CreateEnrollment(r.Context(), userID, p["username"], code, now, now.Add(ActivationValidity)); err != nil {
		s.log.Error("enroll: store", "err", err)
		duoFail(w, http.StatusInternalServerError, 50000, "Internal error")
		return
	}
	s.log.Info("enrollment created", "user_id", userID, "username", p["username"])
	link := ActivationLink(s.verifier.Host, userID, code)
	duoOK(w, map[string]any{
		"activation_barcode": link,
		"activation_code":    link,
		"user_id":            userID,
		"username":           p["username"],
		"valid_secs":         int(ActivationValidity / time.Second),
	})
}

// duoEnrollStatus answers duo_client's Auth.enroll_status, whose
// activation_code is the link duoEnroll returned.
func (s *Server) duoEnrollStatus(w http.ResponseWriter, r *http.Request) {
	p, err := duoParams(r)
	if err != nil || p["user_id"] == "" || p["activation_code"] == "" {
		duoFail(w, http.StatusBadRequest, 40002, "Missing required request parameters: user_id, activation_code")
		return
	}
	status := store.EnrollmentInvalid
	if code, ok := codeFromLink(p["activation_code"]); ok {
		status, err = s.store.EnrollmentStatusOf(r.Context(), p["user_id"], code, s.verifier.Now())
		if err != nil {
			s.log.Error("enroll_status: store", "err", err)
			duoFail(w, http.StatusInternalServerError, 50000, "Internal error")
			return
		}
	}
	s.log.Info("enroll_status", "user_id", p["user_id"], "status", string(status))
	duoOK(w, status)
}

// ActivationLink is the app link for an activation: what the enrollment QR
// code encodes.
func ActivationLink(apiHost, userID, code string) string {
	q := url.Values{"host": {apiHost}, "user_id": {userID}, "code": {code}}
	return "frict://enroll?" + q.Encode()
}

func codeFromLink(link string) (string, bool) {
	u, err := url.Parse(link)
	if err != nil || u.Scheme != "frict" || u.Host != "enroll" {
		return "", false
	}
	code := u.Query().Get("code")
	return code, code != ""
}

type enrollRequest struct {
	ActivationCode string          `json:"activation_code"`
	DeviceKey      string          `json:"device_key"`
	ApprovalKey    string          `json:"approval_key"`
	Attestation    json.RawMessage `json:"attestation"`
	FID            string          `json:"fid"`
}

// deviceEnroll registers a phone's keys for the user its activation code was
// issued to. The signature is checked against the body's device_key; the
// header's user_id must be the code's user.
func (s *Server) deviceEnroll(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		deviceFail(w, http.StatusBadRequest, "bad_request")
		return
	}
	now := s.verifier.Now()
	var req enrollRequest
	var dev store.Device
	userID, err := devicesig.Verify(r, body, now, func(string) (*ecdsa.PublicKey, error) {
		var key *ecdsa.PublicKey
		var perr error
		req, dev, key, perr = parseEnroll(body)
		return key, perr
	})
	if err != nil {
		s.log.Warn("device enroll rejected", "reason", err.Error())
		deviceFail(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	dev.EnrolledAt = now
	err = s.store.Enroll(r.Context(), req.ActivationCode, userID, dev)
	switch {
	case errors.Is(err, store.ErrActivationInvalid), errors.Is(err, store.ErrActivationUsed), errors.Is(err, store.ErrUserMismatch):
		s.log.Warn("device enroll rejected", "user_id", userID, "reason", err.Error())
		deviceFail(w, http.StatusUnauthorized, "unauthorized")
		return
	case err != nil:
		s.log.Error("device enroll: store", "err", err)
		deviceFail(w, http.StatusInternalServerError, "internal")
		return
	}
	s.log.Info("device enrolled", "user_id", userID)
	writeJSON(w, http.StatusOK, struct{}{})
}

var errBadEnroll = errors.New("malformed enroll body")

// parseEnroll decodes an enroll body and returns the device it describes and
// its device_key, which must have signed the request.
func parseEnroll(body []byte) (enrollRequest, store.Device, *ecdsa.PublicKey, error) {
	var req enrollRequest
	if err := decodeStrict(body, &req); err != nil {
		return req, store.Device{}, nil, fmt.Errorf("%w: %v", errBadEnroll, err)
	}
	if req.ActivationCode == "" || req.FID == "" {
		return req, store.Device{}, nil, fmt.Errorf("%w: activation_code and fid are required", errBadEnroll)
	}
	deviceDER, deviceKey, err := parseP256(req.DeviceKey)
	if err != nil {
		return req, store.Device{}, nil, fmt.Errorf("%w: device_key: %v", errBadEnroll, err)
	}
	approvalDER, _, err := parseP256(req.ApprovalKey)
	if err != nil {
		return req, store.Device{}, nil, fmt.Errorf("%w: approval_key: %v", errBadEnroll, err)
	}
	if err := checkAttestation(req.Attestation); err != nil {
		return req, store.Device{}, nil, fmt.Errorf("%w: attestation: %v", errBadEnroll, err)
	}
	dev := store.Device{DeviceKey: deviceDER, ApprovalKey: approvalDER, Attestation: req.Attestation, FID: req.FID}
	return req, dev, deviceKey, nil
}

// parseP256 decodes a base64url SPKI P-256 public key.
func parseP256(s string) ([]byte, *ecdsa.PublicKey, error) {
	der, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, nil, err
	}
	key, err := p256FromDER(der)
	return der, key, err
}

func p256FromDER(der []byte) (*ecdsa.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	key, ok := pub.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("not a P-256 key")
	}
	return key, nil
}

// decodeStrict decodes a JSON value from body into v, rejecting unknown
// fields.
func decodeStrict(body []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// checkAttestation requires a chain of base64url certificates for each key.
// The certificates themselves are not verified.
func checkAttestation(raw json.RawMessage) error {
	var a struct {
		DeviceKey   []string `json:"device_key"`
		ApprovalKey []string `json:"approval_key"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		return err
	}
	for name, chain := range map[string][]string{"device_key": a.DeviceKey, "approval_key": a.ApprovalKey} {
		if len(chain) == 0 {
			return fmt.Errorf("no chain for %s", name)
		}
		for _, c := range chain {
			if _, err := base64.RawURLEncoding.Strict().DecodeString(c); err != nil || c == "" {
				return fmt.Errorf("%s chain entry is not base64url", name)
			}
		}
	}
	return nil
}

// deviceFail writes a device API error.
func deviceFail(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

func duoOK(w http.ResponseWriter, response any) {
	writeJSON(w, http.StatusOK, map[string]any{"stat": "OK", "response": response})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// duoFail writes an error in the shape duo_client parses.
func duoFail(w http.ResponseWriter, status, code int, message string) {
	writeJSON(w, status, map[string]any{"stat": "FAIL", "code": code, "message": message})
}
