// Package duostub serves the subset of Duo's Auth API that Authentik's Duo
// stages call (enroll, enroll_status, auth). It approves every push except
// those for user IDs it was told to deny.
package duostub

import (
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/frict-auth/frict-server/internal/duosig"
)

const maxBodyBytes = 64 << 10

type Server struct {
	verifier  duosig.Verifier
	authDelay time.Duration
	deny      map[string]bool // user_id -> push is denied
	log       *slog.Logger

	mu          sync.Mutex
	enrollments map[string]string // user_id -> activation_code
}

// New returns a stub whose /auth blocks for authDelay, then denies pushes for
// denyUserIDs and approves all others.
func New(v duosig.Verifier, authDelay time.Duration, denyUserIDs []string, log *slog.Logger) *Server {
	deny := map[string]bool{}
	for _, id := range denyUserIDs {
		deny[id] = true
	}
	return &Server{verifier: v, authDelay: authDelay, deny: deny, log: log, enrollments: map[string]string{}}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/v2/enroll", s.signed(s.enroll))
	mux.HandleFunc("POST /auth/v2/enroll_status", s.signed(s.enrollStatus))
	mux.HandleFunc("POST /auth/v2/auth", s.signed(s.auth))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.log.Info("unhandled", "method", r.Method, "path", r.URL.Path)
		fail(w, http.StatusNotFound, 40401, "Resource not found")
	})
	return mux
}

type signedHandler func(w http.ResponseWriter, r *http.Request, params map[string]string)

// signed rejects any request whose sig v5 signature does not verify, then
// passes the JSON body's string parameters to next.
func (s *Server) signed(next signedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
		if err != nil {
			fail(w, http.StatusBadRequest, 40002, "Invalid request body")
			return
		}
		if err := s.verifier.Verify(r, body); err != nil {
			s.log.Warn("signature rejected", "path", r.URL.Path, "reason", err.Error())
			fail(w, http.StatusUnauthorized, 40103, "Invalid signature in request credentials")
			return
		}
		params := map[string]string{}
		if err := json.Unmarshal(body, &params); err != nil {
			fail(w, http.StatusBadRequest, 40002, "Invalid request parameters")
			return
		}
		s.log.Info("signature ok", "path", r.URL.Path)
		next(w, r, params)
	}
}

func (s *Server) enroll(w http.ResponseWriter, _ *http.Request, p map[string]string) {
	userID := "DU" + rand.Text()
	code := rand.Text()
	s.mu.Lock()
	s.enrollments[userID] = code
	s.mu.Unlock()
	s.log.Info("enrolled", "user_id", userID)
	ok(w, map[string]any{
		"activation_barcode": "https://" + s.verifier.Host + "/frict/enroll/" + code + ".png",
		"activation_code":    "frict://enroll/" + code,
		"user_id":            userID,
		"username":           p["username"],
		"valid_secs":         86400,
	})
}

func (s *Server) enrollStatus(w http.ResponseWriter, _ *http.Request, p map[string]string) {
	s.mu.Lock()
	code, known := s.enrollments[p["user_id"]]
	s.mu.Unlock()
	status := "invalid"
	if known && code != "" && "frict://enroll/"+code == p["activation_code"] {
		status = "success"
	}
	s.log.Info("enroll_status", "user_id", p["user_id"], "status", status)
	ok(w, status)
}

func (s *Server) auth(w http.ResponseWriter, r *http.Request, p map[string]string) {
	if p["async"] == "1" {
		fail(w, http.StatusBadRequest, 40002, "async auth not supported")
		return
	}
	start := time.Now()
	s.log.Info("auth blocking", "user_id", p["user_id"], "delay", s.authDelay.String())
	select {
	case <-time.After(s.authDelay):
	case <-r.Context().Done():
		s.log.Warn("auth caller gave up", "user_id", p["user_id"], "after", time.Since(start).String())
		return
	}
	if s.deny[p["user_id"]] {
		s.log.Info("auth denied", "user_id", p["user_id"], "after", time.Since(start).String())
		ok(w, map[string]string{
			"result":     "deny",
			"status":     "deny",
			"status_msg": "Login request denied.",
		})
		return
	}
	s.log.Info("auth approved", "user_id", p["user_id"], "after", time.Since(start).String())
	ok(w, map[string]string{
		"result":     "allow",
		"status":     "allow",
		"status_msg": "Success. Logging you in...",
	})
}

func ok(w http.ResponseWriter, response any) {
	writeJSON(w, http.StatusOK, map[string]any{"stat": "OK", "response": response})
}

func fail(w http.ResponseWriter, status, code int, message string) {
	writeJSON(w, status, map[string]any{"stat": "FAIL", "code": code, "message": message})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Warn("writing response", "err", err)
	}
}
