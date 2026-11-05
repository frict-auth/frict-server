// Package server routes Frict's HTTP API: Duo's Auth API for Authentik on
// /auth/v2/*, and /healthz.
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/frict-auth/frict-server/internal/duosig"
)

const maxBodyBytes = 64 << 10

// Pinger reports whether the store can serve requests.
type Pinger interface {
	Ping(ctx context.Context) error
}

type Server struct {
	verifier duosig.Verifier
	store    Pinger
	log      *slog.Logger
}

func New(v duosig.Verifier, store Pinger, log *slog.Logger) *Server {
	return &Server{verifier: v, store: store, log: log}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.Handle("POST /auth/v2/enroll", s.duoSigned(notImplemented))
	mux.Handle("POST /auth/v2/enroll_status", s.duoSigned(notImplemented))
	mux.Handle("POST /auth/v2/auth", s.duoSigned(notImplemented))
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

func notImplemented(w http.ResponseWriter, r *http.Request) {
	duoFail(w, http.StatusNotImplemented, 50100, r.URL.Path+" is not implemented yet")
}

// duoFail writes an error in the shape duo_client parses.
func duoFail(w http.ResponseWriter, status, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"stat": "FAIL", "code": code, "message": message})
}
