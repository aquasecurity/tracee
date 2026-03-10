package http

import (
	"context"
	"fmt"
	"net/http"
	"net/http/pprof"
	"time"

	"github.com/grafana/pyroscope-go"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/aquasecurity/tracee/common/logger"
)

// Server represents a http server
type Server struct {
	hs               *http.Server
	mux              *http.ServeMux // just an exposed copy of hs.Handler
	pyroProfiler     *pyroscope.Profiler
	address          string
	metricsEnabled   bool
	healthzEnabled   bool
	pprofEnabled     bool
	pyroscopeEnabled bool
}

// New creates a new server
func New(listenAddr string) *Server {
	mux := http.NewServeMux()

	return &Server{
		address: listenAddr,
		hs: &http.Server{
			Addr:    listenAddr,
			Handler: mux,
		},
		mux: mux,
	}
}

// EnableMetricsEndpoint enables metrics endpoint
func (s *Server) EnableMetricsEndpoint() {
	s.mux.Handle("/metrics", promhttp.Handler())
	s.metricsEnabled = true
}

// SetHealthzEnabled marks healthz as enabled (handler registered later with EnableHealthzEndpoint)
func (s *Server) SetHealthzEnabled() {
	s.healthzEnabled = true
}

// EnableHealthzEndpoint registers the /healthz handler. The isHealthy function
// is called on each request; the caller is responsible for composing all checks
// (e.g., Tracee readiness + heartbeat liveness) into a single predicate.
func (s *Server) EnableHealthzEndpoint(isHealthy func() bool) {
	s.mux.HandleFunc("/healthz", func(w http.ResponseWriter, req *http.Request) {
		if isHealthy != nil && isHealthy() {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "OK")
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(w, "NOT OK")
	})
	s.healthzEnabled = true
}

// Start starts the http server on the listen address.
// It initializes heartbeat monitoring and blocks until context is cancelled.
func (s *Server) Start(ctx context.Context) {
	srvCtx, srvCancel := context.WithCancel(ctx)
	defer srvCancel()

	go func() {
		logger.Debugw("Starting HTTP server", "address", s.hs.Addr)
		defer logger.Debugw("HTTP server stopped")

		if err := s.hs.ListenAndServe(); err != http.ErrServerClosed {
			logger.Errorw("HTTP server error", "error", err)
		}

		srvCancel()
	}()

	select {
	case <-ctx.Done():
		logger.Debugw("Context cancelled, shutting down HTTP server")
		// Use a fresh context for shutdown since the original is cancelled
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.hs.Shutdown(shutdownCtx); err != nil {
			logger.Errorw("Error shutting down HTTP server", "error", err)
		}

	// If server error occurred while base ctx is not done, exit via this case
	case <-srvCtx.Done():
	}
}

// EnablePProfEndpoint enables pprof endpoint for debugging
func (s *Server) EnablePProfEndpoint() {
	s.mux.HandleFunc("/debug/pprof/", pprof.Index)
	s.mux.Handle("/debug/pprof/allocs", pprof.Handler("allocs"))
	s.mux.Handle("/debug/pprof/block", pprof.Handler("block"))
	s.mux.Handle("/debug/pprof/heap", pprof.Handler("heap"))
	s.mux.Handle("/debug/pprof/mutex", pprof.Handler("mutex"))
	s.mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	s.mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	s.mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	s.mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	s.pprofEnabled = true
}

// EnablePyroAgent enables pyroscope agent in golang push mode
// TODO: make this configurable
func (s *Server) EnablePyroAgent() error {
	p, err := pyroscope.Start(
		pyroscope.Config{
			ApplicationName: "tracee",
			ServerAddress:   "http://localhost:4040",
		},
	)
	s.pyroProfiler = p
	if err != nil {
		return err
	}

	s.pyroscopeEnabled = true

	return nil
}

// IsMetricsEnabled returns true if metrics endpoint is enabled
func (s *Server) IsMetricsEnabled() bool {
	if s == nil {
		return false
	}

	return s.metricsEnabled
}

// IsHealthzEnabled returns true if healthz endpoint is enabled
func (s *Server) IsHealthzEnabled() bool {
	return s.healthzEnabled
}

// IsPProfEnabled returns true if pprof endpoint is enabled
func (s *Server) IsPProfEnabled() bool {
	return s.pprofEnabled
}

// IsPyroscopeEnabled returns true if pyroscope agent is enabled
func (s *Server) IsPyroscopeEnabled() bool {
	return s.pyroscopeEnabled
}

// Address returns the address of the server
func (s *Server) Address() string {
	return s.address
}
