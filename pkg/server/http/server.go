package http

import (
	"context"
	"fmt"
	"net/http"
	"net/http/pprof"

	"github.com/grafana/pyroscope-go"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/aquasecurity/tracee/pkg/logger"
)

// Server represents a http server
type Server struct {
	hs             *http.Server
	mux            *http.ServeMux // just an exposed copy of hs.Handler
	metricsEnabled bool
	pyroProfiler   *pyroscope.Profiler
}

// New creates a new server
func New(listenAddr string) *Server {
	mux := http.NewServeMux()

	return &Server{
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

// EnableHealthzEndpoint enables healthz endpoint
func (s *Server) EnableHealthzEndpoint() {
	s.mux.HandleFunc("/healthz", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "OK")
	})
}

// Start starts the http server on the listen address
func (s *Server) Start(ctx context.Context) {
	srvCtx, srvCancel := context.WithCancel(ctx)
	defer srvCancel()

	go func() {
		logger.Debugw("Starting serving metrics endpoint goroutine", "address", s.hs.Addr)
		defer logger.Debugw("Stopped serving metrics endpoint goroutine")

		if err := s.hs.ListenAndServe(); err != http.ErrServerClosed {
			logger.Errorw("Serving metrics endpoint", "error", err)
		}

		srvCancel()
	}()

	select {
	case <-ctx.Done():
		logger.Debugw("Context cancelled, shutting down metrics endpoint server")
		if err := s.hs.Shutdown(ctx); err != nil {
			logger.Errorw("Stopping serving metrics endpoint", "error", err)
		}

	// if server error occurred while base ctx is not done, we should exit via this case
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

	return err
}

// MetricsEndpointEnabled returns true if metrics endpoint is enabled
func (s *Server) MetricsEndpointEnabled() bool {
	return s.metricsEnabled
}
