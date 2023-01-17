package server

import (
	"fmt"
	"net/http"
	"net/http/pprof"

	"github.com/aquasecurity/tracee/logger"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Server represents a http server
type Server struct {
	mux            *http.ServeMux
	listenAddr     string
	metricsEnabled bool
}

// New creates a new server
func New(listenAddr string) *Server {
	return &Server{
		mux:        http.NewServeMux(),
		listenAddr: listenAddr,
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

// Start starts the http server on the listen addr
func (s *Server) Start() {
	logger.Debug("serving metrics endpoint", "address", s.listenAddr)

	if err := http.ListenAndServe(s.listenAddr, s.mux); err != http.ErrServerClosed {
		logger.Error("serving metrics endpoint", "error", err)
	}
}

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

func (s *Server) MetricsEndpointEnabled() bool {
	return s.metricsEnabled
}
