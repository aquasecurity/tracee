package server

import (
	"fmt"
	"net/http"
	"net/http/pprof"
	"os"

	"github.com/aquasecurity/tracee/pkg/logger"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/urfave/cli/v2"
)

const (
	MetricsEndpointFlag = "metrics"
	HealthzEndpointFlag = "healthz"
	PProfEndpointFlag   = "pprof"
	ListenEndpointFlag  = "listen-addr"
)

// Server represents a http server
type Server struct {
	mux        *http.ServeMux
	listenAddr string
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
}

// EnableHealthzEndpoint enables healthz endpoint
func (s *Server) EnableHealthzEndpoint() {
	s.mux.HandleFunc("/healthz", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "OK")
	})
}

// Start starts the http server on the listen addr
func (s *Server) Start() {
	logger.Debug(fmt.Sprintf("Serving metrics endpoint at %s\n", s.listenAddr))

	if err := http.ListenAndServe(s.listenAddr, s.mux); err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "Error serving metrics endpoint: %v\n", err)
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

func ShouldStart(c *cli.Context) bool {
	return c.Bool(MetricsEndpointFlag) || c.Bool(HealthzEndpointFlag) || c.Bool(PProfEndpointFlag)
}
