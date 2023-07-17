package server

import (
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/server/http"
)

const (
	MetricsEndpointFlag    = "metrics"
	HealthzEndpointFlag    = "healthz"
	PProfEndpointFlag      = "pprof"
	HTTPListenEndpointFlag = "http-listen-addr"
	GRPCListenEndpointFlag = "grpc-listen-addr"
	PyroscopeAgentFlag     = "pyroscope"
)

// TODO: this should be extract to be under 'pkg/cmd/flags' once we remove the binary tracee-rules.
// The reason why we have a specific pkg for it `pkg/cmd/flags/server` is because tracee rules uses
// this code, and doesn't compile libbpfgo and isn't dependant on libbpf go, if we import
// 'pkf/cmd/flags' directly libbpfgo becomes a dependency and we need to compile it with
// tracee-rules.

func PrepareHTTPServer(listenAddr string, metrics, healthz, pprof, pyro bool) (*http.Server, error) {
	if len(listenAddr) == 0 {
		return nil, errfmt.Errorf("http listen address cannot be empty")
	}

	if metrics || healthz || pprof {
		httpServer := http.New(listenAddr)

		if metrics {
			logger.Debugw("Enabling metrics endpoint")
			httpServer.EnableMetricsEndpoint()
		}

		if healthz {
			logger.Debugw("Enabling healthz endpoint")
			httpServer.EnableHealthzEndpoint()
		}

		if pprof {
			logger.Debugw("Enabling pprof endpoint")
			httpServer.EnablePProfEndpoint()
		}
		if pyro {
			logger.Debugw("Enabling pyroscope agent")
			err := httpServer.EnablePyroAgent()
			if err != nil {
				return httpServer, err
			}
		}

		return httpServer, nil
	}

	return nil, nil
}
