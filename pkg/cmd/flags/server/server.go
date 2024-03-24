package server

import (
	"fmt"

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
			logger.Infow(fmt.Sprintf("Enabling metrics endpoint at %s/metrics", listenAddr))
			httpServer.EnableMetricsEndpoint()
		}

		if healthz {
			logger.Infow(fmt.Sprintf("Enabling healthz endpoint at %s/healthz", listenAddr))
			httpServer.EnableHealthzEndpoint()
		}

		if pprof {
			logger.Infow(fmt.Sprintf("Enabling pprof endpoint at %s/debug/pprof", listenAddr))
			httpServer.EnablePProfEndpoint()
		}
		if pyro {
			logger.Infow("Enabling pyroscope agent")
			err := httpServer.EnablePyroAgent()
			if err != nil {
				return httpServer, err
			}
		}

		return httpServer, nil
	}

	return nil, nil
}
