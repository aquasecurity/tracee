package server

import (
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/server"
)

const (
	MetricsEndpointFlag = "metrics"
	HealthzEndpointFlag = "healthz"
	PProfEndpointFlag   = "pprof"
	ListenEndpointFlag  = "listen-addr"
	PyroscopeAgentFlag  = "pyroscope"
)

// TODO: this should be extract to be under 'pkg/cmd/flags' once we remove the binary tracee-rules.
// The reason why we have a specific pkg for it `pkg/cmd/flags/server` is because tracee rules uses
// this code, and doesn't compile libbpfgo and isn't dependant on libbpf go, if we import
// 'pkf/cmd/flags' directly libbpfgo becomes a dependency and we need to compile it with
// tracee-rules.

func PrepareServer(listenAddr string, metrics, healthz, pprof, pyro bool) (*server.Server, error) {
	if len(listenAddr) == 0 {
		return nil, errfmt.Errorf("listen address cannot be empty")
	}

	if metrics || healthz || pprof {
		httpServer := server.New(listenAddr)

		if metrics {
			httpServer.EnableMetricsEndpoint()
		}

		if healthz {
			httpServer.EnableHealthzEndpoint()
		}

		if pprof {
			httpServer.EnablePProfEndpoint()
		}
		if pyro {
			err := httpServer.EnablePyroAgent()
			if err != nil {
				return httpServer, err
			}
		}

		return httpServer, nil
	}

	return nil, nil
}
