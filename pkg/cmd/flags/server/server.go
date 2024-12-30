package server

import (
	"os"
	"strings"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/server/grpc"
	"github.com/aquasecurity/tracee/pkg/server/http"
)

const (
	HTTPServer          = "http"
	GRPCServer          = "grpc"
	MetricsEndpointFlag = "metrics"
	HealthzEndpointFlag = "healthz"
	PProfEndpointFlag   = "pprof"
	ListenEndpointFlag  = "address"
	PyroscopeAgentFlag  = "pyroscope"
)

// TODO: this should be extract to be under 'pkg/cmd/flags' once we remove the binary tracee-rules.
// The reason why we have a specific pkg for it `pkg/cmd/flags/server` is because tracee rules uses
// this code, and doesn't compile libbpfgo and isn't dependant on libbpf go, if we import
// 'pkf/cmd/flags' directly libbpfgo becomes a dependency and we need to compile it with
// tracee-rules.

type Server struct {
	HTTPServer *http.Server
	GRPCServer *grpc.Server
}

func PrepareServer(serverSlice []string) (*Server, error) {
	var err error
	var server *Server
	var (
		enableMetrics   = false
		enableHealthz   = false
		enablePProf     = false
		enablePyroscope = false
	)
	grpcAddr := ""
	for _, endpoint := range serverSlice {
		if strings.Contains(endpoint, HTTPServer) {
			if strings.Contains(endpoint, MetricsEndpointFlag) {
				if strings.Contains(endpoint, "true") {
					enableMetrics = true
				}
			} else if strings.Contains(endpoint, HealthzEndpointFlag) {
				if strings.Contains(endpoint, "true") {
					enableHealthz = true
				}
			} else if strings.Contains(endpoint, PProfEndpointFlag) {
				if strings.Contains(endpoint, "true") {
					enablePProf = true
				}
			} else if strings.Contains(endpoint, PyroscopeAgentFlag) {
				if strings.Contains(endpoint, "true") {
					enablePyroscope = true
				}
			} else if strings.Contains(endpoint, ListenEndpointFlag) {
				server.HTTPServer = http.New(endpoint[len(HTTPServer)+1+len(ListenEndpointFlag):])
			} else {
				server.HTTPServer = http.New("")
			}
		} else if strings.Contains(endpoint, GRPCServer) {
			if strings.Contains(endpoint, ListenEndpointFlag) {
				grpcAddr = endpoint[len(GRPCServer)+1+len(ListenEndpointFlag):]

				addrParts := strings.SplitN(grpcAddr, ":", 2)
				protocol := addrParts[0]

				if protocol != "tcp" && protocol != "unix" {
					return nil, errfmt.Errorf("grpc supported protocols are tcp or unix. eg: tcp:4466, unix:/tmp/tracee.sock")
				}

				if len(addrParts) == 1 {
					if protocol == "tcp" {
						grpcAddr += ":4466"
					} else { // protocol == "unix"
						grpcAddr += ":/var/run/tracee.sock"
					}
				}
				// cleanup listen address if needed (unix socket), for example if a panic happened
				if protocol == "unix" {
					path := strings.SplitN(grpcAddr, ":", 2)[1]
					if _, err = os.Stat(path); err == nil {
						err = os.Remove(path)
						if err != nil {
							return nil, errfmt.Errorf("failed to cleanup gRPC listening address (%s): %v", path, err)
						}
					}
				}
				server.GRPCServer, err = grpc.New("dsa", "dsa") //protocol, grpcAddr)

			}
		}
	}
	if server.HTTPServer != nil {
		if enableMetrics {
			server.HTTPServer.EnableMetricsEndpoint()
		}
		if enableHealthz {
			server.HTTPServer.EnableHealthzEndpoint()
		}
		if enablePProf {
			server.HTTPServer.EnablePProfEndpoint()
		}
		if enablePyroscope {
			err = server.HTTPServer.EnablePyroAgent()
			if err != nil {
				return nil, err
			}
		}
	}

	return server, nil
}
