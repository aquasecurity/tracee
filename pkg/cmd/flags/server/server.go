package server

import (
	"fmt"
	"os"
	"strings"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/server/grpc"
	"github.com/aquasecurity/tracee/pkg/server/http"
)

const (
	HTTPServer                 = "http"
	GRPCServer                 = "grpc"
	MetricsEndpointFlag        = "metrics"
	HealthzEndpointFlag        = "healthz"
	PProfEndpointFlag          = "pprof"
	ListenEndpointFlag         = "address"
	PyroscopeAgentEndpointFlag = "pyroscope"
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
	var server Server
	var (
		enableMetrics   = false
		enableHealthz   = false
		enablePProf     = false
		enablePyroscope = false
	)
	for _, endpoint := range serverSlice {
		// split flag http.address or grpc.address for example
		serverParts := strings.SplitN(endpoint, ".", 2)
		if len(serverParts) < 2 {
			return nil, fmt.Errorf("cannot process http or grpc alone")
		}
		switch serverParts[0] {
		//flag http.Xxx
		case HTTPServer:
			httpParts := strings.SplitN(serverParts[1], "=", 2)
			switch httpParts[0] {
			case ListenEndpointFlag:
				server.HTTPServer = http.New(httpParts[1])
			case MetricsEndpointFlag:
				if strings.Compare(httpParts[1], "true") == 0 {
					enableMetrics = true
				}
			case HealthzEndpointFlag:
				if strings.Compare(httpParts[1], "true") == 0 {
					enableHealthz = true
				}
			case PProfEndpointFlag:
				if strings.Compare(httpParts[1], "true") == 0 {
					enablePProf = true
				}
			case PyroscopeAgentEndpointFlag:
				if strings.Compare(httpParts[1], "true") == 0 {
					enablePyroscope = true
				}
			}
		//flag grpc.Xxx
		case GRPCServer:
			grpcParts := strings.SplitN(serverParts[1], "=", 1)
			switch grpcParts[0] {
			case ListenEndpointFlag:
				addressParts := strings.SplitN(grpcParts[1], ":", 2)
				switch addressParts[0] {
				case "unix":
					if len(addressParts) == 1 {
						addressParts = append(addressParts, "/var/run/tracee.sock")
					}
					if _, err = os.Stat(addressParts[1]); err == nil {
						err = os.Remove(addressParts[1])
						if err != nil {
							return nil, errfmt.Errorf("failed to cleanup gRPC listening address (%s): %v", addressParts[1], err)
						}
					}
				case "tcp":
					if len(addressParts) == 1 {
						addressParts = append(addressParts, "4466")
					}
				default:
					return nil, errfmt.Errorf("grpc supported protocols are tcp or unix. eg: tcp:4466, unix:/tmp/tracee.sock")
				}
				server.GRPCServer, err = grpc.New(addressParts[0], addressParts[1])
				if err != nil {
					return nil, err
				}

			default:
				if _, err = os.Stat("/var/run/tracee.sock"); err == nil {
					err = os.Remove("/var/run/tracee.sock")
					if err != nil {
						return nil, errfmt.Errorf("failed to cleanup gRPC listening address (%s): %v", "/var/run/tracee.sock", err)
					}
				}
				server.GRPCServer, err = grpc.New("unix", "/var/run/tracee.sock")
				if err != nil {
					return nil, err
				}
			}
		}
	}

	if enableMetrics || enableHealthz || enablePProf || enablePyroscope {
		if server.HTTPServer == nil {
			server.HTTPServer = http.New("")
		}
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

	return &server, nil
}
