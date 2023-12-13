package grpc

import (
	"context"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/signatures/engine"
)

type Server struct {
	listener   net.Listener
	protocol   string
	listenAddr string
	server     *grpc.Server
}

func New(protocol, listenAddr string) (*Server, error) {
	if protocol == "tcp" {
		listenAddr = ":" + listenAddr
	}

	lis, err := net.Listen(protocol, listenAddr)
	if err != nil {
		return nil, err
	}

	return &Server{listener: lis, protocol: protocol, listenAddr: listenAddr}, nil
}

func (s *Server) Start(ctx context.Context, t *tracee.Tracee, e *engine.Engine) {
	srvCtx, srvCancel := context.WithCancel(ctx)
	defer srvCancel()

	// TODO: allow grpc keep alive configuration from CLI/Configfile
	keepaliveParams := keepalive.ServerParameters{
		Time:    5 * time.Second, // Ping the client if it is idle for 5 seconds to ensure the connection is still active
		Timeout: 1 * time.Second, // Wait 1 second for the ping ack before assuming the connection is dead
	}

	grpcServer := grpc.NewServer(grpc.KeepaliveParams(keepaliveParams))
	s.server = grpcServer
	pb.RegisterTraceeServiceServer(grpcServer, &TraceeService{tracee: t})
	pb.RegisterDiagnosticServiceServer(grpcServer, &DiagnosticService{tracee: t})
	pb.RegisterDataSourceServiceServer(grpcServer, &DataSourceService{sigEngine: e})

	go func() {
		logger.Debugw("Starting grpc server", "protocol", s.protocol, "address", s.listenAddr)
		if err := grpcServer.Serve(s.listener); err != nil {
			logger.Errorw("GRPC server", "error", err)
		}
		srvCancel()
	}()

	select {
	case <-ctx.Done():
		logger.Debugw("Context cancelled, shutting down grpc server")
		s.cleanup()
	// if server error occurred while base ctx is not done, we should exit via this case
	case <-srvCtx.Done():
		s.cleanup()
	}
}

func (s *Server) cleanup() {
	s.server.GracefulStop()
}
