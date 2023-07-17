package grpc

import (
	"context"
	"net"

	"google.golang.org/grpc"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
	pb "github.com/aquasecurity/tracee/types/api/v1beta1"
)

type Server struct {
	pb.UnimplementedTraceeServer
	listener   net.Listener
	protocol   string
	listenAddr string
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

func (s *Server) Start(ctx context.Context) {
	srvCtx, srvCancel := context.WithCancel(ctx)
	defer srvCancel()

	// TODO: allow grpc keep alive configuration from CLI/Configfile
	grpcServer := grpc.NewServer()
	pb.RegisterTraceeServer(grpcServer, s)

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
		grpcServer.GracefulStop()
	// if server error occurred while base ctx is not done, we should exit via this case
	case <-srvCtx.Done():
	}
}

func (s *Server) ListEventDefinitions(ctx context.Context, in *pb.ListEventDefinitionRequest) (*pb.ListEventDefinitionResponse, error) {
	eventDefinitions := make([]*pb.EventDefinition, 0)

	for _, evtDefinition := range events.Core.GetDefinitions() {
		if evtDefinition.IsInternal() {
			continue
		}

		args := make([]string, 0, len(evtDefinition.GetParams()))
		for _, p := range evtDefinition.GetParams() {
			args = append(args, p.Name)
		}

		def := &pb.EventDefinition{Name: evtDefinition.GetName(), Sets: evtDefinition.GetSets(), Arguments: args}

		eventDefinitions = append(eventDefinitions, def)
	}

	return &pb.ListEventDefinitionResponse{Events: eventDefinitions}, nil
}
