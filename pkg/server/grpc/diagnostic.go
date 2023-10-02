package grpc

import (
	"context"
	"runtime"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/pkg/logger"
)

type DiagnosticService struct {
	pb.UnimplementedDiagnosticServiceServer
	tracee *tracee.Tracee
}

func (s *DiagnosticService) GetMetrics(ctx context.Context, in *pb.GetMetricsRequest) (*pb.GetMetricsResponse, error) {
	stats := s.tracee.Stats()
	metrics := &pb.GetMetricsResponse{
		EventCount:       stats.EventCount.Get(),
		EventsFiltered:   stats.EventsFiltered.Get(),
		NetCapCount:      stats.NetCapCount.Get(),
		BPFLogsCount:     stats.BPFLogsCount.Get(),
		ErrorCount:       stats.ErrorCount.Get(),
		LostEvCount:      stats.LostEvCount.Get(),
		LostWrCount:      stats.LostWrCount.Get(),
		LostNtCapCount:   stats.LostNtCapCount.Get(),
		LostBPFLogsCount: stats.LostBPFLogsCount.Get(),
	}

	return metrics, nil
}

func (s *DiagnosticService) ChangeLogLevel(ctx context.Context, in *pb.ChangeLogLevelRequest) (*pb.ChangeLogLevelResponse, error) {
	// default level
	level := logger.InfoLevel

	switch in.Level {
	case pb.LogLevel_Debug:
		level = logger.DebugLevel
	case pb.LogLevel_Warn:
		level = logger.WarnLevel
	case pb.LogLevel_Error:
		level = logger.ErrorLevel
	case pb.LogLevel_DPanic:
		level = logger.DPanicLevel
	case pb.LogLevel_Panic:
		level = logger.PanicLevel
	case pb.LogLevel_Fatal:
		level = logger.FatalLevel
	}

	logger.SetLevel(level)

	return &pb.ChangeLogLevelResponse{}, nil
}

func (s *DiagnosticService) GetStacktrace(ctx context.Context, in *pb.GetStacktraceRequest) (*pb.GetStacktraceResponse, error) {
	return &pb.GetStacktraceResponse{
		Stacktrace: stack(),
	}, nil
}

// This func is based on runtime.Stack(),
// but instead if pass true to runtime.Stack in order to include all goroutines.
func stack() []byte {
	buf := make([]byte, 1024)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return buf[:n]
		}
		buf = make([]byte, 2*len(buf))
	}
}
