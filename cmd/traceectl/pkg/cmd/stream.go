package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/client"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd/printer"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/config"
)

type Stream struct {
	Config  config.Config
	Server  *client.Server
	Printer printer.EventPrinter
}

func (s Stream) Run(policies []string) error {
	// create context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := s.Server.Connect(); err != nil {
		return fmt.Errorf("error running stream: %s", err)
	}
	defer s.Server.Close()

	// Create signal chanel
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	errChan := make(chan error)
	stopChan := make(chan struct{}) // Channel to trigger stop routine

	go func() {
		stream, err := s.Server.StreamEvents(ctx, &pb.StreamEventsRequest{Policies: policies})
		if err != nil {
			errChan <- fmt.Errorf("error calling Stream: %s", err)
			return
		}
		s.Printer.Preamble()
		for {
			select {
			case <-ctx.Done():
				return
			default:
				res, err := stream.Recv()
				if err == io.EOF {
					// Trigger stop routine via stopChan
					// We should probably improve the UX here,
					// or enable reconnection to a new stream
					// but for now we just close the channel
					// and return
					close(stopChan)
					return
				}
				if err != nil {
					errChan <- fmt.Errorf("error receiving streamed event: %s", err.Error())
					return
				}
				s.Printer.Print(res.Event)
			}
		}
	}()

	for {
		select {
		// Receive stop signal
		case <-sigs:
			return s.stopRoutine(ctx)

		// Handle stop routine triggered by EOF
		case <-stopChan:
			return s.stopRoutine(ctx)

		case err := <-errChan:
			return err
		}
	}
}

func (s Stream) stopRoutine(ctx context.Context) error {
	metrics, err := s.Server.GetMetrics(ctx, &pb.GetMetricsRequest{})
	if err != nil {
		if status.Code(err) == codes.Unavailable {
			// this is the likley case when the stream ends because the server closed
			// we need to add logging capabilities to traceectl to log this
			err = nil
		} else {
			err = fmt.Errorf("error getting metrics: %s", err)
		}
	} else {
		s.Printer.Epilogue(metrics)
	}
	s.Printer.Close()
	return err
}
