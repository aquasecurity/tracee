package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/client"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd/printer"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/config"
)

type Stream struct {
	Config   config.Config
	Server   *client.Server
	Printer  printer.EventPrinter
	Policies []string
}

func (s Stream) Run() error {
	// create context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := s.Server.Connect(); err != nil {
		return fmt.Errorf("error running stream: %s", err)
	}
	defer s.Server.Close()
	// create signal chanel
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	errChan := make(chan error)

	go func() {
		stream, err := s.Server.StreamEvents(ctx, &pb.StreamEventsRequest{Policies: s.Policies})
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
			// stop streaming
			metrics, err := s.Server.GetMetrics(ctx, &pb.GetMetricsRequest{})
			if err != nil {
				return fmt.Errorf("error getting metrics: %s", err)
			}
			s.Printer.Epilogue(metrics)
			s.Printer.Close()
			cancel()
			return nil

		case err := <-errChan:
			// return error
			cancel()
			return err
		}
	}
}
