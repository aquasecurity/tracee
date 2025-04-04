package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/client"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd/printer"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/config"
)

type Metrics struct {
	Config  config.Config
	Server  *client.Server
	Printer *cobra.Command
}

func (m Metrics) Run() error {
	if err := m.Server.Connect(); err != nil {
		return fmt.Errorf("error running metrics: %s", err)
	}
	defer m.Server.Close()

	response, err := m.Server.GetMetrics(context.Background(), &pb.GetMetricsRequest{})
	if err != nil {
		return fmt.Errorf("error getting metrics: %s", err)
	}

	metricsJson, err := printer.MarshalJSON(response)
	if err != nil {
		panic(err)
	}
	m.Printer.Printf("%s\n", metricsJson)
	return nil
}
