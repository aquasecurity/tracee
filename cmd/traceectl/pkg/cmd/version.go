package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/client"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/config"
)

type Version struct {
	Config  config.Config
	Server  *client.Server
	Printer *cobra.Command
}

func (v Version) Run() error {
	if err := v.Server.Connect(); err != nil {
		return fmt.Errorf("error running version: %s", err)
	}
	defer v.Server.Close()

	response, err := v.Server.GetVersion(context.Background(), &pb.GetVersionRequest{})
	if err != nil {
		return fmt.Errorf("error getting version: %s", err)
	}
	v.Printer.Printf("Version: %s\n", response.Version)
	return nil
}
