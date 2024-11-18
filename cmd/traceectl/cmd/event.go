package cmd

//TODO:
import (
	"context"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/client"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd/formatter"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd/printer"
	"github.com/spf13/cobra"
)

var eventFormatFlag string
var eventOutputFlag string

// main command
var eventCmd = &cobra.Command{
	Use:   "event [command]",
	Short: "event management for tracee",
	Long: `Event Management for tracee 
	let you enable and disable events in tracee.
	get descriptions of events and run them.
	`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// Check if args are provided
		if len(args) == 0 {
			cmd.PrintErrln("Error: no event names provided. Please specify at least one event to enable.")
			return // Exit if no arguments
		}
	},
}

func init() {
	eventCmd.AddCommand(listEventCmd)
	eventCmd.AddCommand(describeEventCmd)
	eventCmd.AddCommand(enableEventCmd)
	eventCmd.AddCommand(disableEventCmd)
	eventCmd.AddCommand(runEventCmd)

	runEventCmd.PersistentFlags().StringVar(&runCmdArgs, "args", "", "Arguments for the event")

	listEventCmd.Flags().StringVarP(&eventFormatFlag, "format", "f", formatter.FormatTable, "Output format (json|table|template) ")
	listEventCmd.Flags().StringVarP(&eventOutputFlag, "output", "o", "stdout", "Output destination ")

	describeEventCmd.Flags().StringVarP(&eventFormatFlag, "format", "f", formatter.FormatTable, "Output format (json|table|template) ")
	describeEventCmd.Flags().StringVarP(&eventOutputFlag, "output", "o", "stdout", "Output destination ")
}

// Sub commands
// list
var listEventCmd = &cobra.Command{
	Use:   "list",
	Short: "list events",
	Long:  `Lists all available event definitions (built-in and plugin-defined), providing a brief summary of each.`,
	Args:  cobra.MaximumNArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		listEvents(cmd, args)
	},
}

// describe
var describeEventCmd = &cobra.Command{
	Use:   "describe <event_name>",
	Short: "describe event",
	Long:  `Retrieves the detailed definition of a specific event, including its fields, types, and other metadata.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		getEventDescriptions(cmd, args)
	},
}

// enable
var enableEventCmd = &cobra.Command{
	Use:   "enable <event_name>",
	Short: "enable event",
	Long:  `Enables capturing of a specific event type.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		enableEvents(cmd, args[0])
	},
}

// disable
var disableEventCmd = &cobra.Command{
	Use:   "disable <event_name>",
	Short: "disable event",
	Long:  `Disables capturing of a specific event type.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		disableEvents(cmd, args[0])
	},
}

// run
var runCmdArgs string
var runEventCmd = &cobra.Command{
	Use:   "run <event_name> [--args <arguments>]",
	Short: "run event",
	Long:  `Manually triggers a user-space event.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		//runEvents(cmd, args)
	},
}

func listEvents(cmd *cobra.Command, args []string) {
	//create service client
	var traceeClient client.ServiceClient
	if err := traceeClient.NewServiceClient(serverInfo); err != nil {
		cmd.PrintErrln("Error creating client: ", err)
		return
	}
	defer traceeClient.CloseConnection()
	response, err := traceeClient.GetEventDefinitions(context.Background(), &pb.GetEventDefinitionsRequest{EventNames: args})

	if err != nil {
		cmd.PrintErrln("Error getting event definitions: ", err)
		return

	}
	//display event definitions
	//TODO:  add support for different outputs and formats
	format, err := formatter.New(eventFormatFlag, eventOutputFlag, cmd)
	if err != nil {
		cmd.PrintErrln("Error creating formatter: ", err)
		return
	}
	//show events
	printer.ListEvents(format, args, response)
}
func getEventDescriptions(cmd *cobra.Command, args []string) {
	//create service client
	var traceeClient client.ServiceClient
	if err := traceeClient.NewServiceClient(serverInfo); err != nil {
		cmd.PrintErrln("Error creating client: ", err)
		return
	}
	defer traceeClient.CloseConnection()
	response, err := traceeClient.GetEventDefinitions(context.Background(), &pb.GetEventDefinitionsRequest{EventNames: args})

	if err != nil {
		cmd.PrintErrln("Error getting event definitions: ", err)
		return

	}
	//display event definitions
	//TODO:  add support for different outputs and formats
	format, err := formatter.New(eventFormatFlag, eventOutputFlag, cmd)
	if err != nil {
		cmd.PrintErrln("Error creating formatter: ", err)
		return
	}
	//show events
	printer.DescribeEvent(format, args, response)

}
func enableEvents(cmd *cobra.Command, eventName string) {
	// Create Tracee gRPC client
	var traceeClient client.ServiceClient // tracee client

	if err := traceeClient.NewServiceClient(serverInfo); err != nil {
		cmd.PrintErrln("Error creating client: ", err)
		return // Exit on error
	}

	// Iterate over event names and enable each one

	_, err := traceeClient.EnableEvent(context.Background(), &pb.EnableEventRequest{Name: eventName})
	if err != nil {
		cmd.PrintErrln("Error enabling event:", err)
		return
	}
	cmd.Printf("Enabled event: %s\n", eventName)
}

func disableEvents(cmd *cobra.Command, eventName string) {
	// Create Tracee gRPC client
	var traceeClient client.ServiceClient
	if err := traceeClient.NewServiceClient(serverInfo); err != nil {
		cmd.PrintErrln("Error creating client: ", err)
		return // Exit on error
	}
	_, err := traceeClient.DisableEvent(context.Background(), &pb.DisableEventRequest{Name: eventName})
	if err != nil {
		cmd.PrintErrln("Error disabling event:", err)
		return
	}
	cmd.Printf("Disabled event: %s\n", eventName)

}
