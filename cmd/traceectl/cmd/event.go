package cmd

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/client"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd/formatter"
)

var eventCmd = &cobra.Command{
	Use:   "event [enable | disable | describe | list]",
	Short: "Manage tracee events",
	Long: `Manage events in tracee.

	Subcommands:
	  enable    Enable specific events.
	  disable   Disable specific events.
	  describe  Get descriptions of available events.
	  list      List available events. 

	Examples:
	  tracee event enable security_file_open
	  tracee event describe magic_write
	  tracee event list
	`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			cmd.PrintErrln("Error: no event names provided. Please specify at least one event to enable.")
			return
		}
	},
}

func init() {
	eventCmd.AddCommand(listEventCmd)
	eventCmd.AddCommand(describeEventCmd)
	eventCmd.AddCommand(enableEventCmd)
	eventCmd.AddCommand(disableEventCmd)

	listEventCmd.Flags().StringVarP(&formatFlag, "format", "f", formatter.FormatTable, "Output format (json|table)")
	describeEventCmd.Flags().StringVarP(&formatFlag, "format", "f", formatter.FormatTable, "Output format (json|table)")
}

var listEventCmd = &cobra.Command{
	Use:   "list",
	Short: "List available events",
	Long:  `Lists all available event definitions (built-in and plugin-defined), providing a brief summary of each.`,
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		listEvents(cmd, args)
	},
}
var describeEventCmd = &cobra.Command{
	Use:   "describe <event_name>",
	Short: "Describe an event",
	Long:  `Retrieves the detailed definition of a specific event, including its fields, types, and other metadata.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		eventDescriptions(cmd, args)
	},
}
var enableEventCmd = &cobra.Command{
	Use:   "enable <event_name>",
	Short: "Enable an event",
	Long:  `Enables capturing of a specific event type.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		enableEvents(cmd, args[0])
	},
}
var disableEventCmd = &cobra.Command{
	Use:   "disable <event_name>",
	Short: "Disable an event",
	Long:  `Disables capturing of a specific event type.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		disableEvents(cmd, args[0])
	},
}

func listEvents(cmd *cobra.Command, args []string) {
	traceeClient, err := client.NewServiceClient(server)
	if err != nil {
		cmd.PrintErrln("Error creating client: ", err)
		return
	}
	defer traceeClient.CloseConnection()

	response, err := traceeClient.GetEventDefinitions(context.Background(), &pb.GetEventDefinitionsRequest{EventNames: args})
	if err != nil {
		cmd.PrintErrln("Error getting event definitions: ", err)
		return
	}
	format, err := formatter.NewFormatter(formatFlag, cmd)
	if err != nil {
		cmd.PrintErrln("Error creating formatter: ", err)
		return
	}
	switch format.GetFormat() {
	case formatter.FormatJson:
		format.PrintJson(response)
	case formatter.FormatTable:
		format.PrintTableHeaders([]string{"ID", "Name", "Version", "Tags"})
		for _, event := range response.Definitions {
			// remove descriptions
			format.PrintTableRow(prepareDescription(event)[:4])
		}
	default:
		cmd.PrintErrln("output format not supported")
		return
	}
}

func eventDescriptions(cmd *cobra.Command, args []string) {
	traceeClient, err := client.NewServiceClient(server)
	if err != nil {
		cmd.PrintErrln("Error creating client: ", err)
		return
	}
	defer traceeClient.CloseConnection()

	response, err := traceeClient.GetEventDefinitions(context.Background(), &pb.GetEventDefinitionsRequest{EventNames: args})
	if err != nil {
		cmd.PrintErrln("Error getting event definitions: ", err)
		return
	}
	format, err := formatter.NewFormatter(formatFlag, cmd)
	if err != nil {
		cmd.PrintErrln("Error creating formatter: ", err)
		return
	}
	switch format.GetFormat() {
	case formatter.FormatJson:
		format.PrintJson(response)
	case formatter.FormatTable:
		format.PrintTableHeaders([]string{"ID", "Name", "Version", "Tags", "Description"})
		for _, event := range response.Definitions {
			format.PrintTableRow(prepareDescription(event))
		}
	default:
		cmd.PrintErrln("output format not supported")
		return
	}
}
func prepareDescription(event *pb.EventDefinition) []string {
	return []string{
		strconv.Itoa(int(event.Id)),
		event.Name,
		fmt.Sprintf("%d.%d.%d", event.Version.Major, event.Version.Minor, event.Version.Patch),
		strings.Join(event.Tags, ", "),
		event.Description,
	}
}
func enableEvents(cmd *cobra.Command, eventName string) {
	traceeClient, err := client.NewServiceClient(server)
	if err != nil {
		cmd.PrintErrln("Error creating client: ", err)
		return
	}
	defer traceeClient.CloseConnection()

	_, err = traceeClient.EnableEvent(context.Background(), &pb.EnableEventRequest{Name: eventName})
	if err != nil {
		cmd.PrintErrln("Error enabling event:", err)
		return
	}
	cmd.Printf("Enabled event: %s\n", eventName)
}
func disableEvents(cmd *cobra.Command, eventName string) {
	traceeClient, err := client.NewServiceClient(server)
	if err != nil {
		cmd.PrintErrln("Error creating client: ", err)
		return
	}
	defer traceeClient.CloseConnection()
	_, err = traceeClient.DisableEvent(context.Background(), &pb.DisableEventRequest{Name: eventName})
	if err != nil {
		cmd.PrintErrln("Error disabling event:", err)
		return
	}
	cmd.Printf("Disabled event: %s\n", eventName)
}
