package trigger

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
)

var (
	triggerCmd = &cobra.Command{
		Use:           "trigger",
		Aliases:       []string{"t"},
		Short:         "Trigger events to trigger",
		RunE:          triggerCmdRun,
		SilenceErrors: true,
		SilenceUsage:  true,
	}
)

const (
	defaultTriggerOps      = int32(1)
	defaultTriggerSleep    = 10 * time.Nanosecond
	defaultTriggerParallel = int32(1)
	triggerTimeout         = 30 * time.Minute
)

func init() {
	triggerCmd.Flags().StringP(
		"event",
		"e",
		"",
		"<name>...\t\tSelect event to trigger",
	)
	if err := triggerCmd.MarkFlagRequired("event"); err != nil {
		triggerCmd.PrintErrf("marking required flag: %v\n", err)
		os.Exit(1)
	}

	triggerCmd.Flags().Int32P(
		"ops",
		"o",
		defaultTriggerOps,
		"<number>...\t\tNumber of operations to perform",
	)

	triggerCmd.Flags().DurationP(
		"sleep",
		"s",
		defaultTriggerSleep,
		"<duration>...\t\tSleep time between operations",
	)

	triggerCmd.Flags().BoolP(
		"bypass-flags",
		"b",
		false,
		"\t\t\tPrint tracee bypass flags",
	)

	triggerCmd.Flags().BoolP(
		"wait-signal",
		"w",
		false,
		"\t\t\tWait for start signal (SIGUSR1)",
	)

	triggerCmd.Flags().Duration(
		"signal-timeout",
		1*time.Minute,
		"<duration>\t\tTimeout for waiting for signal (e.g., 5m, 10m)",
	)

	triggerCmd.Flags().Int32P(
		"parallel",
		"p",
		defaultTriggerParallel,
		"<number>...\t\tNumber of parallel workers (total ops = workers × ops)",
	)
}

func getTrigger(cmd *cobra.Command) (*trigger, error) {
	event, err := cmd.Flags().GetString("event")
	if err != nil {
		return nil, err
	}
	if event == "" {
		return nil, errors.New("event name cannot be empty")
	}

	// Check if user tried to specify multiple events (common mistake)
	// Cobra doesn't error on duplicate flags, it just uses the last value
	if cmd.Flags().Changed("event") {
		// Check for multiple -e flags in os.Args
		eventFlagCount := 0
		for i, arg := range os.Args {
			if arg == "-e" || arg == "--event" {
				eventFlagCount++
				if eventFlagCount > 1 {
					return nil, fmt.Errorf("multiple events not supported: use separate 'evt trigger' commands for each event (found -e/%s at args[%d])", arg, i)
				}
			}
		}
	}

	ops, err := cmd.Flags().GetInt32("ops")
	if err != nil {
		return nil, err
	}
	if ops <= 0 {
		return nil, errors.New("ops must be greater than 0")
	}

	sleep, err := cmd.Flags().GetDuration("sleep")
	if err != nil {
		return nil, err
	}

	bypassFlags, err := cmd.Flags().GetBool("bypass-flags")
	if err != nil {
		return nil, err
	}

	waitSignal, err := cmd.Flags().GetBool("wait-signal")
	if err != nil {
		return nil, err
	}

	signalTimeout, err := cmd.Flags().GetDuration("signal-timeout")
	if err != nil {
		return nil, err
	}

	parallel, err := cmd.Flags().GetInt32("parallel")
	if err != nil {
		return nil, err
	}
	if parallel <= 0 {
		return nil, errors.New("parallel must be greater than 0")
	}

	return &trigger{
		event:            event,
		ops:              ops,
		sleep:            sleep,
		printBypassFlags: bypassFlags,
		waitSignal:       waitSignal,
		signalTimeout:    signalTimeout,
		parallel:         parallel,
		cmd:              cmd,
	}, nil
}

func triggerCmdRun(cmd *cobra.Command, args []string) error {
	t, err := getTrigger(cmd)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeoutCause(
		t.cmd.Context(),
		triggerTimeout,
		fmt.Errorf("timeout after %v", triggerTimeout),
	)
	defer cancel()
	t.ctx = ctx

	return t.run()
}

func Cmd() *cobra.Command {
	return triggerCmd
}
