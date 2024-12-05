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
	defaultTriggerOps   = int32(1)
	defaultTriggerSleep = 10 * time.Nanosecond
	triggerTimeout      = 30 * time.Minute
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
}

func getTrigger(cmd *cobra.Command) (*trigger, error) {
	event, err := cmd.Flags().GetString("event")
	if err != nil {
		return nil, err
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

	return &trigger{
		event:            event,
		ops:              ops,
		sleep:            sleep,
		printBypassFlags: bypassFlags,
		waitSignal:       waitSignal,
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
