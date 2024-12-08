package trigger

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/aquasecurity/tracee/cmd/evt/cmd/helpers"
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
		"f",
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

const (
	defaultTriggerOps   = int32(1)
	defaultTriggerSleep = 10 * time.Nanosecond
	triggerTimeout      = 30 * time.Minute
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

type trigger struct {
	event            string
	ops              int32
	sleep            time.Duration
	waitSignal       bool
	printBypassFlags bool

	ctx context.Context
	cmd *cobra.Command
}

func (t *trigger) Run() error {
	t.setCmdOutErr()

	if t.printBypassFlags {
		t.printTraceeBypassFlags()
		os.Exit(0)
	}

	err := t.waitForSignal()
	if err != nil {
		return err
	}

	const layout = "15:04:05.999999999"
	now := time.Now()
	t.Printf("Starting triggering %d ops with %v sleep time at %v\n", t.ops, t.sleep, now.Format(layout))

	for i := int32(0); i < t.ops; i++ {
		select {
		case <-t.ctx.Done():
			t.Printf("Stopping triggering: %v\n", t.ctx.Err())
			return t.ctx.Err()
		default:
			time.Sleep(t.sleep)
		}

		exeCmd := exec.CommandContext(t.ctx, getTriggerPath(t.event))
		err := exeCmd.Run()
		if err != nil {
			return fmt.Errorf("failed to run command: %w", err)
		}
	}

	end := time.Now()
	t.Printf("Finished triggering %d ops at %v after %v\n", t.ops, end.Format(layout), end.Sub(now).String())

	return nil
}

func (t *trigger) Printf(format string, args ...interface{}) {
	t.cmd.Printf(format, args...)
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
		return nil, fmt.Errorf("ops must be greater than 0")
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

func (t *trigger) setCmdOutErr() {
	if !t.waitSignal {
		return
	}

	prefix := []byte(fmt.Sprintf("[trigger:%d:%s] ", os.Getpid(), t.event))
	cmd := t.cmd
	cmd.SetOut(&helpers.PrefixWriter{
		Prefix: prefix,
		Writer: os.Stdout,
	})
	cmd.SetErr(&helpers.PrefixWriter{
		Prefix: prefix,
		Writer: os.Stderr,
	})
}

func (t *trigger) waitForSignal() error {
	if !t.waitSignal {
		return nil
	}

	startChan := make(chan os.Signal, 1)
	signal.Notify(startChan, syscall.SIGUSR1)
	t.Printf("Waiting for start signal\n")

	ctx := t.ctx
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-startChan:
		return nil
	}
}

func getTriggerPath(event string) string {
	return fmt.Sprintf("./cmd/evt/cmd/trigger/triggers/%s.sh", event)
}

func (t *trigger) printTraceeBypassFlags() {
	self := helpers.GetFilterOutCommScope(os.Args[0])
	comm := helpers.GetFilterOutCommScope(fmt.Sprintf("%s.sh", t.event))
	t.cmd.Printf("Tracee bypass flags: -s %s -s %s\n", self, comm)
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

	return t.Run()
}

func Cmd() *cobra.Command {
	return triggerCmd
}
