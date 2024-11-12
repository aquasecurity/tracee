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
)

func init() {
	triggerCmd.Flags().StringP(
		"event",
		"e",
		"",
		"<name>...\t\t\tSelect event to stress",
	)
	if err := triggerCmd.MarkFlagRequired("event"); err != nil {
		fmt.Printf("Error setting required flag: %v\n", err)
		os.Exit(1)
	}

	triggerCmd.Flags().Uint32P(
		"ops",
		"o",
		defaultStressOps,
		"<number>...\t\t\tNumber of operations to perform",
	)

	triggerCmd.Flags().DurationP(
		"sleep",
		"s",
		defaultTriggerSleep,
		"<duration>...\t\t\tSleep time between operations",
	)
}

const (
	maxTriggerTime      = 1 * time.Hour
	defaultTriggerSleep = 10 * time.Nanosecond
	defaultStressOps    = uint32(1_000_000)
)

var (
	triggerCmd = &cobra.Command{
		Use:           "trigger",
		Aliases:       []string{"t"},
		Short:         "Trigger events to stress the system",
		RunE:          triggerRun,
		SilenceErrors: true,
		SilenceUsage:  true,
	}
)

type TriggerConfig struct {
	Event string
	Ops   uint32
	Sleep time.Duration
}

func getTriggerConfig(cmd *cobra.Command) (*TriggerConfig, error) {
	event, err := cmd.Flags().GetString("event")
	if err != nil {
		return nil, err
	}

	ops, err := cmd.Flags().GetUint32("ops")
	if err != nil {
		return nil, err
	}

	sleep, err := cmd.Flags().GetDuration("sleep")
	if err != nil {
		return nil, err
	}

	return &TriggerConfig{
		Event: event,
		Ops:   ops,
		Sleep: sleep,
	}, nil
}

func triggerRun(cmd *cobra.Command, args []string) error {
	cfg, err := getTriggerConfig(cmd)
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	_, cancelTimeout := context.WithTimeoutCause(
		ctx,
		maxTriggerTime,
		fmt.Errorf("[trigger:%d] time for event %s is up after %v", os.Getegid(), cfg.Event, maxTriggerTime),
	)
	defer cancelTimeout()

	startChan := make(chan os.Signal, 1)
	signal.Notify(startChan, syscall.SIGUSR1)
	fmt.Printf("[trigger:%d:%s] Waiting for start signal\n", os.Getpid(), cfg.Event)

	select {
	case <-ctx.Done():
		fmt.Printf("[trigger:%d:%s] Stopping triggering: %v\n", os.Getpid(), cfg.Event, ctx.Err())
		return ctx.Err()
	case <-startChan:
		fmt.Printf("[trigger:%d:%s] Starting triggering %d ops with %v sleep time\n", os.Getpid(), cfg.Event, cfg.Ops, cfg.Sleep)
	}

	for i := uint32(0); i < cfg.Ops; i++ {
		select {
		case <-ctx.Done():
			fmt.Printf("[trigger:%d:%s] Stopping triggering: %v\n", os.Getpid(), cfg.Event, ctx.Err())
			return ctx.Err()
		case <-time.After(cfg.Sleep):
			// continue
		}

		exeCmd := exec.CommandContext(ctx, fmt.Sprintf("./cmd/evt/cmd/trigger/triggers/%s.sh", cfg.Event))
		err := exeCmd.Run()
		if err != nil {
			return fmt.Errorf("[trigger:%d:%s] failed to run command: %w", os.Getpid(), cfg.Event, err)
		}
	}

	fmt.Printf("[trigger:%d:%s] Finished triggering %d ops\n", os.Getpid(), cfg.Event, cfg.Ops)

	return nil
}

func Cmd() *cobra.Command {
	return triggerCmd
}
