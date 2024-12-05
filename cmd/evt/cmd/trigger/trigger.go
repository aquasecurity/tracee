package trigger

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/aquasecurity/tracee/cmd/evt/cmd/helpers"
)

const (
	signalWaitTimeout = 1 * time.Minute
)

type trigger struct {
	event            string
	ops              int32
	sleep            time.Duration
	waitSignal       bool
	printBypassFlags bool
	triggerPath      string

	ctx context.Context
	cmd *cobra.Command
}

func (t *trigger) run() error {
	t.setCmdOutErr()

	err := t.setTriggerPath()
	if err != nil {
		return err
	}

	if t.printBypassFlags {
		t.printTraceeBypassFlags()
		os.Exit(0)
	}

	err = t.waitForSignal()
	if err != nil {
		return err
	}

	return t.runTriggers()
}

func (t *trigger) setTriggerPath() error {
	triggerPath, err := getTriggerPath(t.event)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("trigger for the event %s does not exist: %w", t.event, err)
		}
		return fmt.Errorf("failed to get trigger path: %w", err)
	}

	t.triggerPath = triggerPath
	return nil
}

func (t *trigger) runTriggers() error {
	const layout = "15:04:05.999999999"
	now := time.Now()
	t.printf("Starting triggering %d ops with %v sleep time at %v\n", t.ops, t.sleep, now.Format(layout))

	for i := int32(0); i < t.ops; i++ {
		select {
		case <-t.ctx.Done():
			t.printf("Stopping triggering: %v\n", t.ctx.Err())
			return t.ctx.Err()
		default:
			time.Sleep(t.sleep)
		}

		exeCmd := exec.CommandContext(t.ctx, t.triggerPath)
		err := exeCmd.Run()
		if err != nil {
			return fmt.Errorf("failed to run command: %w", err)
		}
	}

	end := time.Now()
	t.printf("Finished triggering %d ops after %v at %v\n", t.ops, end.Sub(now).String(), end.Format(layout))

	return nil
}

func (t *trigger) printf(format string, args ...interface{}) {
	t.cmd.Printf(format, args...)
}

func (t *trigger) println(args ...interface{}) {
	t.cmd.Println(args...)
}

func (t *trigger) printErrf(format string, args ...interface{}) {
	t.cmd.PrintErrf(format, args...)
}

func (t *trigger) printErrln(args ...interface{}) {
	t.cmd.PrintErrln(args...)
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
	t.println("Waiting for start signal SIGUSR1")

	ctx := t.ctx
	timeout := time.After(signalWaitTimeout)

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-startChan:
		return nil
	case <-timeout:
		return errors.New("timed out waiting for signal SIGUSR1")
	}
}

// printTraceeBypassFlags outputs the bypass flags used by Tracee.
// The execution path leading to the triggered event inherently generates numerous other events,
// influenced by the shell, interpreter, and versions of the commands in the trigger script.
// To reduce noise and exclude most unrelated events, the bypass flags serve as effective filters.
// NOTE: Each trigger script includes an estimate of the residual noise that remains.
func (t *trigger) printTraceeBypassFlags() {
	parentShellComm, ok := os.LookupEnv("SHELL")
	if ok {
		parentShellComm = filepath.Base(parentShellComm)
		parentShellComm = helpers.GetFilterOutCommScope(parentShellComm) // parent shell comm
	}
	selfComm := helpers.GetFilterOutCommScope(os.Args[0])                       // self comm
	triggersInterpComm := helpers.GetFilterOutCommScope("sh")                   // scripts interpreter comm
	triggerComm := helpers.GetFilterOutCommScope(fmt.Sprintf("%s.sh", t.event)) // trigger script comm
	t.printf("Tracee bypass flags: %s\n", getScopeFlags(triggersInterpComm, parentShellComm, selfComm, triggerComm))

	parentPid := helpers.GetFilterInTreeScope(fmt.Sprintf("%d", os.Getppid()))
	t.printf("If running trigger from this shell, also use: %s\n", getScopeFlags(parentPid))
}

// helpers

func getTriggerPath(event string) (string, error) {
	execPath, err := os.Executable()
	if err != nil {
		panic(err)
	}

	basePath := filepath.Dir(execPath)
	triggerPath := filepath.Join(basePath, "evt-triggers", fmt.Sprintf("%s.sh", event))
	_, err = os.Stat(triggerPath)
	if err != nil {
		return "", err
	}

	return triggerPath, nil
}

func getScopeFlags(flags ...string) string {
	var scopes []string
	for _, flag := range flags {
		if flag == "" {
			continue
		}
		scopes = append(scopes, fmt.Sprintf("-s %s", flag))
	}

	return strings.Join(scopes, " ")
}
