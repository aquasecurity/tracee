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
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/aquasecurity/tracee/cmd/evt/cmd/helpers"
)

type trigger struct {
	event            string
	ops              int32
	sleep            time.Duration
	waitSignal       bool
	signalTimeout    time.Duration
	printBypassFlags bool
	parallel         int32
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

	if t.parallel == 1 {
		// Sequential execution
		t.printf("Starting triggering %d ops with %v sleep time at %v\n", t.ops, t.sleep, now.Format(layout))
		err := t.runTriggersSequential()
		if err != nil {
			return err
		}
	} else {
		// Parallel execution: total = parallel × ops
		totalOps := t.parallel * t.ops
		t.printf("Starting triggering %d total ops (%d workers × %d ops) with %v sleep time at %v\n",
			totalOps, t.parallel, t.ops, t.sleep, now.Format(layout))
		err := t.runTriggersParallel()
		if err != nil {
			return err
		}
	}

	end := time.Now()
	totalOps := t.ops
	if t.parallel > 1 {
		totalOps = t.parallel * t.ops
	}
	t.printf("Finished triggering %d ops after %v at %v\n", totalOps, end.Sub(now).String(), end.Format(layout))

	return nil
}

// runTriggersSequential runs ops sequentially
func (t *trigger) runTriggersSequential() error {
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
	return nil
}

// runTriggersParallel spawns N workers, each running ops operations
// Total operations = parallel × ops
func (t *trigger) runTriggersParallel() error {
	var wg sync.WaitGroup
	errChan := make(chan error, t.parallel)

	// Each worker runs the full ops count
	for workerID := int32(0); workerID < t.parallel; workerID++ {
		wg.Add(1)
		go func(id int32) {
			defer wg.Done()

			// Each worker runs t.ops operations
			for i := int32(0); i < t.ops; i++ {
				select {
				case <-t.ctx.Done():
					errChan <- t.ctx.Err()
					return
				default:
					time.Sleep(t.sleep)
				}

				exeCmd := exec.CommandContext(t.ctx, t.triggerPath)
				if err := exeCmd.Run(); err != nil {
					errChan <- fmt.Errorf("worker %d failed: %w", id, err)
					return
				}
			}
		}(workerID)
	}

	// Wait for all workers to complete
	wg.Wait()
	close(errChan)

	// Collect all errors
	var errs []error
	for err := range errChan {
		if err != nil {
			errs = append(errs, err)
		}
	}

	// Return combined error if any failures occurred
	if len(errs) == 0 {
		return nil
	}

	// Multiple errors - join them preserving error chain
	return fmt.Errorf("%d workers failed: %w", len(errs), errors.Join(errs...))
}

func (t *trigger) printf(format string, args ...any) {
	t.cmd.Printf(format, args...)
}

func (t *trigger) println(args ...any) {
	t.cmd.Println(args...)
}

func (t *trigger) printErrf(format string, args ...any) {
	t.cmd.PrintErrf(format, args...)
}

func (t *trigger) printErrln(args ...any) {
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
	t.printf("Waiting for start signal SIGUSR1 (timeout: %v)", t.signalTimeout)

	ctx := t.ctx
	timeout := time.After(t.signalTimeout)

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-startChan:
		return nil
	case <-timeout:
		return fmt.Errorf("timed out waiting for signal SIGUSR1 after %v", t.signalTimeout)
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
