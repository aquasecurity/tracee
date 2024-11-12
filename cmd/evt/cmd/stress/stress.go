package stress

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/spf13/cobra"
	"golang.org/x/exp/slices"
	"gopkg.in/yaml.v2"

	"github.com/aquasecurity/tracee/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/policy/v1beta1"
)

func init() {
	stressCmd.Flags().StringArrayP(
		"policy",
		"p",
		[]string{},
		"<file|dir>\t\t\tPath to a policy or directory with policies to stress",
	)
	stressCmd.Flags().StringSliceP(
		"event",
		"e",
		[]string{},
		"<name>...\t\t\tSelect events to stress",
	)

	stressMode := os.Getenv("EVT_STRESS_MODE")
	if stressMode == "" {
		stressMode = fmt.Sprintf("ops=%d", defaultStressOps)
	}
	stressCmd.Flags().StringVarP(
		&stressMode,
		"mode",
		"m",
		stressMode,
		"<time=30m|ops=2000000>\tStress mode",
	)

	stressThreads := defaultStressThreads
	stressThreadsS := os.Getenv("EVT_STRESS_THREADS")
	if stressThreadsS != "" {
		v, err := strconv.ParseUint(stressThreadsS, 10, 8)
		if err != nil {
			fmt.Printf("Error parsing EVT_STRESS_THREADS: %v\n", err)
			os.Exit(1)
		}

		stressThreads = uint8(v)
	}
	stressCmd.Flags().Uint8P(
		"threads",
		"t",
		stressThreads,
		"<number>...\t\t\tNumber of threads to stress for each trigger",
	)
}

type StressMode int32

const (
	StressModeTime StressMode = iota
	StressModeOps
)

const (
	maxStressTime        = 3 * time.Hour
	defaultStressTime    = 10 * time.Minute
	defaultStressOps     = uint32(10_000_000)
	defaultStressThreads = uint8(1)
)

var (
	stressCmd = &cobra.Command{
		Use:           "stress",
		Aliases:       []string{"s"},
		Short:         "Stress the system with events",
		RunE:          stressRun,
		SilenceErrors: true,
		SilenceUsage:  true,
	}
)

type StressConfig struct {
	Mode     StressModeConfig
	Selected *SelectedToStress
}

type StressModeConfig struct {
	Selected StressMode
	Ops      uint32
	Threads  uint8
	Time     time.Duration
}

func parseStressModeFlag(modeFlag string) (StressModeConfig, error) {
	parts := strings.Split(modeFlag, "=")
	mode := ""
	value := ""
	if len(parts) == 0 || len(parts) > 2 {
		goto invalid_mode
	}

	mode = parts[0]
	if mode != "time" && mode != "ops" {
		goto invalid_mode
	}

	if len(parts) == 1 {
		switch mode {
		case "time":
			return StressModeConfig{
				Selected: StressModeTime,
				Time:     defaultStressTime,
			}, nil

		case "ops":
			return StressModeConfig{
				Selected: StressModeOps,
				Ops:      defaultStressOps,
			}, nil
		}
	}

	value = parts[1]
	switch mode {
	case "time":
		t, err := time.ParseDuration(value)
		if err != nil {
			return StressModeConfig{}, fmt.Errorf("invalid stress time: %s", value)
		}
		return StressModeConfig{
			Selected: StressModeTime,
			Time:     t,
		}, nil

	case "ops":
		ops, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return StressModeConfig{}, fmt.Errorf("invalid stress ops: %s", value)
		}
		return StressModeConfig{
			Selected: StressModeOps,
			Ops:      uint32(ops),
		}, nil
	}

invalid_mode:
	return StressModeConfig{}, fmt.Errorf("invalid stress mode: %s", modeFlag)
}

func getStressConfig(cmd *cobra.Command) (*StressConfig, error) {
	modeFlag := cmd.Flag("mode").Value.String()
	modeConfig, err := parseStressModeFlag(modeFlag)
	if err != nil {
		return nil, err
	}

	modeConfig.Threads, err = cmd.Flags().GetUint8("threads")
	if err != nil {
		return nil, err
	}

	return &StressConfig{
		Mode: modeConfig,
	}, nil
}

const coolDownTime = 10 * time.Second

func coolDownCtx(ctx context.Context, msg string, coolDownTime time.Duration) {
	fmt.Printf("%s: waiting %v for cool down...\n", msg, coolDownTime)

	select {
	case <-time.After(coolDownTime):
		return
	case <-ctx.Done():
		return
	}
}

func coolDown(msg string, coolDownTime time.Duration) {
	fmt.Printf("%s: waiting %v for cool down...\n", msg, coolDownTime)
	time.Sleep(coolDownTime)
}

func stressRun(cmd *cobra.Command, args []string) error {
	logger.Init(logger.NewDefaultLoggingConfig())

	cfg, err := getStressConfig(cmd)
	if err != nil {
		return err
	}

	err = setSelectedToStress(cmd, cfg)
	if err != nil {
		return err
	}

	fmt.Printf("Events selected to stress: %v\n", cfg.Selected.EventsNames)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	var timeLimit time.Duration
	if cfg.Mode.Selected == StressModeOps {
		timeLimit = maxStressTime
		fmt.Printf("Stressing the system with %v ops per event and time limit of %v\n", humanize.Comma(int64(cfg.Mode.Ops)), timeLimit)
		fmt.Println("Ops mode triggers events based on the ops of the event, until it reaches the event ops amount or the time limit")
	} else {
		timeLimit = cfg.Mode.Time
		fmt.Printf("Stressing the system without ops limit for %v\n", timeLimit)
		fmt.Println("Time mode triggers events disregarding the ops, until it reaches the time limit")
	}

	ctx, cancelTimeout := context.WithTimeoutCause(
		ctx,
		timeLimit,
		fmt.Errorf("stress time is up after %v", timeLimit),
	)
	defer cancelTimeout()

	wg := &sync.WaitGroup{}
	triggerPids := make([]int, 0, len(cfg.Selected.EventsNames)*int(cfg.Mode.Threads))
	triggerComms := make([]string, 0, len(cfg.Selected.EventsNames)*int(cfg.Mode.Threads))

	for _, evt := range cfg.Selected.EventsNames {
		for i := uint8(0); i < cfg.Mode.Threads; i++ {
			triggerPid, err := triggerEvent(ctx, wg, evt, cfg.Mode.Ops)
			if err != nil {
				return err
			}

			fmt.Printf("Started trigger %d for event %s with pid %d\n", i+1, evt, triggerPid)
			triggerPids = append(triggerPids, triggerPid)
			// limit the comm length to 15 printable characters
			comm := fmt.Sprintf("%s.sh", evt)
			comm = comm[:min(len(comm), 15)]
			triggerComms = append(triggerComms, comm)
		}
	}

	traceeStatus := RunTracee(ctx, wg, cfg.Selected, os.Getpid(), triggerComms, triggerPids)

	// block until receiving tracee status
	err = <-traceeStatus
	if err != nil {
		return err
	}

	coolDownCtx(ctx, "tracee started", coolDownTime)

	// signal all triggers to start
	for _, pid := range triggerPids {
		err = syscall.Kill(pid, syscall.SIGUSR1)
		if err != nil {
			return fmt.Errorf("sending SIGUSR1 to trigger %d: %w", pid, err)
		}
	}
	// err = syscall.Kill(-os.Getpid(), syscall.SIGUSR1)
	// if err != nil {
	// 	return fmt.Errorf("sending SIGUSR1 to all triggers: %w", err)
	// }

	if cfg.Mode.Selected == StressModeOps {
		wg.Add(1)
		go func(cancel context.CancelFunc) {
			logger.Debugw("checkTriggersLiveness goroutine started")
			defer logger.Debugw("checkTriggersLiveness goroutine finished")

			defer wg.Done()

			for {
				select {
				case <-time.After(1 * time.Second):
					allDone := true
					for _, pid := range triggerPids {
						if syscall.Kill(pid, 0) == nil {
							allDone = false
							break
						}
					}

					if allDone {
						coolDown("triggers finished", coolDownTime)
						cancel()
						return
					}
				}
			}
		}(cancel)
	}

	// block until tracee is finished or context is done
	for {
		select {
		case <-ctx.Done():
			for _, pid := range triggerPids {
				err = syscall.Kill(pid, syscall.SIGTERM)
				if err != nil {
					return fmt.Errorf("sending SIGTERM to trigger %d: %w", pid, err)
				}
			}
			goto cleanup
		case err := <-traceeStatus:
			if err != nil {
				fmt.Println(err)
			}
			goto cleanup
		}
	}

cleanup:
	// drain closed channels
	for err := range traceeStatus {
		if err != nil {
			fmt.Println(err)
		}
	}

	wg.Wait()

	return nil
}

func triggerEvent(ctx context.Context, wg *sync.WaitGroup, event string, ops uint32) (int, error) {
	var err error
	triggerPid := 0

	exeCmd := exec.CommandContext(ctx, "./dist/evt", "trigger", "-e", event, "-o", fmt.Sprintf("%d", ops))
	exeCmd.SysProcAttr = &syscall.SysProcAttr{
		// Setpgid: true,
		// Pgid:    os.Getpid(),
	}
	exeCmd.Stdin = nil
	exeCmd.Stdout = os.Stdout
	exeCmd.Stderr = os.Stderr

	err = exeCmd.Start()
	if err != nil {
		err = fmt.Errorf("starting trigger: %w", err)
		return triggerPid, err
	}

	triggerPid = exeCmd.Process.Pid

	wg.Add(1)
	go func() {
		logger.Debugw("waitForTrigger goroutine started")
		defer logger.Debugw("waitForTrigger goroutine finished")

		defer wg.Done()

		waitErr := exeCmd.Wait()
		if waitErr != nil {
			fmt.Errorf("waiting for trigger: %w", waitErr)
		}
	}()

	return triggerPid, err
}

func RunTracee(
	ctx context.Context,
	wg *sync.WaitGroup,
	selected *SelectedToStress,
	treePid int,
	filterOutCommScope []string,
	filterOutPidScope []int,
) <-chan error {
	errCh := make(chan error, 1)

	wg.Add(1)
	go func() {
		logger.Debugw("runTracee goroutine started")
		defer logger.Debugw("runTracee goroutine finished")

		defer wg.Done()
		defer close(errCh)

		var args []string
		if selected.Origin == "policy" {
			// update the policy files with the filter out scope
			updatePolicyFiles(selected.PolicyFiles, treePid, filterOutCommScope, filterOutPidScope)

			// save all updated policies to a temporary directory
			const policiesTmpDir = "/tmp/evt-policies"

			err := writePolicyFiles(policiesTmpDir, selected.PolicyFiles)
			if err != nil {
				errCh <- fmt.Errorf("writing policy files: %w", err)
			}

			args = append(args, "-p", policiesTmpDir)
		} else {
			args = append(args, "-s", getFilterOutCommScope(filepath.Base(os.Args[0])))
			for _, outComm := range filterOutCommScope {
				args = append(args, "-s", getFilterOutCommScope(outComm))
			}

			selfPid := os.Getpid()
			args = append(args, "-s", getFilterOutPidScope(selfPid))
			for _, outPid := range filterOutPidScope {
				args = append(args, "-s", getFilterOutPidScope(outPid))
			}

			args = append(args, "-s", fmt.Sprintf("tree=%d", treePid))

			for _, evt := range selected.EventsFlags {
				args = append(args, "-e", evt)
			}
		}

		args = append(args, "--metrics", "--pprof", "--pyroscope")
		args = append(args, "-o", "none")

		fmt.Println("Running tracee with args:", args)

		cmd := exec.CommandContext(ctx, "./dist/tracee", args...)
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Setpgid: true,
		}
		cmd.Cancel = func() error {
			errCh <- fmt.Errorf("tracee being stopped: %w", context.Cause(ctx))
			return cmd.Process.Signal(syscall.SIGTERM)
		}
		cmd.Stdin = nil

		logFile, err := os.Create(fmt.Sprintf("tracee-%s.log", time.Now().Format("20060102-150405")))
		if err != nil {
			errCh <- fmt.Errorf("creating log file: %w", err)
			return
		}
		defer logFile.Close()

		cmd.Stdout = logFile
		cmd.Stderr = logFile

		err = cmd.Start()
		if err != nil {
			errCh <- fmt.Errorf("starting tracee: %w", err)
			return
		}

		cmdWaitChan := waitForCommand(cmd)
		select {
		case err = <-cmdWaitChan:
			if err == nil {
				errCh <- fmt.Errorf("tracee finished with no error right after starting")
				return
			}

			// tracee finished with error
			errCh <- fmt.Errorf("tracee finished: %w", err)
		case <-time.After(1 * time.Second):
			// give tracee some time to start
		}
		if err != nil {
			return
		}

		// tracee started, unblock the caller
		errCh <- nil

		// wait for tracee to finish
		err = <-cmdWaitChan
		if err != nil {
			errCh <- fmt.Errorf("tracee finished: %w", err)
		}
	}()

	return errCh
}

func updatePolicyFiles(
	policyFiles []v1beta1.PolicyFile,
	treePid int,
	filterOutCommScope []string,
	filterOutPidScope []int,
) {
	for i := range policyFiles {
		p := &policyFiles[i]
		p.Spec.Scope = append(p.Spec.Scope, getFilterTreeScope(treePid))

		selfCommScope := getFilterOutCommScope(filepath.Base(os.Args[0]))
		if idx := slices.Index(p.Spec.Scope, "global"); idx != -1 {
			p.Spec.Scope[idx] = selfCommScope
		} else {
			p.Spec.Scope = append(p.Spec.Scope, selfCommScope)
		}
		p.Spec.Scope = append(p.Spec.Scope, getFilterOutPidScope(os.Getpid()))

		for _, outComm := range filterOutCommScope {
			p.Spec.Scope = append(p.Spec.Scope, getFilterOutCommScope(outComm))
		}
		for _, outPid := range filterOutPidScope {
			p.Spec.Scope = append(p.Spec.Scope, getFilterOutPidScope(outPid))
		}
	}
}

func writePolicyFiles(policiesTmpDir string, policyFiles []v1beta1.PolicyFile) error {
	err := os.RemoveAll(policiesTmpDir)
	if err != nil {
		return fmt.Errorf("removing policies tmp dir: %w", err)
	}
	err = os.MkdirAll(policiesTmpDir, 0755)
	if err != nil {
		return fmt.Errorf("creating policies tmp dir: %w", err)
	}

	for _, policyFile := range policyFiles {
		policyYaml, err := yaml.Marshal(policyFile)
		if err != nil {
			return fmt.Errorf("marshaling policy to yaml: %w", err)
		}

		policyFilePath := fmt.Sprintf("%s/%s.yaml", policiesTmpDir, policyFile.Metadata.Name)
		err = os.WriteFile(policyFilePath, policyYaml, 0755)
		if err != nil {
			return fmt.Errorf("writing policy to file: %w", err)
		}
	}

	return nil
}

func waitForCommand(cmd *exec.Cmd) <-chan error {
	done := make(chan error)

	go func() {
		done <- cmd.Wait()
		close(done)
	}()

	return done
}

type SelectedToStress struct {
	Origin      string
	EventsNames []string
	EventsFlags []string
	PolicyFlags []string
	PolicyFiles []v1beta1.PolicyFile
}

func setSelectedToStress(cmd *cobra.Command, stressConfig *StressConfig) error {
	policyFlags, err := cmd.Flags().GetStringArray("policy")
	if err != nil {
		return err
	}
	eventFlags, err := cmd.Flags().GetStringSlice("event")
	if err != nil {
		return err
	}

	if len(policyFlags) == 0 && len(eventFlags) == 0 {
		return fmt.Errorf("no policies or events provided")
	}
	if len(policyFlags) > 0 && len(eventFlags) > 0 {
		return fmt.Errorf("policy and event flags cannot be used together")
	}

	var events []string
	var policyFiles []v1beta1.PolicyFile
	origin := ""
	if len(policyFlags) > 0 {
		origin = "policy"
		events, policyFiles, err = getEventsAndPoliciesFromPolicyFiles(policyFlags)
		if err != nil {
			return err
		}
	} else {
		origin = "event"
		events, err = getEventsFromEventFlags(eventFlags)
		if err != nil {
			return err
		}
	}

	slices.Sort(events)
	events = slices.Compact(events)

	// set the selected events
	stressConfig.Selected = &SelectedToStress{
		Origin:      origin,
		EventsNames: events,
		EventsFlags: eventFlags,
		PolicyFlags: policyFlags,
		PolicyFiles: policyFiles,
	}

	return nil
}

func getFilterOutCommScope(comm string) string {
	return fmt.Sprintf("comm!=%s", comm)
}

func getFilterOutPidScope(pid int) string {
	return fmt.Sprintf("pid!=%d", pid)
}

func getFilterTreeScope(treePid int) string {
	return fmt.Sprintf("tree=%d", treePid)
}

func getEventsAndPoliciesFromPolicyFiles(policyFlags []string) ([]string, []v1beta1.PolicyFile, error) {
	policyInterfaceSlice, err := v1beta1.PoliciesFromPaths(policyFlags)
	if err != nil {
		return nil, nil, err
	}

	policyFiles := make([]v1beta1.PolicyFile, 0, len(policyInterfaceSlice))
	for i := range policyInterfaceSlice {
		p, ok := policyInterfaceSlice[i].(v1beta1.PolicyFile)
		if !ok {
			return nil, nil, fmt.Errorf("policy file is not a v1beta1.PolicyFile")
		}

		policyFiles = append(policyFiles, p)
	}

	_, policyEventsMap, err := flags.PrepareFilterMapsFromPolicies(policyInterfaceSlice)
	if err != nil {
		return nil, nil, err
	}

	return policyEventsMap.GetSelectedEvents(), policyFiles, nil
}

func getEventsFromEventFlags(eventFlags []string) ([]string, error) {
	policyEventsMap, err := flags.PrepareEventMapFromFlags(eventFlags)
	if err != nil {
		return nil, err
	}

	return policyEventsMap.GetSelectedEvents(), nil
}

func Cmd() *cobra.Command {
	return stressCmd
}
