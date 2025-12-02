package stress

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var (
	stressCmd = &cobra.Command{
		Use:     "stress",
		Aliases: []string{"s"},
		Short:   "Stress test by running multiple event triggers in containers",
		Long: `Stress test Tracee by orchestrating multiple event triggers in isolated containers.

Each event runs in its own container with configurable parallel workers.
Tracee is automatically started and configured to capture events only from these containers.

Event Format:
  event[:key=value:key=value:...]
  
  Keys: instances, ops, sleep
  Defaults: instances=1, ops=100, sleep=10ns

Examples:
  # Single event with custom config
  evt stress --events security_file_open:instances=10:ops=1000:sleep=1ms

  # Multiple events with different configs
  evt stress \
    --events security_file_open:instances=10:ops=1000:sleep=1ms \
    --events kprobe_attach:instances=2:ops=10:sleep=100ms

  # Using defaults (instances=1, ops=100, sleep=10ns)
  evt stress --events ptrace

  # Multiple events with defaults
  evt stress --events security_file_open --events ptrace --events magic_write

  # Keep Tracee running after test (for profiling analysis)
  evt stress --events ptrace --keep-tracee --pyroscope
  # Tracee continues running so you can analyze pyroscope data

  # Manual Tracee control (you start/stop tracee yourself)
  evt stress --events ptrace --auto-tracee=false
  # Start tracee separately before running this command

  # Enable event logging to file (default is no output for performance)
  evt stress --events ptrace --tracee-output json:/tmp/my-events.json

  # Minimal overhead (disable profiling endpoints)
  evt stress --events security_file_open --metrics=false --pprof=false

  # Wait before triggering to setup profiling/scraping tools
  evt stress --events security_file_open --pyroscope --wait-before-trigger
  # Setup your tools (dashboard, scrapers, etc.), then press ENTER

  # Profiling with sustained load (30+ seconds of events)
  evt stress --events security_file_open:instances=20:ops=10000:sleep=1ms \
    --pyroscope --wait-before-trigger --keep-tracee

  # Custom signal timeout for longer setup times
  evt stress --events security_file_open --pyroscope --wait-before-trigger \
    --signal-timeout 30m

  # Keep Tracee running after test for external scrapers
  evt stress --events ptrace --pyroscope --keep-tracee

  # Dry run to see what would be executed
  evt stress --events sched_process_fork:instances=5 --dry-run`,
		RunE:          stressCmdRun,
		SilenceErrors: true,
		SilenceUsage:  true,
	}
)

const (
	defaultStressInstances      = 1
	defaultStressOps            = int32(100)
	defaultStressSleep          = "10ns"
	defaultStressContainerImage = "evt-trigger-runner:latest"
	defaultTraceeBinary         = "./dist/tracee"
	defaultTraceeOutput         = "none"
	defaultTraceeInitCooldown   = 5 * time.Second
	defaultStressEndCooldown    = 10 * time.Second
	stressTimeout               = 60 * time.Minute
)

func init() {
	stressCmd.Flags().StringSliceP(
		"events",
		"e",
		[]string{},
		"<event[:key=val:...]>\tEvents to stress test (format: event[:instances=N:ops=N:sleep=dur])\n"+
			"\t\t\t\tExample: security_file_open:instances=10:ops=1000:sleep=1ms\n"+
			"\t\t\t\tDefaults: instances=1, ops=100, sleep=10ns",
	)
	if err := stressCmd.MarkFlagRequired("events"); err != nil {
		stressCmd.PrintErrf("marking required flag: %v\n", err)
		os.Exit(1)
	}

	stressCmd.Flags().String(
		"image",
		defaultStressContainerImage,
		"<name:tag>\t\tTrigger runner container image (build with 'make evt-trigger-runner' or 'EVT_TRIGGER_RUNNER_IMAGE=<name:tag> make evt-trigger-runner')",
	)

	stressCmd.Flags().Bool(
		"auto-tracee",
		true,
		"\t\t\tAutomatically manage Tracee lifecycle (start and stop). Set to false for manual control.",
	)

	stressCmd.Flags().Bool(
		"keep-tracee",
		false,
		"\t\t\tWhen --auto-tracee=true: keep Tracee running after test (useful for --pyroscope profiling)",
	)

	stressCmd.Flags().String(
		"tracee-binary",
		defaultTraceeBinary,
		"<path>\t\t\tPath to Tracee binary (only used when --auto-tracee=true)",
	)

	stressCmd.Flags().String(
		"tracee-output",
		defaultTraceeOutput,
		"<format:path>\tTracee output format (default: none for performance; use json:/path/to/file.json to enable logging)",
	)

	stressCmd.Flags().Bool(
		"metrics",
		true,
		"\t\t\tEnable Tracee metrics endpoint (default: true)",
	)

	stressCmd.Flags().Bool(
		"pprof",
		true,
		"\t\t\tEnable Tracee pprof profiling endpoint (default: true)",
	)

	stressCmd.Flags().Bool(
		"pyroscope",
		false,
		"\t\t\tEnable Tracee pyroscope continuous profiling (default: false)",
	)

	stressCmd.Flags().Bool(
		"wait-before-trigger",
		false,
		"\t\tWait for user input before triggering events (useful to start profiling/scraping)",
	)

	stressCmd.Flags().Duration(
		"signal-timeout",
		15*time.Minute,
		"<duration>\t\tTimeout for containers waiting for signal (e.g., 5m, 30m)",
	)

	stressCmd.Flags().Duration(
		"tracee-init-cooldown",
		defaultTraceeInitCooldown,
		"<duration>\t\tCooldown after Tracee starts for stabilization before triggering (e.g., 5s, 10s)",
	)

	stressCmd.Flags().Duration(
		"stress-end-cooldown",
		defaultStressEndCooldown,
		"<duration>\t\tCooldown after stress completes for stabilization before cleanup (e.g., 10s, 30s)",
	)

	stressCmd.Flags().Bool(
		"dry-run",
		false,
		"\t\t\tShow what would be executed without running",
	)
}

func getStress(cmd *cobra.Command) (*stress, error) {
	eventSpecs, err := cmd.Flags().GetStringSlice("events")
	if err != nil {
		return nil, err
	}

	if len(eventSpecs) == 0 {
		return nil, errors.New("at least one event must be specified")
	}

	// Parse event specifications into trigger configs
	triggers := make([]triggerConfig, 0, len(eventSpecs))
	for _, spec := range eventSpecs {
		tc, err := parseEventSpec(spec)
		if err != nil {
			return nil, fmt.Errorf("invalid event spec %q: %w", spec, err)
		}
		triggers = append(triggers, tc)
	}

	image, err := cmd.Flags().GetString("image")
	if err != nil {
		return nil, err
	}
	if image == "" {
		return nil, errors.New("container image cannot be empty")
	}

	dryRun, err := cmd.Flags().GetBool("dry-run")
	if err != nil {
		return nil, err
	}

	autoTracee, err := cmd.Flags().GetBool("auto-tracee")
	if err != nil {
		return nil, err
	}

	traceeBinary, err := cmd.Flags().GetString("tracee-binary")
	if err != nil {
		return nil, err
	}

	traceeOutput, err := cmd.Flags().GetString("tracee-output")
	if err != nil {
		return nil, err
	}

	metrics, err := cmd.Flags().GetBool("metrics")
	if err != nil {
		return nil, err
	}

	pprof, err := cmd.Flags().GetBool("pprof")
	if err != nil {
		return nil, err
	}

	pyroscope, err := cmd.Flags().GetBool("pyroscope")
	if err != nil {
		return nil, err
	}

	keepTracee, err := cmd.Flags().GetBool("keep-tracee")
	if err != nil {
		return nil, err
	}

	// Validate flag interactions
	if keepTracee && !autoTracee {
		return nil, errors.New("--keep-tracee requires --auto-tracee=true (cannot keep tracee running if evt stress didn't start it)")
	}

	waitBeforeTrigger, err := cmd.Flags().GetBool("wait-before-trigger")
	if err != nil {
		return nil, err
	}

	signalTimeout, err := cmd.Flags().GetDuration("signal-timeout")
	if err != nil {
		return nil, err
	}

	traceeInitCooldown, err := cmd.Flags().GetDuration("tracee-init-cooldown")
	if err != nil {
		return nil, err
	}

	stressEndCooldown, err := cmd.Flags().GetDuration("stress-end-cooldown")
	if err != nil {
		return nil, err
	}

	// Extract event names from triggers for Tracee
	eventNames := make([]string, 0, len(triggers))
	for _, tc := range triggers {
		eventNames = append(eventNames, tc.event)
	}

	s := &stress{
		triggers:           triggers,
		containerImage:     image,
		dryRun:             dryRun,
		autoTracee:         autoTracee,
		traceeBinary:       traceeBinary,
		traceeOutput:       traceeOutput,
		eventNames:         eventNames,
		metrics:            metrics,
		pprof:              pprof,
		pyroscope:          pyroscope,
		keepTracee:         keepTracee,
		waitBeforeTrigger:  waitBeforeTrigger,
		signalTimeout:      signalTimeout,
		traceeInitCooldown: traceeInitCooldown,
		stressEndCooldown:  stressEndCooldown,
		cmd:                cmd,
	}

	return s, nil
}

// parseEventSpec parses an event specification in the format:
// event[:key=value:key=value:...]
// Example: security_file_open:instances=10:ops=1000:sleep=1ms
func parseEventSpec(spec string) (triggerConfig, error) {
	// Default values
	tc := triggerConfig{
		instances: defaultStressInstances,
		ops:       defaultStressOps,
		sleep:     defaultStressSleep,
	}

	parts := strings.Split(spec, ":")
	if len(parts) == 0 || parts[0] == "" {
		return tc, errors.New("event name cannot be empty")
	}

	tc.event = parts[0]

	// Parse key=value pairs
	for _, part := range parts[1:] {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			return tc, fmt.Errorf("invalid key=value pair: %q", part)
		}

		key := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])

		switch key {
		case "instances", "i":
			instances, err := strconv.Atoi(value)
			if err != nil {
				return tc, fmt.Errorf("invalid instances value %q: %w", value, err)
			}
			if instances <= 0 {
				return tc, fmt.Errorf("instances must be greater than 0, got %d", instances)
			}
			tc.instances = instances

		case "ops", "o":
			ops, err := strconv.ParseInt(value, 10, 32)
			if err != nil {
				return tc, fmt.Errorf("invalid ops value %q: %w", value, err)
			}
			if ops <= 0 {
				return tc, fmt.Errorf("ops must be greater than 0, got %d", ops)
			}
			tc.ops = int32(ops)

		case "sleep", "s":
			// Validate it's a valid duration
			_, err := time.ParseDuration(value)
			if err != nil {
				return tc, fmt.Errorf("invalid sleep duration %q: %w", value, err)
			}
			tc.sleep = value

		default:
			return tc, fmt.Errorf("unknown key: %q (valid keys: instances, ops, sleep)", key)
		}
	}

	return tc, nil
}

func stressCmdRun(cmd *cobra.Command, args []string) error {
	s, err := getStress(cmd)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeoutCause(
		cmd.Context(),
		stressTimeout,
		fmt.Errorf("timeout after %v", stressTimeout),
	)
	defer cancel()
	s.ctx = ctx

	// Validate prerequisites
	if !s.dryRun {
		if err := s.validateDockerAvailable(); err != nil {
			return err
		}
		if err := s.validateContainerImage(); err != nil {
			return err
		}
		if err := s.validateTraceeBinary(); err != nil {
			return err
		}
	}

	return s.run()
}

func Cmd() *cobra.Command {
	return stressCmd
}
