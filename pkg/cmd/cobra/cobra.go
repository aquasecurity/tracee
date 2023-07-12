package cobra

import (
	"errors"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/aquasecurity/libbpfgo/helpers"

	"github.com/aquasecurity/tracee/pkg/cmd"
	"github.com/aquasecurity/tracee/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/pkg/cmd/flags/server"
	"github.com/aquasecurity/tracee/pkg/cmd/initialize"
	"github.com/aquasecurity/tracee/pkg/cmd/printer"
	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/policy"
	"github.com/aquasecurity/tracee/pkg/signatures/engine"
	"github.com/aquasecurity/tracee/pkg/signatures/signature"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/trace"
)

func GetTraceeRunner(c *cobra.Command, version string) (cmd.Runner, error) {
	var runner cmd.Runner

	// Log command line flags

	// Logger initialization must be the first thing to be done,
	// so all other packages can use it
	logCfg, err := flags.PrepareLogger(viper.GetStringSlice("log"), true)
	if err != nil {
		return runner, err
	}
	logger.Init(logCfg)

	// Rego command line flags

	rego, err := flags.PrepareRego(viper.GetStringSlice("rego"))
	if err != nil {
		return runner, err
	}

	// Signature directory command line flags

	sigs, err := signature.Find(
		rego.RuntimeTarget,
		rego.PartialEval,
		viper.GetStringSlice("signatures-dir"),
		nil,
		rego.AIO,
	)
	if err != nil {
		return runner, err
	}

	initialize.CreateEventsFromSignatures(events.StartSignatureID, sigs)

	// Initialize a tracee config structure

	cfg := config.Config{
		PerfBufferSize:     viper.GetInt("perf-buffer-size"),
		BlobPerfBufferSize: viper.GetInt("blob-perf-buffer-size"),
		ContainersEnrich:   viper.GetBool("containers"),
	}

	// OS release information

	osInfo, err := helpers.GetOSInfo()
	if err != nil {
		logger.Debugw("OSInfo", "warning: os-release file could not be found", "error", err) // only to be enforced when BTF needs to be downloaded, later on
		logger.Debugw("OSInfo", "os_release_field", helpers.OS_KERNEL_RELEASE, "OS_KERNEL_RELEASE", osInfo.GetOSReleaseFieldValue(helpers.OS_KERNEL_RELEASE))
	} else {
		osInfoSlice := make([]interface{}, 0)
		for k, v := range osInfo.GetOSReleaseAllFieldValues() {
			osInfoSlice = append(osInfoSlice, k.String(), v)
		}
		logger.Debugw("OSInfo", osInfoSlice...)
	}

	cfg.OSInfo = osInfo

	// Container Runtime command line flags

	sockets, err := flags.PrepareContainers(viper.GetStringSlice("crs"))
	if err != nil {
		return runner, err
	}
	cfg.Sockets = sockets

	// Cache command line flags

	cache, err := flags.PrepareCache(viper.GetStringSlice("cache"))
	if err != nil {
		return runner, err
	}
	cfg.Cache = cache
	if cfg.Cache != nil {
		logger.Debugw("Cache", "type", cfg.Cache.String())
	}

	// Capture command line flags - via cobra flag

	captureFlags, err := c.Flags().GetStringArray("capture")
	if err != nil {
		return runner, err
	}

	capture, err := flags.PrepareCapture(captureFlags, true)
	if err != nil {
		return runner, err
	}
	cfg.Capture = &capture

	// Capabilities command line flags

	capsCfg, err := flags.PrepareCapabilities(viper.GetStringSlice("capabilities"))
	if err != nil {
		return runner, err
	}
	cfg.Capabilities = &capsCfg

	// Policy/Filter command line flags - via cobra flag

	policyFlags, err := c.Flags().GetStringArray("policy")
	if err != nil {
		return runner, err
	}

	scopeFlags, err := c.Flags().GetStringArray("scope")
	if err != nil {
		return runner, err
	}

	eventFlags, err := c.Flags().GetStringArray("events")
	if err != nil {
		return runner, err
	}

	if len(policyFlags) > 0 && len(scopeFlags) > 0 {
		return runner, errors.New("policy and scope flags cannot be used together")
	}
	if len(policyFlags) > 0 && len(eventFlags) > 0 {
		return runner, errors.New("policy and event flags cannot be used together")
	}

	var policies *policy.Policies

	if len(policyFlags) > 0 {
		policies, err = createPoliciesFromPolicyFiles(policyFlags)
		if err != nil {
			return runner, err
		}
	} else {
		policies, err = createPoliciesFromCLIFlags(scopeFlags, eventFlags)
		if err != nil {
			return runner, err
		}
	}

	cfg.Policies = policies

	// Output command line flags
	output, err := flags.PrepareOutput(viper.GetStringSlice("output"), true)
	if err != nil {
		return runner, err
	}
	cfg.Output = output.TraceeConfig

	// Create printer
	p, err := printer.NewBroadcast(output.PrinterConfigs, cmd.GetContainerMode(cfg))
	if err != nil {
		return runner, err
	}

	// Check kernel lockdown

	lockdown, err := helpers.Lockdown()
	if err != nil {
		logger.Debugw("OSInfo", "lockdown", err)
	}
	if err == nil && lockdown == helpers.CONFIDENTIALITY {
		return runner, errfmt.Errorf("kernel lockdown is set to 'confidentiality', can't load eBPF programs")
	}

	logger.Debugw("OSInfo", "security_lockdown", lockdown)

	// Check if ftrace is enabled

	enabled, err := helpers.FtraceEnabled()
	if err != nil {
		return runner, err
	}
	if !enabled {
		logger.Errorw("ftrace_enabled: ftrace is not enabled, kernel events won't be caught, make sure to enable it by executing echo 1 | sudo tee /proc/sys/kernel/ftrace_enabled")
	}

	// Pick OS information

	kernelConfig, err := initialize.KernelConfig()
	if err != nil {
		return runner, err
	}

	// Decide BTF & BPF files to use (based in the kconfig, release & environment info)

	err = initialize.BpfObject(&cfg, kernelConfig, osInfo, viper.GetString("install-path"), version)
	if err != nil {
		return runner, errfmt.Errorf("failed preparing BPF object: %v", err)
	}

	cfg.ChanEvents = make(chan trace.Event, 1000)

	// Prepare the server

	httpServer, err := server.PrepareServer(
		viper.GetString(server.ListenEndpointFlag),
		viper.GetBool(server.MetricsEndpointFlag),
		viper.GetBool(server.HealthzEndpointFlag),
		viper.GetBool(server.PProfEndpointFlag),
		viper.GetBool(server.PyroscopeAgentFlag),
	)

	if err != nil {
		return runner, err
	}

	runner.Server = httpServer
	runner.TraceeConfig = cfg
	runner.Printer = p

	// parse arguments must be enabled if the rule engine is part of the pipeline
	runner.TraceeConfig.Output.ParseArguments = true

	runner.TraceeConfig.EngineConfig = engine.Config{
		Enabled:    true,
		Signatures: sigs,
		// This used to be a flag, we have removed the flag from this binary to test
		// if users do use it or not.
		SignatureBufferSize: 1000,
		DataSources:         []detect.DataSource{},
	}

	return runner, nil
}
