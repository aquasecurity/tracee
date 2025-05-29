package urfave

import (
	cli "github.com/urfave/cli/v2"

	"github.com/aquasecurity/tracee/pkg/cmd"
	"github.com/aquasecurity/tracee/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/pkg/cmd/initialize"
	"github.com/aquasecurity/tracee/pkg/cmd/printer"
	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/utils/environment"
)

func GetTraceeRunner(c *cli.Context, version string) (cmd.Runner, error) {
	var runner cmd.Runner

	// Initialize a tracee config structure
	cfg := config.Config{
		PerfBufferSize:      c.Int("perf-buffer-size"),
		BlobPerfBufferSize:  c.Int("blob-perf-buffer-size"),
		PipelineChannelSize: c.Int("pipeline-channel-size"),
		NoContainersEnrich:  c.Bool("no-containers"),
	}

	// Output command line flags

	var err error
	var output flags.PrepareOutputResult

	output, err = flags.TraceeEbpfPrepareOutput(c.StringSlice("output"), false)

	if err != nil {
		return runner, err
	}
	cfg.Output = output.TraceeConfig

	// Log command line flags

	logCfg, err := flags.PrepareLogger(c.StringSlice("log"), false)
	if err != nil {
		return runner, err
	}
	logger.Init(logCfg)

	// OS release information

	osInfo, err := environment.GetOSInfo()
	if err != nil {
		logger.Debugw("OSInfo", "warning: os-release file could not be found", "error", err) // only to be enforced when BTF needs to be downloaded, later on
		logger.Debugw("OSInfo", "os_release_field", environment.OS_KERNEL_RELEASE, "OS_KERNEL_RELEASE", osInfo.GetOSReleaseFieldValue(environment.OS_KERNEL_RELEASE))
	} else {
		osInfoSlice := make([]interface{}, 0)
		for k, v := range osInfo.GetOSReleaseAllFieldValues() {
			osInfoSlice = append(osInfoSlice, k.String(), v)
		}
		logger.Debugw("OSInfo", osInfoSlice...)
	}

	cfg.OSInfo = osInfo

	// Container Runtime command line flags

	if !cfg.NoContainersEnrich {
		sockets, err := flags.PrepareContainers(c.StringSlice("cri"))
		if err != nil {
			return runner, err
		}
		cfg.Sockets = sockets
	}

	// Cache command line flags

	cache, err := flags.PrepareCache(c.StringSlice("cache"))
	if err != nil {
		return runner, err
	}
	cfg.Cache = cache
	if cfg.Cache != nil {
		logger.Debugw("Cache", "type", cfg.Cache.String())
	}

	// Cache command line flags

	procTree, err := flags.PrepareProcTree(c.StringSlice("proctree"))
	if err != nil {
		return runner, err
	}
	cfg.ProcTree = procTree

	// Capture command line flags

	capture, err := flags.PrepareCapture(c.StringSlice("capture"), false)
	if err != nil {
		return runner, err
	}
	cfg.Capture = &capture

	// Capabilities command line flags

	capsCfg, err := flags.PrepareCapabilities(c.StringSlice("capabilities"))
	if err != nil {
		return runner, err
	}
	cfg.Capabilities = &capsCfg

	// Filter command line flags

	var policyScopeMap flags.PolicyScopeMap
	var policyEventsMap flags.PolicyEventMap

	policyScopeMap, err = flags.PrepareScopeMapFromFlags(c.StringSlice("scope"))
	if err != nil {
		return runner, err
	}

	policyEventsMap, err = flags.PrepareEventMapFromFlags(c.StringSlice("events"))
	if err != nil {
		return runner, err
	}

	initialPolicies, err := flags.CreatePolicies(policyScopeMap, policyEventsMap, false)
	if err != nil {
		return runner, err
	}

	ps := make([]interface{}, 0, len(initialPolicies))
	for _, p := range initialPolicies {
		ps = append(ps, p)
	}
	cfg.InitialPolicies = ps

	containerFilterEnabled := func() bool {
		for _, p := range initialPolicies {
			if p.ContainerFilterEnabled() {
				return true
			}
		}

		return false
	}

	broadcast, err := printer.NewBroadcast(
		output.PrinterConfigs,
		cmd.GetContainerMode(containerFilterEnabled(), cfg.NoContainersEnrich),
	)
	if err != nil {
		return runner, err
	}

	// Check kernel lockdown

	lockdown, err := environment.Lockdown()
	if err != nil {
		logger.Debugw("OSInfo", "lockdown", err)
	}
	if err == nil && lockdown == environment.CONFIDENTIALITY {
		return runner, errfmt.Errorf("kernel lockdown is set to 'confidentiality', can't load eBPF programs")
	}

	logger.Debugw("OSInfo", "security_lockdown", lockdown)

	// Check if ftrace is enabled

	enabled, err := environment.FtraceEnabled()
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

	traceeInstallPath := c.String("install-path")
	err = initialize.BpfObject(&cfg, kernelConfig, osInfo, traceeInstallPath, version)
	if err != nil {
		return runner, errfmt.Errorf("failed preparing BPF object: %v", err)
	}

	// httpServer, err := server.PrepareHTTPServer(
	// 	c.String(server.HTTPListenEndpointFlag),
	// 	c.Bool(server.MetricsEndpointFlag),
	// 	c.Bool(server.HealthzEndpointFlag),
	// 	c.Bool(server.PProfEndpointFlag),
	// 	c.Bool(server.PyroscopeAgentFlag),
	// )

	if err != nil {
		return runner, err
	}

	runner.HTTPServer = nil
	runner.TraceeConfig = cfg
	runner.Printer = broadcast
	runner.InstallPath = traceeInstallPath

	return runner, nil
}
