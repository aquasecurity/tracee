package urfave

import (
	cli "github.com/urfave/cli/v2"

	"github.com/aquasecurity/tracee/common/environment"
	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/pkg/cmd"
	"github.com/aquasecurity/tracee/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/pkg/cmd/initialize"
	"github.com/aquasecurity/tracee/pkg/cmd/printer"
	"github.com/aquasecurity/tracee/pkg/config"
)

func GetTraceeRunner(c *cli.Context, version string) (cmd.Runner, error) {
	var runner cmd.Runner
	var err error

	buffers, err := flags.PrepareBuffers(c.StringSlice("buffers"))
	if err != nil {
		return runner, err
	}
	// Initialize a tracee config structure
	cfg := config.Config{
		PerfBufferSize:             buffers.EventsSize,
		BlobPerfBufferSize:         buffers.BlobSize,
		ControlPlanePerfBufferSize: buffers.ControlPlaneSize,
		PipelineChannelSize:        buffers.PipelineSize,
	}

	// Output command line flags

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

	// Enrichment command line flags

	enrichment, err := flags.PrepareEnrichment(c.StringSlice(flags.EnrichFlag))
	if err != nil {
		return runner, err
	}
	sockets, err := enrichment.GetRuntimeSockets()
	if err != nil {
		return runner, err
	}
	cfg.Sockets = sockets
	cfg.NoContainersEnrich = enrichment.ContainerEnabled
	cfg.CgroupFSPath = enrichment.ContainerCgroupPath

	// cfg.CgroupFSForce = res.CgroupfsForce

	stores, err := flags.PrepareStores(c.StringSlice("stores"))
	if err != nil {
		return runner, err
	}
	cfg.DNSCacheConfig = stores.DNS
	cfg.ProcTree = stores.Process

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

	generalConfig, err := flags.PrepareGeneral(c.StringSlice("general"))
	if err != nil {
		return runner, err
	}
	err = initialize.BpfObject(&cfg, kernelConfig, osInfo, generalConfig.Workdir, version)
	if err != nil {
		return runner, errfmt.Errorf("failed preparing BPF object: %v", err)
	}

	// Prepare HTTP server using unified server flags
	serverRunner, err := flags.PrepareServer(c.StringSlice(flags.ServerFlag))
	if err != nil {
		return runner, err
	}

	runner.HTTP = serverRunner.HTTP
	runner.TraceeConfig = cfg
	runner.Printer = broadcast
	runner.Workdir = generalConfig.Workdir

	return runner, nil
}
