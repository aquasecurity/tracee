package urfave

import (
	cli "github.com/urfave/cli/v2"

	"github.com/aquasecurity/libbpfgo/helpers"

	"github.com/aquasecurity/tracee/pkg/cmd"
	"github.com/aquasecurity/tracee/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/pkg/cmd/flags/server"
	"github.com/aquasecurity/tracee/pkg/cmd/initialize"
	"github.com/aquasecurity/tracee/pkg/cmd/printer"
	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/types/trace"
)

func GetTraceeRunner(c *cli.Context, version string) (cmd.Runner, error) {
	var runner cmd.Runner

	// Initialize a tracee config structure
	cfg := config.Config{
		PerfBufferSize:     c.Int("perf-buffer-size"),
		BlobPerfBufferSize: c.Int("blob-perf-buffer-size"),
		ContainersEnrich:   c.Bool("containers"),
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

	sockets, err := flags.PrepareContainers(c.StringSlice("crs"))
	if err != nil {
		return runner, err
	}
	cfg.Sockets = sockets

	// Cache command line flags

	cache, err := flags.PrepareCache(c.StringSlice("cache"))
	if err != nil {
		return runner, err
	}
	cfg.Cache = cache
	if cfg.Cache != nil {
		logger.Debugw("Cache", "type", cfg.Cache.String())
	}

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

	var filterMap flags.PolicyFilterMap

	filterMap, err = flags.PrepareFilterMapFromFlags(c.StringSlice("filter"))
	if err != nil {
		return runner, err
	}

	policies, err := flags.CreatePolicies(filterMap, false)
	if err != nil {
		return runner, err
	}

	cfg.Policies = policies

	broadcast, err := printer.NewBroadcast(output.PrinterConfigs, cmd.GetContainerMode(cfg))
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

	traceeInstallPath := c.String("install-path")
	err = initialize.BpfObject(&cfg, kernelConfig, osInfo, traceeInstallPath, version)
	if err != nil {
		return runner, errfmt.Errorf("failed preparing BPF object: %v", err)
	}

	cfg.ChanEvents = make(chan trace.Event, 1000)

	httpServer, err := server.PrepareServer(
		c.String(server.ListenEndpointFlag),
		c.Bool(server.MetricsEndpointFlag),
		c.Bool(server.HealthzEndpointFlag),
		c.Bool(server.PProfEndpointFlag),
		c.Bool(server.PyroscopeAgentFlag),
	)

	if err != nil {
		return runner, err
	}

	runner.Server = httpServer
	runner.TraceeConfig = cfg
	runner.Printer = broadcast

	return runner, nil
}
