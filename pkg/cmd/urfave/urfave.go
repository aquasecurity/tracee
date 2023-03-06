package urfave

import (
	cli "github.com/urfave/cli/v2"

	"github.com/aquasecurity/libbpfgo/helpers"

	"github.com/aquasecurity/tracee/pkg/cmd"
	"github.com/aquasecurity/tracee/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/pkg/cmd/flags/server"
	"github.com/aquasecurity/tracee/pkg/cmd/initialize"
	"github.com/aquasecurity/tracee/pkg/cmd/printer"
	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/types/trace"
)

func GetTraceeRunner(c *cli.Context, version string, newBinary bool) (cmd.Runner, error) {
	var runner cmd.Runner

	// Initialize a tracee config structure
	cfg := tracee.Config{
		PerfBufferSize:     c.Int("perf-buffer-size"),
		BlobPerfBufferSize: c.Int("blob-perf-buffer-size"),
		ContainersEnrich:   c.Bool("containers"),
	}

	// Output command line flags

	var err error
	var output flags.OutputConfig

	if newBinary {
		output, err = flags.PrepareOutput(c.StringSlice("output"))
	} else {
		output, err = flags.TraceeEbpfPrepareOutput(c.StringSlice("output"))
	}

	if err != nil {
		return runner, err
	}
	cfg.Output = output.TraceeConfig

	// Log command line flags

	logCfg, err := flags.PrepareLogger(c.StringSlice("log"), output.LogFile)
	if err != nil {
		return runner, err
	}
	logger.Init(logCfg)

	// OS release information

	OSInfo, err := helpers.GetOSInfo()
	if err != nil {
		logger.Debug("OSInfo", "warning: os-release file could not be found", "error", err) // only to be enforced when BTF needs to be downloaded, later on
		logger.Debug("OSInfo", "os_realease_field", helpers.OS_KERNEL_RELEASE, "OS_KERNEL_RELEASE", OSInfo.GetOSReleaseFieldValue(helpers.OS_KERNEL_RELEASE))
	} else {
		osInfoSlice := make([]interface{}, 0)
		for k, v := range OSInfo.GetOSReleaseAllFieldValues() {
			osInfoSlice = append(osInfoSlice, k.String(), v)
		}
		logger.Debug("OSInfo", osInfoSlice...)
	}

	cfg.OSInfo = OSInfo

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
		logger.Debug("Cache", "type", cfg.Cache.String())
	}

	// Capture command line flags

	capture, err := flags.PrepareCapture(c.StringSlice("capture"))
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

	filterScopes, err := flags.PrepareFilterScopes(c.StringSlice("filter"))
	if err != nil {
		return runner, err
	}
	cfg.FilterScopes = filterScopes

	// Container information printer flag
	containerMode := getContainerMode(cfg)
	printers := make([]printer.EventPrinter, 0, len(output.PrinterConfigs))
	for _, pConfig := range output.PrinterConfigs {
		pConfig.ContainerMode = containerMode

		p, err := printer.New(pConfig)
		if err != nil {
			return runner, err
		}

		printers = append(printers, p)
	}

	// Check kernel lockdown

	lockdown, err := helpers.Lockdown()
	if err != nil {
		logger.Debug("OSInfo", "lockdown", err)
	}
	if err == nil && lockdown == helpers.CONFIDENTIALITY {
		return runner, logger.NewErrorf("kernel lockdown is set to 'confidentiality', can't load eBPF programs")

	}

	logger.Debug("OSInfo", "security_lockdown", lockdown)

	// Check if ftrace is enabled

	enabled, err := helpers.FtraceEnabled()
	if err != nil {
		return runner, err
	}
	if !enabled {
		logger.Error("ftrace_enabled: ftrace is not enabled, kernel events won't be caught, make sure to enable it by executing echo 1 | sudo tee /proc/sys/kernel/ftrace_enabled")
	}

	// Pick OS information

	kernelConfig, err := initialize.KernelConfig()
	if err != nil {
		return runner, err
	}

	// Decide BTF & BPF files to use (based in the kconfig, release & environment info)

	traceeInstallPath := c.String("install-path")
	err = initialize.BpfObject(&cfg, kernelConfig, OSInfo, traceeInstallPath, version)
	if err != nil {
		return runner, logger.NewErrorf("failed preparing BPF object: %v", err)
	}

	cfg.ChanEvents = make(chan trace.Event, 1000)

	httpServer, err := server.PrepareServer(
		c.String(server.ListenEndpointFlag),
		c.Bool(server.MetricsEndpointFlag),
		c.Bool(server.HealthzEndpointFlag),
		c.Bool(server.PProfEndpointFlag),
	)

	if err != nil {
		return runner, err
	}

	runner.Server = httpServer
	runner.TraceeConfig = cfg
	runner.Printers = printers

	return runner, nil
}

func getContainerMode(cfg tracee.Config) printer.ContainerMode {
	containerMode := printer.ContainerModeDisabled

	for filterScope := range cfg.FilterScopes.Map() {
		if filterScope.ContainerFilterEnabled() {
			// enable printer container print mode if container filters are set
			containerMode = printer.ContainerModeEnabled
			if cfg.ContainersEnrich {
				// further enable container enrich print mode if container enrichment is enabled
				containerMode = printer.ContainerModeEnriched
			}

			break
		}
	}

	return containerMode
}

func GetGPTDocsRunner(k string, t float64, m int, e []string) (
	*cmd.GPTDocsRunner, error,
) {
	return &cmd.GPTDocsRunner{
		OpenAIKey:         k,
		OpenAITemperature: t,
		OpenAIMaxTokens:   m,
		GivenEvents:       e,
	}, nil
}
