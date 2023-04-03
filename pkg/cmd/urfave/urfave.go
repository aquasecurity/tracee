package urfave

import (
	"os"
	"path/filepath"
	"strings"

	cli "github.com/urfave/cli/v2"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/libbpfgo/helpers"

	"github.com/aquasecurity/tracee/pkg/cmd"
	"github.com/aquasecurity/tracee/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/pkg/cmd/flags/server"
	"github.com/aquasecurity/tracee/pkg/cmd/initialize"
	"github.com/aquasecurity/tracee/pkg/cmd/printer"
	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/pkg/errfmt"
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

	logCfg, err := flags.PrepareLogger(c.StringSlice("log"))
	if err != nil {
		return runner, err
	}
	logger.Init(logCfg)

	// OS release information

	OSInfo, err := helpers.GetOSInfo()
	if err != nil {
		logger.Debugw("OSInfo", "warning: os-release file could not be found", "error", err) // only to be enforced when BTF needs to be downloaded, later on
		logger.Debugw("OSInfo", "os_release_field", helpers.OS_KERNEL_RELEASE, "OS_KERNEL_RELEASE", OSInfo.GetOSReleaseFieldValue(helpers.OS_KERNEL_RELEASE))
	} else {
		osInfoSlice := make([]interface{}, 0)
		for k, v := range OSInfo.GetOSReleaseAllFieldValues() {
			osInfoSlice = append(osInfoSlice, k.String(), v)
		}
		logger.Debugw("OSInfo", osInfoSlice...)
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
		logger.Debugw("Cache", "type", cfg.Cache.String())
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

	var filterMap flags.FilterMap

	if len(c.StringSlice("policy")) > 0 {
		policies, err := getPolicies(c.StringSlice("policy"))
		if err != nil {
			return runner, err
		}

		filterMap, err = flags.PrepareFilterMapFromPolicies(policies)
		if err != nil {
			return runner, err
		}
	} else {
		filterMap, err = flags.PrepareFilterMapFromFlags(c.StringSlice("filter"))
		if err != nil {
			return runner, err
		}
	}

	policies, err := flags.CreatePolicies(filterMap)
	if err != nil {
		return runner, err
	}

	cfg.Policies = policies

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
	err = initialize.BpfObject(&cfg, kernelConfig, OSInfo, traceeInstallPath, version)
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
	runner.Printers = printers

	return runner, nil
}

func getContainerMode(cfg tracee.Config) printer.ContainerMode {
	containerMode := printer.ContainerModeDisabled

	for p := range cfg.Policies.Map() {
		if p.ContainerFilterEnabled() {
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

func getPolicies(paths []string) ([]flags.PolicyFile, error) {
	policies := make([]flags.PolicyFile, 0)

	for _, path := range paths {
		if path == "" {
			return nil, errfmt.Errorf("policy path cannot be empty")
		}

		path, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}

		fileInfo, err := os.Stat(path)
		if err != nil {
			return nil, err
		}

		if !fileInfo.IsDir() {
			p, err := getPoliciesFromFile(path)
			if err != nil {
				return nil, err
			}
			policies = append(policies, p)

			continue
		}

		files, err := os.ReadDir(path)
		if err != nil {
			return nil, err
		}

		for _, file := range files {
			if file.IsDir() {
				continue
			}

			// TODO: support json
			if strings.HasSuffix(file.Name(), ".yaml") ||
				strings.HasSuffix(file.Name(), ".yml") {

				policy, err := getPoliciesFromFile(filepath.Join(path, file.Name()))
				if err != nil {
					return nil, err
				}

				policies = append(policies, policy)
			}
		}
	}

	return policies, nil
}

func getPoliciesFromFile(filePath string) (flags.PolicyFile, error) {
	var p flags.PolicyFile

	data, err := os.ReadFile(filePath)
	if err != nil {
		return p, err
	}

	err = yaml.Unmarshal(data, &p)
	if err != nil {
		return p, err
	}

	return p, nil
}
